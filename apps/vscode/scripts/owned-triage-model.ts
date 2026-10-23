/** Test-owned loopback model, not a product bypass: uses the real provider/tool/approval path. */
import { createServer } from "node:http"
import { createHash, randomUUID } from "node:crypto"
import { readFile, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { setTimeout as delay } from "node:timers/promises"
export const OWNED_TRIAGE_TARGET = "owned-ai-triage.exe"
/** Stage the installed pack's compiled owned PE, not the legacy MZ-only YARA marker.
 * Read/hash/structure checks only: this fixture is never launched. */
export async function stageOwnedTriagePe(packRoot: string, workspace: string) {
	const manifest = JSON.parse((await readFile(join(packRoot, "manifest.json"), "utf8")).replace(/^\uFEFF/, ""))
	const expected = manifest.schemaVersion === 1 ? manifest.files?.["owned-fixture.exe"] : undefined
	const bytes = await readFile(join(packRoot, "owned-fixture.exe"))
	const hash = createHash("sha256").update(bytes).digest("hex")
	if (typeof expected !== "string" || !/^[a-f0-9]{64}$/.test(expected) || hash !== expected)
		throw new Error("Installed owned PE fixture does not match its pack manifest")
	const pe = bytes.length >= 64 ? bytes.readUInt32LE(0x3c) : -1
	if (bytes.toString("ascii", 0, 2) !== "MZ" || pe < 64 || pe > bytes.length - 24 ||
		bytes.readUInt32LE(pe) !== 0x00004550 || !bytes.includes(Buffer.from("CLINE_OWNED_TRIAGE_FIXTURE_V1")))
		throw new Error("Installed owned fixture lacks valid PE structure and owned marker")
	const target = join(workspace, OWNED_TRIAGE_TARGET)
	await writeFile(target, bytes, { flag: "wx" })
	if (createHash("sha256").update(await readFile(target)).digest("hex") !== hash)
		throw new Error("Staged owned PE fixture changed")
	return { target: OWNED_TRIAGE_TARGET, sha256: hash, bytes: bytes.length }
}
export const OWNED_TRIAGE_SEQUENCE = [
	"inspect_binary",
	"list_functions",
	"get_function_disassembly",
	"find_references",
	"scan_yara",
	"identify_capabilities",
	"extract_strings",
] as const
export async function startOwnedTriageModel() {
	const results: Record<string, unknown>[] = []
	let error: Error | undefined, selectedAddress: string | undefined
	let providerRequests = 0
	const server = createServer(async (req, res) => {
		try {
			if (req.method !== "POST" || !req.url?.endsWith("/chat/completions"))
				throw new Error("Unexpected owned model endpoint")
			let body = ""
			for await (const part of req) {
				body += part.toString()
				if (body.length > 8 * 1024 * 1024) throw new Error("Owned model request budget")
			}
			const request = JSON.parse(body)
			providerRequests++
			const tools = (request.messages as Array<Record<string, unknown>>).filter((m) => m.role === "tool")
			results.length = 0
			for (const message of tools) {
				const text = typeof message.content === "string" ? message.content : JSON.stringify(message.content)
				let result = JSON.parse(text)
				if (typeof result === "string") result = JSON.parse(result)
				// A transport/provider/tool error must never be treated as engine acceptance.
				if (
					result.status !== "completed" ||
					typeof result.receiptId !== "string" ||
					!/^[a-f0-9]{64}$/.test(String(result.targetSha256))
				)
					throw new Error("Owned model received a failed or incomplete triage result: " +
						JSON.stringify({status:result.status, operation:result.operation, diagnostic:result.diagnostic,
							error:result.error, receiptId:result.receiptId}).slice(0, 600))
				results.push(result)
				if (result.operation === "list_functions") {
					// Pinned radare2 6.2.4 aflj emits addr; older fixtures used offset.
					// Parse the decimal token with BigInt, never a lossy JS number.
					const match = String(result.text).match(/"(?:addr|offset)":\s*(\d+)/)
					if (!match) throw new Error("Owned function listing lacks an address for the next call")
					selectedAddress = "0x" + BigInt(match[1]).toString(16)
				}
			}
			if (results.length > OWNED_TRIAGE_SEQUENCE.length) throw new Error("Unexpected extra triage results")
			const operation = OWNED_TRIAGE_SEQUENCE[results.length]
			const toolCall = operation
				? {
						id: "call_" + randomUUID().replaceAll("-", ""),
						type: "function",
						function: {
							name: "reverse_engineer",
							arguments: JSON.stringify({
								operation: "advanced_analysis",
								advanced_action: "binary_triage",
								target: OWNED_TRIAGE_TARGET,
								advanced_options: {
									binary_triage: {
										action: "run",
										operation,
										question: "Inspect this owned fixture using bounded static evidence.",
										...(["get_function_disassembly", "find_references"].includes(operation)
											? { address: selectedAddress }
											: {}),
									},
								},
							}),
						},
					}
				: undefined
			const content = toolCall
				? null
				: "Owned AI triage acceptance complete: seven static operations returned saved evidence; no target execution or malware verdict is claimed."
			const id = "chatcmpl-owned-" + randomUUID(),
				created = Math.floor(Date.now() / 1000),
				model = String(request.model)
			if (request.stream) {
				res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" })
				const chunk = (delta: unknown, finish_reason: string | null) =>
					res.write(
						"data: " +
							JSON.stringify({
								id,
								object: "chat.completion.chunk",
								created,
								model,
								choices: [{ index: 0, delta, finish_reason }],
							}) +
							"\n\n",
					)
				chunk(
					toolCall ? { role: "assistant", tool_calls: [{ index: 0, ...toolCall }] } : { role: "assistant", content },
					null,
				)
				chunk({}, toolCall ? "tool_calls" : "stop")
				res.end("data: [DONE]\n\n")
			} else {
				res.writeHead(200, { "Content-Type": "application/json" })
				res.end(
					JSON.stringify({
						id,
						object: "chat.completion",
						created,
						model,
						choices: [
							{
								index: 0,
								message: { role: "assistant", content, ...(toolCall ? { tool_calls: [toolCall] } : {}) },
								finish_reason: toolCall ? "tool_calls" : "stop",
							},
						],
						usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
					}),
				)
			}
		} catch (e) {
			error = e instanceof Error ? e : new Error(String(e))
			res.writeHead(500, { "Content-Type": "application/json" })
			res.end(JSON.stringify({ error: { message: error.message, type: "owned_acceptance_failure" } }))
		}
	})
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject)
		server.listen(0, "127.0.0.1", () => resolve())
	})
	const address = server.address()
	if (!address || typeof address === "string") throw new Error("Owned provider port unavailable")
	return {
		baseUrl: `http://127.0.0.1:${address.port}/v1`,
		results,
		get providerRequests() {
			return providerRequests
		},
		get error() {
			return error
		},
		async close() {
			server.closeAllConnections()
			await new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve())))
		},
	}
}
export async function waitOwnedTriageModel(
	model: Awaited<ReturnType<typeof startOwnedTriageModel>>,
	poll: () => Promise<Array<{ requestId: string; toolName?: string; input?: Record<string, unknown> }>>,
	approve: (requestId: string) => Promise<unknown>,
) {
	const deadline = Date.now() + 9 * 60_000,
		reviewed = new Set<string>(),
		independent = new Set<string>()
	while (Date.now() < deadline) {
		if (model.error) throw model.error
		for (const item of await poll()) {
			if (reviewed.has(item.requestId)) continue
			if (item.toolName !== "reverse_engineer") throw new Error("Unexpected tool requested by owned model")
			const details = item.input
			if (details?.independentStaticAnalysisApproval === true) {
				if (!/^[a-f0-9]{64}$/.test(String(details.requestHash)) || !/^[a-f0-9]{64}$/.test(String(details.targetSha256)))
					throw new Error("Installed approval lacks triage identity")
				independent.add(String(details.operation) + ":" + String(details.requestHash))
			}
			await approve(item.requestId)
			reviewed.add(item.requestId)
		}
		if (model.results.length === 7) {
			if (independent.size !== 7) throw new Error("Installed AI triage did not review all seven exact requests")
			if (model.results.some((r, i) => r.operation !== OWNED_TRIAGE_SEQUENCE[i]))
				throw new Error("Installed AI triage operation order mismatch")
			return { results: model.results, independentApprovals: independent.size }
		}
		await delay(500)
	}
	throw new Error(
		`Installed AI triage timed out: providerRequests=${model.providerRequests}; results=${model.results.length}; reviewed=${reviewed.size}; independent=${independent.size}`,
	)
}

/** Queue through the normal idle-session route: immediate sends await the entire
 * agent turn and would deadlock this driver before it polls tool approvals. */
export async function enqueueOwnedTriageTurn(
	send: (request: { action: "send"; sessionId: string; delivery: "queue"; prompt: string }) => Promise<{ queued?: boolean }>,
	sessionId: string,
) {
	const reply = await send({
		action: "send",
		sessionId,
		delivery: "queue",
		prompt: `Analyze ${OWNED_TRIAGE_TARGET} using the fixed binary triage operations. Use saved static evidence only.`,
	})
	if (reply.queued !== true) throw new Error("Owned AI triage turn was not acknowledged by the normal queue")
}
