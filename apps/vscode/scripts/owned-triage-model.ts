/** Test-owned loopback model, not a product bypass: uses the real provider/tool/approval path. */
import { createServer } from "node:http"
import { randomUUID } from "node:crypto"
import { setTimeout as delay } from "node:timers/promises"
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
					throw new Error("Owned model received a failed or incomplete triage result: " + text.slice(0, 300))
				results.push(result)
				if (result.operation === "list_functions") {
					const match = String(result.text).match(/"offset":\s*(\d+)/)
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
								target: "owned-triage.exe",
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
		await delay(200)
	}
	throw new Error("Installed AI triage model acceptance timed out")
}
