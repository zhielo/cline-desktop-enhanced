import { assertAdmittedApplicationManifest } from "./application-bindings";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { realpathSync } from "node:fs";
import { lstat, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { probeProcessStartTokenAsync } from "../runtime/process-start-token";
import {
	ANALYSIS_PROFILE,
	AnalysisInputSchema,
	type AnalysisReceipt,
	digest,
	LIMITS,
	ResultSchema,
} from "./contracts";
import { analysisHostIdentity, ownershipBinding } from "./recovery";
import { FirstPartyAnalysisStore } from "./store";

type WorkerHost = { executable: string; args: string[] };
export function configureFirstPartyAnalysisHost(host: WorkerHost) {
	if (
		!isAbsolute(host.executable) ||
		host.args.length > 1 ||
		host.args.some((a) => !isAbsolute(a))
	)
		throw new Error(
			"Analysis worker host must be an absolute owned executable/entrypoint",
		);
	process.env.CLINE_FIRST_PARTY_ANALYSIS_HOST = JSON.stringify(host);
}
const controllers = new Map<
	string,
	{ sessionId: string; abort: AbortController }
>();
export function cancelFirstPartyAnalysis(id: string, sessionId: string) {
	const active = controllers.get(id);
	if (!active || active.sessionId !== sessionId)
		throw new Error(
			"No owned active worker; restart does not grant process recovery",
		);
	active.abort.abort();
}
/** Fixed parser entrypoint in an owned child. Process separation is NOT an OS sandbox. */
export async function runFirstPartyAnalysis(
	sessionId: string,
	inputValue: unknown,
	signal?: AbortSignal,
	store = new FirstPartyAnalysisStore(),
	hostValue = process.env.CLINE_FIRST_PARTY_ANALYSIS_HOST,
): Promise<AnalysisReceipt> {
	const input = AnalysisInputSchema.parse(inputValue),
		session = store.session(sessionId);
	if (!session || session.mode === "off")
		throw new Error("Analysis is Off for this session");
	if (!hostValue)
		throw new Error(
			"First-party parser host is unavailable; use the current desktop backend",
		);
	const host = JSON.parse(hostValue) as WorkerHost;
	if (
		!host ||
		typeof host.executable !== "string" ||
		!isAbsolute(host.executable) ||
		!Array.isArray(host.args) ||
		host.args.length > 1 ||
		host.args.some((a) => typeof a !== "string" || !isAbsolute(a))
	)
		throw new Error("Invalid parser host");
	if (signal?.aborted) throw new Error("Analysis cancelled before admission");
	if (input.semanticGraph && input.compareTarget)
		throw new Error(
			"Semantic graph comparison is not implemented; analyze each target separately",
		);
	const receipt: AnalysisReceipt = {
		id: randomUUID(),
		sessionId,
		workspace: realpathSync(session.workspace),
		profile: ANALYSIS_PROFILE,
		input,
		requestHash: digest({
			profile: ANALYSIS_PROFILE,
			workspace: session.workspace,
			input,
		}),
		createdAt: new Date().toISOString(),
		status: "running",
	};
	store.start(receipt);
	let scratch: string | undefined;
	try {
		if (input.semanticGraph)
			scratch = await mkdtemp(join(tmpdir(), "cline-semantic-"));
	} catch {
		receipt.status = "failed";
		receipt.error = "Could not create private semantic transfer directory";
		store.save(receipt);
		return receipt;
	}
	const semanticOutput = scratch ? join(scratch, "graph.json") : undefined;
	const abort = new AbortController();
	controllers.set(receipt.id, { sessionId, abort });
	return await new Promise<AnalysisReceipt>((resolve) => {
		let child: ReturnType<typeof spawn> | undefined;
		let output = Buffer.alloc(0),
			failure: string | undefined,
			termination: ReturnType<typeof setTimeout> | undefined;
		let final = false,
			timedOut = false;
		let deadline: ReturnType<typeof setTimeout> | undefined;
		const finish = async (
			confirmed: boolean,
			code: number | null,
			sig: string | null,
		) => {
			if (final) return;
			final = true;
			if (deadline) clearTimeout(deadline);
			if (termination) clearTimeout(termination);
			signal?.removeEventListener("abort", stop);
			abort.signal.removeEventListener("abort", stop);
			controllers.delete(receipt.id);
			receipt.completedAt = new Date().toISOString();
			receipt.exitCode = code;
			receipt.signal = sig;
			if (!confirmed) {
				receipt.status = "termination-unconfirmed";
				receipt.error = "Worker stop was not confirmed; reservation retained.";
			} else if (timedOut) {
				receipt.status = "timed-out";
				receipt.error = "Parser deadline exceeded";
			} else if (abort.signal.aborted || signal?.aborted) {
				receipt.status = "cancelled";
				receipt.error = "Cancelled without replay";
			} else if (failure || code !== 0) {
				receipt.status = "failed";
				receipt.error = failure ?? "Parser exited unsuccessfully";
			} else
				try {
					const parsedResult = ResultSchema.parse(
						JSON.parse(output.toString("utf8")),
					);
					if (
						!!input.semanticGraph !== !!parsedResult.semanticGraph ||
						!!input.applicationGraph !== !!parsedResult.applicationGraph
					)
						throw new Error("Requested semantic evidence was not returned");
					receipt.result = parsedResult;
					receipt.resultHash = digest(receipt.result);
					receipt.status = receipt.result.status;
				} catch {
					receipt.status = "failed";
					receipt.error = "Invalid or oversized parser evidence";
				}
			try {
				let graph: unknown;
				let application: unknown;
				if (receipt.result?.semanticGraph) {
					if (!semanticOutput) throw new Error("Unexpected semantic graph");
					const {
						SEMANTIC_MAX_BYTES,
						javaScriptSemanticGraphSchema,
						semanticSummary,
					} = await import("./semantic-engine/engine");
					const info = await lstat(semanticOutput);
					if (
						!info.isFile() ||
						info.isSymbolicLink() ||
						info.size > SEMANTIC_MAX_BYTES
					)
						throw new Error("Invalid semantic transfer");
					const encoded = await readFile(semanticOutput);
					if (
						encoded.length !== info.size ||
						encoded.length > SEMANTIC_MAX_BYTES
					)
						throw new Error("Semantic transfer size changed");
					const transferred = JSON.parse(encoded.toString("utf8"));
					graph = javaScriptSemanticGraphSchema.parse(
						receipt.result.applicationGraph
							? transferred.semantic
							: transferred,
					);
					if (receipt.result.applicationGraph) {
						assertAdmittedApplicationManifest(
							receipt.result.applicationGraph.sources,
							receipt.result.artifacts,
						);
						const { parseJavaScriptApplicationGraph, applicationSummary } =
							await import("./semantic-engine/application");
						application = parseJavaScriptApplicationGraph(
							transferred.application,
						);
						if (
							digest(
								applicationSummary(
									application as Parameters<typeof applicationSummary>[0],
									graph as Parameters<typeof applicationSummary>[1],
									receipt.result.applicationGraph.sources,
								),
							) !== digest(receipt.result.applicationGraph)
						)
							throw new Error("Application summary integrity mismatch");
					}
					if (
						digest(
							semanticSummary(
								graph as Parameters<typeof semanticSummary>[0],
								!!receipt.result.applicationGraph,
							),
						) !== digest(receipt.result.semanticGraph)
					)
						throw new Error("Semantic summary integrity mismatch");
				}
				store.save(receipt, graph, application);
			} catch {
				receipt.status = "failed";
				receipt.error =
					"Evidence persistence failed; do not replay analysis automatically";
				delete receipt.result;
				delete receipt.resultHash;
				try {
					store.save(receipt);
				} catch {
					/* Reservation is retained if persistence is unavailable. */
				}
			}
			if (scratch && confirmed)
				await rm(scratch, { recursive: true, force: true }).catch(
					() => undefined,
				);
			resolve(receipt);
		};
		const stop = () => {
			if (final || termination) return;
			child?.kill("SIGKILL");
			termination = setTimeout(() => finish(false, null, null), 5000);
		};
		try {
			const env: NodeJS.ProcessEnv = { NODE_ENV: "production" };
			for (const key of [
				"PATH",
				"SystemRoot",
				"SYSTEMROOT",
				"WINDIR",
				"TEMP",
				"TMP",
				"TMPDIR",
				"HOME",
				"USERPROFILE",
			])
				if (process.env[key]) env[key] = process.env[key];
			child = spawn(
				host.executable,
				[...host.args, "--cline-analysis-worker"],
				{
					// Never let a target's .env or bunfig become parser host configuration.
					cwd: dirname(host.executable),
					env,
					windowsHide: true,
					stdio: ["pipe", "pipe", "pipe"],
				},
			);
			child.on("error", () => {
				failure = "Parser process could not start";
				finish(true, null, null);
			});
			child.on("close", (code, sig) => finish(true, code, sig));
			receipt.pid = child.pid;
			store.save(receipt);
			child.stdout!.on("data", (chunk: Buffer) => {
				if (output.length + chunk.length > LIMITS.outputBytes) {
					failure = "Parser output budget exceeded";
					stop();
				} else output = Buffer.concat([output, chunk]);
			});
			// Drain but never persist parser stderr (may contain source content or secrets).
			child.stderr!.on("data", () => undefined);
			child.stdin!.on("error", () => undefined);
			// Worker blocks on stdin until both process birth identities are persisted.
			void (async () => {
				try {
					const [hostId, owner, worker] = await Promise.all([
						analysisHostIdentity(),
						probeProcessStartTokenAsync(process.pid),
						child!.pid
							? probeProcessStartTokenAsync(child!.pid)
							: Promise.resolve({ status: "unavailable" as const }),
					]);
					if (final || termination || signal?.aborted || abort.signal.aborted)
						return;
					if (
						hostId &&
						owner.status === "found" &&
						worker.status === "found" &&
						child!.pid
					) {
						const proof = {
							version: 1 as const,
							host: hostId,
							nonce: randomUUID(),
							owner: { pid: process.pid, token: owner.token },
							worker: { pid: child!.pid, token: worker.token },
						};
						receipt.ownership = {
							...proof,
							binding: ownershipBinding(receipt, proof),
						};
						store.save(receipt);
					}
					child!.stdin!.end(
						JSON.stringify({
							workspace: receipt.workspace,
							input,
							semanticOutput,
						}),
					);
				} catch {
					failure = "Worker ownership persistence failed";
					stop();
				}
			})();
			signal?.addEventListener("abort", stop, { once: true });
			abort.signal.addEventListener("abort", stop, { once: true });
			deadline = setTimeout(
				() => {
					timedOut = true;
					stop();
				},
				input.semanticGraph ? 300_000 : LIMITS.timeoutMs,
			);
			if (signal?.aborted) stop();
		} catch {
			failure = "Parser process admission failed";
			if (child) stop();
			else finish(true, null, null);
		}
	});
}
