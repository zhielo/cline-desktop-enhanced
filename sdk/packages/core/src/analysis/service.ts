import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { realpathSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";
import {
	ANALYSIS_PROFILE,
	AnalysisInputSchema,
	LIMITS,
	ResultSchema,
	digest,
	type AnalysisReceipt,
} from "./contracts";
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
		const finish = (
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
					receipt.result = ResultSchema.parse(
						JSON.parse(output.toString("utf8")),
					);
					receipt.resultHash = digest(receipt.result);
					receipt.status = receipt.result.status;
				} catch {
					receipt.status = "failed";
					receipt.error = "Invalid or oversized parser evidence";
				}
			try {
				store.save(receipt);
			} catch {
				receipt.status = "failed";
				receipt.error =
					"Evidence persistence failed; do not replay analysis automatically";
			}
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
			child.stdin!.end(JSON.stringify({ workspace: receipt.workspace, input }));
			signal?.addEventListener("abort", stop, { once: true });
			abort.signal.addEventListener("abort", stop, { once: true });
			deadline = setTimeout(() => {
				timedOut = true;
				stop();
			}, LIMITS.timeoutMs);
			if (signal?.aborted) stop();
		} catch {
			failure = "Parser process admission failed";
			if (child) stop();
			else finish(true, null, null);
		}
	});
}
