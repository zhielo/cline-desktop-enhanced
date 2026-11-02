/** Native parser is owned directly by the host, never nested under a disposable parser child. */
import path from "node:path";
import { realpathSync } from "node:fs";
import { randomUUID } from "node:crypto";
import {
	runPinnedGeneralRecovery,
	GeneralRecoveryTerminationUnconfirmedError,
	GeneralRecoveryExecutionError,
} from "./engine";
import { readOwnedArtifactBytes } from "../artifact-readers/reader";
import { ResultSchema, digest, type AnalysisReceipt } from "../contracts";
import { FirstPartyAnalysisStore } from "../store";
import { analysisHostIdentity, ownershipBinding } from "../recovery";
import { probeProcessStartTokenAsync } from "../../runtime/process-start-token";

export async function runOwnedGeneralRecovery(
	receipt: AnalysisReceipt,
	store: FirstPartyAnalysisStore,
	abort: AbortController,
): Promise<AnalysisReceipt> {
	let proof: Promise<void> | undefined;
	let persistenceFailed = false;
	try {
		abort.signal.throwIfAborted();
		const request = receipt.input.bundleRecovery;
		if (request?.engine !== "wakaru")
			throw new Error("Explicit native recovery request required");
		const { bytes, resolved, sha256 } = await readOwnedArtifactBytes(
			receipt.workspace,
			receipt.input.target,
			request.expectedSha256,
			1024 * 1024,
		);
		abort.signal.throwIfAborted();
		const report = await runPinnedGeneralRecovery(
			bytes,
			sha256,
			abort.signal,
			(pid) => {
				// The parser can already be running. Missing birth proof never grants
				// restart recovery: unresolved reservations remain blocked, not replayed.
				proof = (async () => {
					if (!pid) throw new Error("Native parser PID unavailable");
					receipt.pid = pid;
					store.save(receipt);
					const [host, owner, worker] = await Promise.all([
						analysisHostIdentity(),
						probeProcessStartTokenAsync(process.pid),
						probeProcessStartTokenAsync(pid),
					]);
					if (host && owner.status === "found" && worker.status === "found") {
						const owned = {
							version: 1 as const,
							host,
							nonce: randomUUID(),
							owner: { pid: process.pid, token: owner.token },
							worker: { pid, token: worker.token },
							...(process.platform === "linux"
								? {
										descendants: {
											kind: "linux-private-process-group" as const,
											id: pid,
										},
									}
								: {}),
						};
						receipt.ownership = {
							...owned,
							binding: ownershipBinding(receipt, owned),
						};
						store.save(receipt);
					}
				})().catch(() => {
					persistenceFailed = true;
					abort.abort();
				});
			},
		);
		await proof;
		abort.signal.throwIfAborted();
		if (persistenceFailed)
			throw new Error("Native ownership persistence failed");
		receipt.result = ResultSchema.parse({
			profile: receipt.profile,
			parserVersion: report.engine,
			status: "partial",
			artifacts: [
				{
					path: path
						.relative(realpathSync.native(receipt.workspace), resolved)
						.split(path.sep)
						.join("/"),
					sha256,
					bytes: bytes.length,
					role: "bundle-recovery-input",
				},
			],
			facts: [],
			edges: [],
			limitations: report.limitations,
			counters: {
				entries: 1,
				bytes: bytes.length,
				nodes: report.modules.length,
			},
			bundleRecovery: report,
		});
		receipt.resultHash = digest(receipt.result);
		receipt.status = "partial";
		receipt.exitCode = 0;
	} catch (error) {
		await proof;
		delete receipt.result;
		delete receipt.resultHash;
		if (error instanceof GeneralRecoveryTerminationUnconfirmedError) {
			receipt.status = "termination-unconfirmed";
			receipt.error =
				"Native parser descendant stop was not confirmed; reservation and private scratch retained";
		} else if (abort.signal.aborted) {
			receipt.status = "cancelled";
			receipt.error = persistenceFailed
				? "Native ownership persistence failed; no automatic replay"
				: "Cancelled without replay";
		} else if (error instanceof GeneralRecoveryExecutionError) {
			receipt.status = "failed";
			receipt.error = error.message;
		} else {
			receipt.status = "failed";
			receipt.error =
				"Native recovery unavailable, input changed or fixed engine validation failed; no fallback or automatic replay";
		}
	}
	receipt.completedAt = new Date().toISOString();
	try {
		store.save(receipt);
	} catch {
		// The on-disk running reservation is retained if terminal persistence fails.
		receipt.status = "termination-unconfirmed";
		receipt.error =
			"Native recovery terminal persistence failed; reservation retained, no replay";
		delete receipt.result;
		delete receipt.resultHash;
	}
	return receipt;
}
