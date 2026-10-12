export * from "./contracts";
export { FirstPartyAnalysisStore } from "./store";
export {
	configureFirstPartyAnalysisHost,
	runFirstPartyAnalysis,
	cancelFirstPartyAnalysis,
} from "./service";
export async function runAnalysisWorkerEntrypoint() {
	const worker = await import("./worker");
	return worker.runAnalysisWorkerEntrypoint();
}

import { z } from "zod";
import { FirstPartyAnalysisStore } from "./store";
export const EvidenceQuerySchema = z
	.object({
		receiptId: z.string().uuid(),
		view: z
			.enum(["artifacts", "findings", "graph", "verification"])
			.default("findings"),
		offset: z.number().int().min(0).max(10000).default(0),
		limit: z.number().int().min(1).max(50).default(20),
		filter: z.string().max(200).default(""),
	})
	.strict();
export function queryFirstPartyEvidence(
	sessionId: string,
	input: unknown,
	store = new FirstPartyAnalysisStore(),
) {
	const q = EvidenceQuerySchema.parse(input),
		receipt = store.get(sessionId, q.receiptId);
	const result = receipt.result;
	if (q.view === "verification")
		return {
			id: receipt.id,
			status: receipt.status,
			profile: receipt.profile,
			requestHash: receipt.requestHash,
			resultHash: receipt.resultHash,
			pid: receipt.pid,
			exitCode: receipt.exitCode,
			signal: receipt.signal,
			createdAt: receipt.createdAt,
			completedAt: receipt.completedAt,
			error: receipt.error,
			limitations: result?.limitations,
			comparison: result?.comparison,
			verifiedBehavior: false,
			note: "Receipt integrity and static inspection are not behavioral certification.",
		};
	const all =
		q.view === "artifacts"
			? (result?.artifacts ?? [])
			: q.view === "graph"
				? (result?.edges ?? [])
				: (result?.facts ?? []);
	const filtered = q.filter
		? all.filter((v) =>
				JSON.stringify(v).toLowerCase().includes(q.filter.toLowerCase()),
			)
		: all;
	return {
		id: receipt.id,
		status: receipt.status,
		resultHash: receipt.resultHash,
		view: q.view,
		total: filtered.length,
		offset: q.offset,
		items: filtered.slice(q.offset, q.offset + q.limit),
		nextOffset:
			q.offset + q.limit < filtered.length ? q.offset + q.limit : null,
	};
}
