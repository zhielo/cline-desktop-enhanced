import { z } from "zod";
/** Proposal is evidence selection, never consent or execution authority. */
export const HybridProposalSchema = z
	.object({
		baselineKind: z.enum(["receipt", "static-task"]),
		baselineId: z.string().uuid(),
		question: z.string().trim().min(1).max(500),
	})
	.strict();
/** Host-derived evidence identity bound into the immutable runtime request. */
export const HybridContextSchema = HybridProposalSchema.extend({
	evidenceHash: z.string().regex(/^[a-f0-9]{64}$/),
	relation: z.enum(["exact-artifact-hash", "investigation-context-only"]),
}).strict();
export type HybridProposal = z.infer<typeof HybridProposalSchema>;
export type HybridContext = z.infer<typeof HybridContextSchema>;
export const runtimeAnalysisEnabled = (mode: unknown) =>
	mode === "runtime" || mode === "hybrid";
