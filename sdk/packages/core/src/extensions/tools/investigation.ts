import { z } from "zod";
import {
	createTool,
	zodToJsonSchema,
	type AgentTool,
	type AgentToolContext,
} from "@cline/shared";
import { HybridProposalSchema } from "../../analysis/hybrid";
const Id = z.string().uuid();
const Selector = z
	.object({
		symbol: z.string().min(1).max(4096).optional(),
		address: z
			.string()
			.regex(/^0x[0-9a-fA-F]{1,16}$/)
			.optional(),
	})
	.strict()
	.refine(
		(v) => !!v.symbol !== !!v.address,
		"Choose exactly one function selector",
	);
const CaptureSchema = z
	.object({
		action: z.enum(["list", "start", "stop"]),
		browserSessionId: Id.optional(),
		purpose: z.string().trim().min(1).max(160).optional(),
		hybridProposal: HybridProposalSchema.optional(),
	})
	.strict()
	.refine(
		(v) => v.action === "list" || !!(v.browserSessionId && v.purpose),
		"Recording requires browserSessionId and purpose",
	);
const BatchStage = z
	.object({
		id: z.string().regex(/^[A-Za-z0-9_-]{1,50}$/),
		depends_on: z
			.array(z.string().regex(/^[A-Za-z0-9_-]{1,50}$/))
			.max(12)
			.default([]),
		timeout_ms: z.number().int().min(1000).max(120000).default(120000),
		request: z
			.object({
				operation: z.enum(["inspect", "scan_strings", "compare_apks"]),
				target: z.string().min(1).max(4096),
				compare_target: z.string().min(1).max(4096).optional(),
				max_results: z.number().int().min(1).max(500).default(100),
				min_string_length: z.number().int().min(4).max(1024).default(6),
			})
			.strict()
			.refine(
				(v) => v.operation !== "compare_apks" || !!v.compare_target,
				"Comparison requires compare_target",
			),
	})
	.strict();
const BatchRequest = z
	.object({
		operation_id: Id,
		title: z.string().trim().min(1).max(120),
		parallel: z.number().int().min(1).max(2).default(1),
		stages: z.array(BatchStage).min(1).max(12),
	})
	.strict();
/** Model inputs deliberately have no authority, owner, token, mode or consent fields. */
export const InvestigationSchemas = {
	plan_batch: BatchRequest,
	preview_batch: BatchRequest,
	run_batch: BatchRequest,
	checkpoint_investigation: z.object({ receiptId: Id }).strict(),
	cancel_batch: z.object({ receiptId: Id }).strict(),
	resume_investigation: z
		.object({ receiptId: Id, revision: z.number().int().min(0) })
		.strict(),
	validate_candidate: z.object({artifactId: Id, kind: z.enum(["javascript", "typescript", "dex", "apk"])}).strict(),
 review_candidate_changes: z.object({artifactId: Id}).strict(),
	open_binary: z.object({ target: z.string().min(1).max(4096) }).strict(),
	analyze_function: z
		.object({
			artifactId: Id,
			engine: z.enum(["ghidra", "ida"]),
			selector: Selector,
		})
		.strict(),
	trace_application_feature: z
		.object({
			feature: z.string().trim().min(1).max(160),
			receiptId: Id.optional(),
			taskIds: z.array(Id).max(5).default([]),
			scenarioIds: z.array(Id).max(5).default([]),
		})
		.strict(),
	capture_browser_scenario: CaptureSchema,
	capture_network_metadata: CaptureSchema,
	get_evidence_bundle: z
		.object({
			receiptIds: z.array(Id).max(10).default([]),
			taskIds: z.array(Id).max(10).default([]),
			scenarioIds: z.array(Id).max(5).default([]),
		})
		.strict(),
} as const;
export type InvestigationToolName = keyof typeof InvestigationSchemas;
export type InvestigationExecutor = (
	name: InvestigationToolName,
	input: Record<string, unknown>,
	context: AgentToolContext,
) => Promise<string>;
const descriptions: Record<InvestigationToolName, string> = {
	plan_batch:
		"Validate a bounded dependency graph of up to 12 existing workspace artifact inspect/string/APK-comparison stages. Uses the durable desktop runner. No shell, target execution or candidate writes; no approval or execution occurs.",
	preview_batch:
		"Preview canonical input hashes, dependency ordering, scope and budgets for a bounded built-in static batch. No approval or execution occurs.",
	run_batch:
		"Request execution of a bounded built-in static batch after fresh independent human approval. Returns an asynchronous receipt, not a completion claim. Inspect it with checkpoint_investigation. No shell, candidate writes, runtime, external engines or produced-input chaining in this front door.",
	checkpoint_investigation:
		"Read the latest durable owning-session batch checkpoint with revision, per-stage results and integrity hash. Does not force a new checkpoint or repeat work; available for cleanup/status after Analysis is disabled.",
	cancel_batch:
		"Cancel only this owning-session AI batch through the existing supervised runner. Read its checkpoint to confirm terminal outcome; never replays stages. Available after Analysis is disabled.",
	resume_investigation:
		"Request a freshly approved continuation of never-started built-in static stages from an exact terminal checkpoint revision. Revalidates every input hash, implementation fingerprint and reused result. Never retries failed/started stages or replays writes/runtime; unresolved dependencies block continuation.",
	validate_candidate: "Request hash-bound candidate checks after independent human approval: JS/TS syntax, DEX header/checksum/table bounds, or APK structure and signature. Results declare their exact coverage, failures and unavailable checks; no execution, signing, build, install or semantic-equivalence claim.",
 review_candidate_changes: "Request read-only exact-recipe audit of an immutable candidate batch manifest after independent human approval. Verifies declared source hashes and candidate bytes using existing patch implementations; missing/mismatched/unverified outputs never pass. Only declared files, not a whole-project change review; cannot authorize writes or replay stages.",
	open_binary:
		"Create an immutable workspace-confined artifact handle; does not execute or decompile the binary. Analysis mode must be enabled.",
	analyze_function:
		"Request one exact Ghidra/IDA function analysis for an open_binary artifact. The desktop requires fresh independent human approval of the hash-bound plan. No approval tokens or consent may be supplied. Installed provider/license required; no target execution.",
	trace_application_feature:
		"Reconcile selected owning-session static facts and recorded scenarios. Returns provenance, candidate links and unresolved boundaries, never proves runtime causality from label matches.",
	capture_browser_scenario:
		"List owned built-in browsers, or request bounded metadata-only recording. Start requires Runtime or Hybrid mode and fresh human recording consent. In Hybrid, inspect first using available static tools, then supply hybridProposal (owning receipt/static-task ID and the unresolved question). Missing evidence must be gathered, never invented. Hybrid does not launch targets automatically. Stop remains available after mode changes. Never opens/replays a browser or captures bodies/cookies.",
	capture_network_metadata:
		"Alias for capture_browser_scenario: owned built-in browser Network/Page protocol metadata only. Explicit fresh human consent and Runtime/Hybrid scope required; no bodies, headers, cookies, arbitrary process capture or automatic browser launch.",
	get_evidence_bundle:
		"Export explicitly selected owning-session evidence with integrity hash, provenance index and limitations. Not a backup; review best-effort redaction before sharing.",
};
export function createInvestigationTools(
	executor: InvestigationExecutor,
): AgentTool[] {
	return (Object.keys(InvestigationSchemas) as InvestigationToolName[]).map(
		(name) =>
			createTool<unknown, string>({
				name,
				description: descriptions[name],
				inputSchema: zodToJsonSchema(InvestigationSchemas[name]),
				timeoutMs: 300_000,
				executionMode: "sequential",
				retryable: false,
				maxRetries: 0,
				execute: (input, context) =>
					executor(name, InvestigationSchemas[name].parse(input), context),
			}),
	);
}
