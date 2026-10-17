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
/** Model inputs deliberately have no authority, owner, token, mode or consent fields. */
export const InvestigationSchemas = {
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
	open_binary:
		"Create an immutable workspace-confined artifact handle; does not execute or decompile the binary. Analysis mode must be enabled.",
	analyze_function:
		"Request one exact Ghidra/IDA function analysis for an open_binary artifact. The desktop requires fresh independent human approval of the hash-bound plan. No approval tokens or consent may be supplied. Installed provider/license required; no target execution.",
	trace_application_feature:
		"Reconcile selected owning-session static facts and recorded scenarios. Returns provenance, candidate links and unresolved boundaries, never proves runtime causality from label matches.",
	capture_browser_scenario:
		"List owned built-in browsers, or request bounded metadata-only recording. Start requires Runtime or Hybrid mode and fresh human recording consent. In Hybrid, inspect first using available static tools, then supply hybridProposal (owning receipt/static-task ID and the unresolved question). Missing evidence must be gathered, never invented. Hybrid does not launch targets automatically. Stop remains available after mode changes. Never opens/replays a browser or captures bodies/cookies.",
	capture_network_metadata: "Alias for capture_browser_scenario: owned built-in browser Network/Page protocol metadata only. Explicit fresh human consent and Runtime/Hybrid scope required; no bodies, headers, cookies, arbitrary process capture or automatic browser launch.",
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
