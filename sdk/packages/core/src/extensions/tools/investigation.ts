import { BatchStaticRequestSchema } from "./batch-analysis-schema";
import { z } from "zod";
import { RuntimeObservationOptionsSchema } from "./runtime-observation-schema";
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
		request: BatchStaticRequestSchema,
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
 run_device_smoke_test: z.discriminatedUnion("action", [
  z.object({action:z.literal("start"),artifactId:Id,deviceSerial:z.string().trim().min(1).max(200),packageName:z.string().regex(/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/),durationSeconds:z.number().int().min(2).max(120).default(10),purpose:z.string().trim().min(1).max(2000),hybridProposal:HybridProposalSchema.optional()}).strict(),
  z.object({action:z.enum(["status","cancel"]),taskId:Id}).strict(),
 ]),
	correlate_static_runtime: z
		.object({ receiptId: Id, taskIds: z.array(Id).min(1).max(10) })
		.strict(),
	plan_batch: BatchRequest,
	preview_batch: BatchRequest,
	run_batch: BatchRequest,
	checkpoint_investigation: z.object({ receiptId: Id }).strict(),
	cancel_batch: z.object({ receiptId: Id }).strict(),
	resume_investigation: z
		.object({ receiptId: Id, revision: z.number().int().min(0) })
		.strict(),
	attach_debug_session: z
		.object({
			artifactId: Id,
			pid: z.number().int().positive().max(4294967295),
			endpoint: z
				.string()
				.max(200)
				.regex(/^ws:\/\/127\.0\.0\.1:[0-9]{1,5}\/[a-fA-F0-9-]{36}$/),
			lifetimeMs: z.number().int().min(1000).max(120000).default(60000),
			hybridProposal: HybridProposalSchema.optional(),
		})
		.strict(),
	set_scoped_breakpoints: z
		.object({
			runtimeSessionId: Id,
			locations: z
				.array(
					z
						.object({
							line: z.number().int().min(0).max(100000),
							column: z.number().int().min(0).max(4096).default(0),
						})
						.strict(),
				)
				.min(1)
				.max(8),
		})
		.strict(),
	capture_execution_trace: z
		.object({
			runtimeSessionId: Id,
			durationMs: z.number().int().min(200).max(2000).default(1000),
		})
		.strict(),
	stop_runtime_session: z.object({ runtimeSessionId: Id }).strict(),
	capture_process_tree: z
		.object({
			artifactId: Id,
			pid: z.number().int().positive().max(4294967295),
			maxProcesses: z.number().int().min(1).max(128).default(64),
			hybridProposal: HybridProposalSchema.optional(),
		})
		.strict(),
	capture_file_activity: z
		.object({
			artifactId: Id,
			durationMs: z.number().int().min(200).max(5000).default(1000),
			maxEvents: z.number().int().min(1).max(128).default(64),
			hybridProposal: HybridProposalSchema.optional(),
		})
		.strict(),
	plan_runtime_observation: z
		.object({ artifactId: Id, observation: RuntimeObservationOptionsSchema })
		.strict(),
	validate_candidate: z
		.object({
			artifactId: Id,
			kind: z.enum(["javascript", "typescript", "dex", "apk"]),
		})
		.strict(),
	review_candidate_changes: z.object({ artifactId: Id }).strict(),
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
 run_device_smoke_test: "Request a separately human-approved launch and bounded 2–120 second process/crash-log observation on one explicitly selected authorized Android device. Uses an immutable workspace APK; installed base APK hash and manifest package must match before launch and after observation. Runtime/Hybrid, attached Full Access only; Hybrid requires real static evidence. No install, uninstall, root, Frida, UI interaction or automatic force-stop. Launch can leave the app running and change its data/network state. Start returns an asynchronous task, not a pass; status/cancel are owning-session reads/cleanup available after Analysis Off. No observed crash does not prove health, regression success or split APK identity. Never claim physical-device validation from fixtures.",
	correlate_static_runtime:
		"Reconcile one exact owning-session saved static receipt with up to ten saved approved task snapshots (at least one runtime task). Hash/scope checks, exact artifact identity, selected Node CPU-sample function-definition-line candidates and supported native module/RVA observations only. Read-only: no attachment, execution, downloads, approval grant or automatic rerun. Shared lines, sampled locations and byte identity never prove causal execution paths or behavior. Unmatched identities stay unresolved.",
	plan_batch:
		"Validate a bounded dependency graph of up to 12 existing workspace artifact inspection, JS/TS/Electron/.NET/mitigation/comparison and saved-graph stages. Uses the durable desktop runner. No shell, target execution or candidate writes; no approval or execution occurs.",
	preview_batch:
		"Preview canonical input hashes, dependency ordering, scope and budgets for a bounded built-in static batch. No approval or execution occurs.",
	run_batch:
		"Request execution of a bounded built-in static batch after fresh independent human approval. Returns an asynchronous receipt, not a completion claim. Inspect it with checkpoint_investigation. Includes bounded JS/TS/Electron/.NET/mitigation comparisons and saved-graph reads. Partial/blocked analysis stops dependents; no shell, candidate writes, runtime, external engines or produced-input chaining.",
	checkpoint_investigation:
		"Read the latest durable owning-session batch checkpoint with revision, per-stage results and integrity hash. Does not force a new checkpoint or repeat work; available for cleanup/status after Analysis is disabled.",
	cancel_batch:
		"Cancel only this owning-session AI batch through the existing supervised runner. Read its checkpoint to confirm terminal outcome; never replays stages. Available after Analysis is disabled.",
	resume_investigation:
		"Request a freshly approved continuation of never-started built-in static stages from an exact terminal checkpoint revision. Revalidates every input hash, implementation fingerprint and reused result. Never retries failed/started stages or replays writes/runtime; unresolved dependencies block continuation.",
	attach_debug_session:
		"Request a separately human-approved Execute/debug-control session for one exact local Node Inspector PID/birth/listener and hash-matched loaded source. Runtime/Hybrid and attached Full Access only. Lifetime 1–120 seconds, one per owner/two globally. Activation and cleanup CAN pause/resume the process. No evaluate/launch/step/explicit resume; not passive or exclusive. Hybrid requires a real static basis. Missing loaded source fails without starting it.",
	set_scoped_breakpoints:
		"Request fresh Execute approval for at most eight unconditional zero-based breakpoints in the managed session's one hash-matched script. Can pause execution; no conditions, logpoints, expressions or automatic continuation. Owning session only. Cleanup may resume the target.",
	capture_execution_trace:
		"Request fresh Execute approval for 200–2000 ms of V8 statistical CPU SAMPLING in an existing owned managed Node session, NOT a full execution trace. Retain only selected-script nodes and samples with function names hashed. Empty samples do not prove no execution. No native/JVM/Android parity.",
	stop_runtime_session:
		"Stop an owned managed Node Inspector connection, even after Analysis Off. Bounded best-effort owned profiler stop/disable and debugger disable, then transport closure. No process kill or explicit resume, but disabling/disconnecting a debugger CAN resume a paused process. Report cleanup uncertainty; never claims target exit or exclusive debugger ownership.",
	capture_process_tree:
		"Request a fresh independently approved Runtime/Hybrid snapshot of one exact OS PID/birth identity and bounded descendants. Linux /proc or Windows CIM only; no command lines, environment, memory, process launch or execution control. Artifact is the immutable evidence basis, NOT proof it runs in that process. Host binds PID birth identity at prepare and rechecks before/after capture. Hybrid requires a real static basis. Non-atomic metadata, not an execution trace.",
	capture_file_activity:
		"Request fresh independently approved Runtime/Hybrid fs.watch metadata on exactly one immutable opened workspace file for 200–5000 ms, maximum 128 events. No contents, filenames from sibling files, recursive directory watch or process attribution. OS notifications may be coalesced/missed; zero events never proves no access. Rename/replacement ends observation as partial. Hybrid requires a real static basis. Existing task cancellation closes the watcher.",
	plan_runtime_observation:
		"Prepare an independently approved read-only plan for an immutable source and an exact live local Node Inspector PID/birth identity/listener. No socket connection, attachment or target execution. Plan is NOT runtime consent: use the existing Runtime/Hybrid workbench with fresh human Debug approval and, in Hybrid, static evidence. Linux/Windows only; not a persistent debugger or trace command.",
	validate_candidate:
		"Request hash-bound candidate checks after independent human approval: JS/TS syntax, DEX header/checksum/table bounds, or APK structure and signature. Results declare their exact coverage, failures and unavailable checks; no execution, signing, build, install or semantic-equivalence claim.",
	review_candidate_changes:
		"Request read-only exact-recipe audit of an immutable candidate batch manifest after independent human approval. Verifies declared source hashes and candidate bytes using existing patch implementations; missing/mismatched/unverified outputs never pass. Only declared files, not a whole-project change review; cannot authorize writes or replay stages.",
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
