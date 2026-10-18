import { realpathSync } from "node:fs";
import { bindHybridObservation } from "./hybrid-analysis";
import { InvestigationSchemas, HybridProposalSchema, runtimeAnalysisEnabled, correlateSavedEvidence } from "@cline/core";
import { evidenceIndex, reconcileFeature } from "./investigation-report";
import { createHash } from "node:crypto";
import { z } from "zod";
import { redactSensitiveText } from "@cline/core";
import type {
	AnalysisWorkflowStore,
	WorkflowScope,
} from "./analysis-workflow-store";
const Id = z.string().uuid();
export const BATCH_WORKFLOW_COMMANDS = ["plan_batch", "preview_batch", "run_batch", "checkpoint_investigation", "cancel_batch", "resume_investigation"] as const;
export const WORKFLOW_COMMANDS = [
 ...BATCH_WORKFLOW_COMMANDS,
	"attach_debug_session",
 "set_scoped_breakpoints",
 "capture_execution_trace",
 "stop_runtime_session",
 "capture_process_tree",
	"capture_file_activity",
	"plan_runtime_observation",
	"validate_candidate",
 "review_candidate_changes",
	"open_binary",
	"analyze_function",
	"trace_application_feature",
	"capture_browser_scenario",
 "capture_network_metadata",
	"get_evidence_bundle",
 "correlate_static_runtime",
	"analysis_workflow_status",
	"analysis_workflow_hybrid_prepare",
] as const;
export interface WorkflowPorts {
	invoke: (command: string, args: Record<string, unknown>) => Promise<unknown>;
	staticReceipt: (id: string) => unknown;
	taskBundle: (id: string) => unknown;
	capture: (input: Record<string, unknown>) => Promise<unknown>;
	browsers?: () => unknown;
 managedSession?: (id:string)=>{target:string;expected_sha256:string;hybrid?:unknown};
 managedRuntime?: (command:string,input:unknown)=>Promise<unknown>;
 runtimeCapture?: (command: string, input: unknown) => Promise<unknown>;
 batch?: (command: string, input: unknown) => Promise<unknown>;
}
export function sanitizeEvidence(value: unknown): unknown {
	const secrets = Object.entries(process.env)
		.filter(([key]) => /token|secret|password|api.?key|credential/i.test(key))
		.map(([, v]) => v ?? "");
	const visit = (v: unknown, depth = 0): unknown => {
		if (depth > 40) throw new Error("Evidence nesting budget");
		if (typeof v === "string") return redactSensitiveText(v, secrets);
		if (Array.isArray(v)) return v.map((x) => visit(x, depth + 1));
		if (v && typeof v === "object")
			return Object.fromEntries(
				Object.entries(v).map(([k, x]) => [
					k,
					/^(password|secret|authorization|cookie|set-cookie|accessToken|refreshToken|executionToken|apiKey)$/i.test(
						k,
					)
						? "[REDACTED]"
						: visit(x, depth + 1),
				]),
			);
		return v;
	};
	return visit(value);
}
export function buildEvidenceBundle(scope: WorkflowScope, records: unknown[]) {
	const payload = {
		schemaVersion: 1,
		coverage: "selected-session-investigation-evidence",
		sessionId: scope.sessionId,
		exportedAt: new Date().toISOString(),
		records: sanitizeEvidence(records),
		report: sanitizeEvidence({
			schemaVersion: 1,
			evidenceIndex: evidenceIndex(records),
			conclusion:
				"Selected evidence only; no claim of complete behavior reconstruction or REA superiority.",
			reviewBeforeSharing: true,
		}),
		limitations: [
			"Selected records only; not a whole-database backup.",
			"Redaction is best-effort; review before sharing. No settings, credential files, cookies or browser bodies are included.",
			"Hashes establish integrity, not correctness or producer authentication.",
		],
	};
	const encoded = JSON.stringify(payload);
	if (Buffer.byteLength(encoded) > 4 * 1024 * 1024)
		throw new Error("Evidence bundle exceeds 4 MiB; select fewer records");
	return {
		payload,
		bundleHash: createHash("sha256").update(encoded).digest("hex"),
	};
}
export function featureTrace(
	feature: string,
	receipt: unknown,
	scenarios: unknown[],
	tasks: unknown[] = [],
) {
	return reconcileFeature(feature, receipt, scenarios, tasks);
}
export async function handleAnalysisWorkflow(
	command: string,
	input: unknown,
	scope: WorkflowScope,
	options: { trusted: boolean; idle: boolean; mode: string; actor?: "model" },
	store: AnalysisWorkflowStore,
	ports: WorkflowPorts,
) {
 if (command === "stop_runtime_session") {
  if (!options.trusted || !ports.managedRuntime) throw new Error("Trusted owning cleanup host required");
  return ports.managedRuntime(command,InvestigationSchemas.stop_runtime_session.parse(input));
 }
 if ((BATCH_WORKFLOW_COMMANDS as readonly string[]).includes(command)) {
  const cleanup = command === "checkpoint_investigation" || command === "cancel_batch";
  if (!options.trusted || (!cleanup && ((!options.idle && options.actor !== "model") || options.mode === "off")))
   throw new Error("Batch work requires a trusted owning session with Analysis enabled");
  if (!ports.batch) throw new Error("Durable batch runner unavailable");
  return ports.batch(command, input);
 }
	if (command === "capture_network_metadata") command = "capture_browser_scenario";
 if (command === "analysis_workflow_hybrid_prepare") {
		if (
			!options.trusted ||
			options.mode !== "hybrid" ||
			(!options.idle && options.actor !== "model")
		)
			throw new Error(
				"Hybrid proposal requires a trusted enabled owning session",
			);
		return bindHybridObservation(input, scope, {
			receipt: ports.staticReceipt,
			task: (id) =>
				(ports.taskBundle(id) as { providerSnapshot?: unknown })
					?.providerSnapshot,
		});
	}
	if (command === "analysis_workflow_status")
		return {
			workspace: scope.workspace,
			artifacts: store.list(scope, "artifact"),
			scenarios: store.list(scope, "scenario"),
			browsers: ports.browsers?.() ?? [],
			mode: options.mode,
		};
	if (command === "correlate_static_runtime") {
  if (!options.trusted) throw new Error("Trusted owning saved-evidence host required");
  const req=InvestigationSchemas.correlate_static_runtime.parse(input);
  if(new Set(req.taskIds).size!==req.taskIds.length)throw new Error("Select distinct task IDs");
  const snapshots=req.taskIds.map(id=>{
   const bundle=ports.taskBundle(id) as {providerSnapshot?:unknown};
   if(!bundle?.providerSnapshot)throw new Error("Owning hash-checked provider snapshot unavailable; no observation will be rerun");
   return bundle.providerSnapshot;
  });
  return correlateSavedEvidence({...scope,workspace:realpathSync(scope.workspace)},ports.staticReceipt(req.receiptId),snapshots);
 }
	if (command === "get_evidence_bundle") {
		const req = z
			.object({
				receiptIds: z.array(Id).max(10).default([]),
				taskIds: z.array(Id).max(10).default([]),
				scenarioIds: z.array(Id).max(5).default([]),
			})
			.strict()
			.parse(input);
		if (
			!req.receiptIds.length &&
			!req.taskIds.length &&
			!req.scenarioIds.length
		)
			throw new Error("Select evidence records explicitly");
		return buildEvidenceBundle(scope, [
			...req.receiptIds.map(ports.staticReceipt),
			...req.taskIds.map(ports.taskBundle),
			...req.scenarioIds.map((id) => store.get(scope, id, "scenario")),
		]);
	}
	if (command === "trace_application_feature") {
		const req = z
			.object({
				feature: z.string().trim().min(1).max(160),
				receiptId: Id.optional(),
				taskIds: z.array(Id).max(5).default([]),
				scenarioIds: z.array(Id).max(5).default([]),
			})
			.strict()
			.parse(input);
		return featureTrace(
			req.feature,
			req.receiptId ? ports.staticReceipt(req.receiptId) : undefined,
			req.scenarioIds.map((id) => store.get(scope, id, "scenario")),
			req.taskIds.map(ports.taskBundle),
		);
	}
	if (command === "capture_browser_scenario") {
		const req = z
			.object({
				browserSessionId: Id,
				action: z.enum(["start", "stop"]),
				confirmRecord: z.literal(true),
				purpose: z.string().min(1).max(160),
				hybridProposal: z
					.unknown()
					.transform((value) => HybridProposalSchema.parse(value))
					.optional(),
			})
			.strict()
			.parse(input);
		if (!options.trusted)
			throw new Error(
				"Trusted connection required for browser recording control",
			);
		if (
			req.action === "start" &&
			((!options.idle && options.actor !== "model") ||
				!runtimeAnalysisEnabled(options.mode))
		)
			throw new Error(
				"Browser scenario capture requires an idle Runtime session and explicit recording approval",
			);
		let hybrid: Awaited<ReturnType<typeof bindHybridObservation>> | undefined;
		if (req.action === "start" && options.mode === "hybrid") {
			hybrid = await bindHybridObservation(req.hybridProposal, scope, {
				receipt: ports.staticReceipt,
				task: (id) =>
					(ports.taskBundle(id) as { providerSnapshot?: unknown })
						?.providerSnapshot,
			});
		}
		const { hybridProposal: _proposal, ...captureRequest } = req;
		const result = await ports.capture({
			...captureRequest,
			...(hybrid ? { hybrid } : {}),
		});
		if (req.action !== "stop") return result;
		try {
			return store.put(scope, "scenario", {
				purpose: (result as { purpose?: string })?.purpose ?? req.purpose,
				capture: result,
				recordedAt: new Date().toISOString(),
			});
		} catch {
			return {
				capture: result,
				evidenceWarning:
					"Observation stopped, but the receipt could not be persisted. Preserve this result; do not replay recording to repair metadata.",
			};
		}
	}
	if (
		!options.trusted ||
		(!options.idle && options.actor !== "model") ||
		options.mode === "off"
	)
		throw new Error(
			"New workflow work requires a trusted idle session with Analysis enabled",
		);
	if (command === "open_binary") {
		const req = z
			.object({ target: z.string().min(1).max(4096) })
			.strict()
			.parse(input);
		const artifact = await store.open(scope, req.target);
		return options.mode === "hybrid"
			? {
					...artifact,
					mode: "hybrid",
					nextStep:
						"Inspect statically using an available tool; an immutable handle alone is not a static analysis receipt. Propose runtime separately with human approval.",
				}
			: artifact;
	}
 if (["attach_debug_session","set_scoped_breakpoints","capture_execution_trace"].includes(command)) {
  if(!runtimeAnalysisEnabled(options.mode))throw new Error("Managed debugger requires Runtime/Hybrid; Static never enables debug control");
  if(!ports.managedRuntime)throw new Error("Managed runtime host unavailable");
  const envelope=z.object({phase:z.enum(["prepare","run"]).default("prepare"),planId:Id.optional(),executionToken:z.string().max(512).optional()}).passthrough().parse(input);
  const {phase,planId,executionToken,...publicInput}=envelope;
  const name=command as "attach_debug_session"|"set_scoped_breakpoints"|"capture_execution_trace";
  const params=InvestigationSchemas[name].parse(publicInput);
  let target:string,expected_sha256:string,hybrid:unknown,controlOptions:unknown;
  if("artifactId" in params){
   const artifact=await store.verify(scope,params.artifactId);target=artifact.path;expected_sha256=artifact.sha256;
   const {artifactId:_artifact,hybridProposal,...rest}=params;controlOptions=rest;
   if(options.mode!=="hybrid"&&hybridProposal)throw new Error("Hybrid proposal requires Hybrid mode");
   hybrid=options.mode==="hybrid"?await bindHybridObservation(hybridProposal,scope,{receipt:ports.staticReceipt,task:(id)=>(ports.taskBundle(id) as {providerSnapshot?:unknown})?.providerSnapshot},target):undefined;
  }else{
   const session=ports.managedSession?.(params.runtimeSessionId);if(!session)throw new Error("Owned managed runtime session unavailable");
   target=session.target;expected_sha256=session.expected_sha256;hybrid=session.hybrid;controlOptions=params;
  }
  return ports.managedRuntime(command,{phase,planId,executionToken,request:{operation:command,target,expected_sha256,options:controlOptions,...(hybrid?{hybrid}:{})}});
 }
 if (command === "capture_process_tree" || command === "capture_file_activity") {
  if (!runtimeAnalysisEnabled(options.mode)) throw new Error("Capture requires Runtime or Hybrid mode; Static never enables observation");
  const envelope = z.object({phase:z.enum(["prepare","run"]).default("prepare"),planId:Id.optional(),executionToken:z.string().max(512).optional()}).passthrough().parse(input);
  const {phase,planId,executionToken,...publicInput}=envelope;
  // SDK uses Zod 4; parse plain values rather than extending it with host Zod 3.
  const params=InvestigationSchemas[command].parse(publicInput);
  const artifact=await store.verify(scope,params.artifactId);
  const {hybridProposal,artifactId:_artifact,...captureOptions}=params;
  if (options.mode !== "hybrid" && hybridProposal) throw new Error("Hybrid proposal requires Hybrid mode");
  const hybrid=options.mode === "hybrid" ? await bindHybridObservation(hybridProposal,scope,{receipt:ports.staticReceipt,task:(id)=>(ports.taskBundle(id) as {providerSnapshot?:unknown})?.providerSnapshot},artifact.path) : undefined;
  if (!ports.runtimeCapture) throw new Error("Runtime capture host unavailable");
  return ports.runtimeCapture(command,{phase,planId,executionToken,request:{operation:command,target:artifact.path,expected_sha256:artifact.sha256,options:captureOptions,...(hybrid?{hybrid}:{})}});
 }
 if (command === "plan_runtime_observation") {
  const req = z.object({artifactId: Id, observation: z.unknown(), phase: z.enum(["prepare","run"]).default("prepare"), planId: Id.optional(), executionToken: z.string().max(512).optional()}).strict().parse(input);
  const params = InvestigationSchemas.plan_runtime_observation.parse({artifactId:req.artifactId, observation:req.observation});
  const artifact = await store.verify(scope, req.artifactId);
  const request = {operation: command, target: artifact.path, timeout_ms: 20000, runtime_observation_plan: {...params.observation, expected_sha256: artifact.sha256}};
  if (req.phase === "prepare") return ports.invoke("prepare_analysis_task", {kind:"static", request});
  if (!req.planId || !req.executionToken) throw new Error("A separately approved one-use plan is required");
  return ports.invoke("run_static_analysis", {input:request, planId:req.planId, executionToken:req.executionToken});
 }
 if (command === "validate_candidate" || command === "review_candidate_changes") {
  const req = z.object({
   artifactId: Id,
   kind: z.enum(["javascript", "typescript", "dex", "apk"]).optional(),
   phase: z.enum(["prepare", "run"]).default("prepare"),
   planId: Id.optional(), executionToken: z.string().max(512).optional(),
  }).strict().parse(input);
  if ((command === "validate_candidate") !== !!req.kind) throw new Error("Only validate_candidate requires a validation kind");
  const artifact = await store.verify(scope, req.artifactId);
  const request = {operation: command, target: artifact.path, timeout_ms: 120000,
   ...(command === "validate_candidate" ? {candidate_validation: {expected_sha256: artifact.sha256, kind: req.kind}} : {candidate_review: {manifest_sha256: artifact.sha256}})};
  if (req.phase === "prepare") return ports.invoke("prepare_analysis_task", {kind: "static", request});
  if (!req.planId || !req.executionToken) throw new Error("A separately approved one-use plan is required");
  return ports.invoke("run_static_analysis", {input: request, planId: req.planId, executionToken: req.executionToken});
 }
	if (command === "analyze_function") {
		const req = z
			.object({
				artifactId: Id,
				engine: z.enum(["ghidra", "ida"]),
				selector: z
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
					),
				phase: z.enum(["prepare", "run"]).default("prepare"),
				planId: Id.optional(),
				executionToken: z.string().max(512).optional(),
			})
			.strict()
			.parse(input);
		const artifact = await store.verify(scope, req.artifactId);
		const request = {
			engine: req.engine,
			operation: "decompile",
			timeout_ms: 120000,
			target: artifact.path,
			function_selector: req.selector,
		};
		if (req.phase === "prepare")
			return ports.invoke("prepare_analysis_task", { kind: "static", request });
		if (!req.planId || !req.executionToken)
			throw new Error("A separately approved one-use plan is required");
		return ports.invoke("run_static_analysis", {
			input: request,
			planId: req.planId,
			executionToken: req.executionToken,
		});
	}
	throw new Error("Unknown workflow operation");
}
