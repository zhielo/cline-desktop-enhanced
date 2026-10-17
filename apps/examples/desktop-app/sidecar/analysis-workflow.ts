import { bindHybridObservation } from "./hybrid-analysis";
import { HybridProposalSchema, runtimeAnalysisEnabled } from "@cline/core";
import { evidenceIndex, reconcileFeature } from "./investigation-report";
import { createHash } from "node:crypto";
import { z } from "zod";
import { redactSensitiveText } from "@cline/core";
import type {
	AnalysisWorkflowStore,
	WorkflowScope,
} from "./analysis-workflow-store";
const Id = z.string().uuid();
export const WORKFLOW_COMMANDS = [
	"open_binary",
	"analyze_function",
	"trace_application_feature",
	"capture_browser_scenario",
 "capture_network_metadata",
	"get_evidence_bundle",
	"analysis_workflow_status",
	"analysis_workflow_hybrid_prepare",
] as const;
export interface WorkflowPorts {
	invoke: (command: string, args: Record<string, unknown>) => Promise<unknown>;
	staticReceipt: (id: string) => unknown;
	taskBundle: (id: string) => unknown;
	capture: (input: Record<string, unknown>) => Promise<unknown>;
	browsers?: () => unknown;
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
