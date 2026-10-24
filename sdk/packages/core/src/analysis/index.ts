export * from "./contracts";
export * from "./hybrid";
export {
	assertInspectorOwner,
	InspectorRequestSchema,
	observeJavaScriptInspector,
	sameInspectorSourcePath,
} from "./inspector";
export { recoverFirstPartyReservation } from "./recovery";
export {
	cancelFirstPartyAnalysis,
	configureFirstPartyAnalysisHost,
	runFirstPartyAnalysis,
} from "./service";
export { FirstPartyAnalysisStore } from "./store";
export {
	dossierDisagreements,
	nativeDossiers,
	UnifiedEvidenceStore,
	unifiedEvidenceView,
} from "./unified-evidence";
export async function runAnalysisWorkerEntrypoint() {
	const worker = await import("./worker");
	return worker.runAnalysisWorkerEntrypoint();
}

import { queryApplicationEvidence } from "./application-query";
import { EvidenceQuerySchema, semanticEvidencePage } from "./evidence-query";
import { javaScriptSemanticGraphSchema } from "./semantic-engine/upstream/src/domain/javascript/javascriptSemanticGraph";
import { queryJavaScriptSemanticGraph } from "./semantic-engine/upstream/src/domain/javascript/javascriptSemanticQuery";
import { FirstPartyAnalysisStore } from "./store";
import { ResultSchema, digest } from "./contracts";

export { EvidenceQuerySchema } from "./evidence-query";
export function queryFirstPartyEvidence(
	sessionId: string,
	input: unknown,
	store = new FirstPartyAnalysisStore(),
) {
	const q = EvidenceQuerySchema.parse(input),
		receipt = store.get(sessionId, q.receiptId);
	const result = receipt.result;
	if (q.view === "source-acquisition" || q.view === "source-containers") {
		const report = result?.acquisition
			? ResultSchema.parse(result).acquisition
			: undefined;
		if (!report)
			return { id: receipt.id, available: false, status: receipt.status };
		return {
			id: receipt.id,
			available: true,
			resultHash: receipt.resultHash,
			manifestSha256: report.manifestSha256,
			selectedPath: report.selectedPath,
			selection: report.selection,
			coverage: report.coverage,
			containerCount: report.containers.length,
			limitations: report.limitations,
			providerCalls: 0,
			targetExecuted: false,
			verifiedBehavior: false,
			...semanticEvidencePage(report, q),
		};
	}
	if (q.view === "bundle-recovery") {
		const report = result?.bundleRecovery;
		if (!report)
			return { id: receipt.id, available: false, status: receipt.status };
		return {
			id: receipt.id,
			available: true,
			resultHash: receipt.resultHash,
			reportHash: digest(report),
			engine: report.engine,
			upstreamRevision: report.upstreamRevision,
			...(report.engine === "wakaru/1.14.0"
				? {
						engineSha256: report.engineSha256,
						resourceBoundary: report.resourceBoundary,
						detectedFormats: report.detectedFormats,
						strategy: report.strategy,
						safety: report.safety,
						warnings: report.warnings
							.slice(0, 10)
							.map((w) => ({ ...w, message: w.message.slice(0, 500) })),
						omittedWarnings: Math.max(0, report.warnings.length - 10),
					}
				: {}),
			sourceSha256: report.sourceSha256,
			truncated: report.truncated,
			omitted: report.omitted,
			limitations: report.limitations,
			providerCalls: 0,
			targetExecuted: false,
			verifiedBehavior: false,
			...semanticEvidencePage(report, q),
		};
	}
	if (q.view === "artifact-metadata") {
		const report = result?.artifactMetadata;
		if (!report)
			return { id: receipt.id, available: false, status: receipt.status };
		return {
			id: receipt.id,
			available: true,
			resultHash: receipt.resultHash,
			reader: report.reader,
			inputSha256: report.inputSha256,
			truncated: report.truncated,
			omitted: report.omitted,
			limitations: report.limitations,
			providerCalls: 0,
			targetExecuted: false,
			verifiedBehavior: false,
			...semanticEvidencePage(report, q),
		};
	}
	if (q.view === "electron-fuses") {
		const report = result?.electronFuses;
		if (!report)
			return { id: receipt.id, available: false, status: receipt.status };
		return {
			id: receipt.id,
			available: true,
			resultHash: receipt.resultHash,
			artifact: report.artifact,
			section: q.fuseSection ?? "slices",
			limitations: report.limitations.slice(0, 20).map((s) => s.slice(0, 1000)),
			omittedLimitations: Math.max(0, report.limitations.length - 20),
			providerCalls: 0,
			targetExecuted: false,
			verifiedBehavior: false,
			...semanticEvidencePage(
				{
					...report,
					sentinels: report.slices.flatMap((slice) =>
						slice.sentinels.map((sentinel) => ({
							slice_index: slice.index,
							architecture: slice.architecture,
							...sentinel,
						})),
					),
				},
				q,
			),
		};
	}
	if (q.view.startsWith("application-"))
		return queryApplicationEvidence(sessionId, q, store);
	if (q.view.startsWith("semantic-")) {
		const summary = result?.semanticGraph;
		if (!summary || q.view === "semantic-summary")
			return {
				id: receipt.id,
				available: !!summary,
				status: receipt.status,
				summary,
			};
		const graph = store.semanticGraph(sessionId, receipt.id);
		if (!graph) throw new Error("Semantic evidence unavailable");
		if (q.view === "semantic-trace") {
			const trace = queryJavaScriptSemanticGraph(
				javaScriptSemanticGraphSchema.parse(graph),
				q.trace,
			);
			return {
				id: receipt.id,
				available: true,
				graphHash: summary.graphHash,
				queryId: trace.query_id,
				status: trace.status,
				direction: trace.direction,
				summary: trace.summary,
				coverage: trace.coverage,
				limitations: trace.limitations,
				...semanticEvidencePage(trace as unknown as Record<string, unknown>, q),
			};
		}
		return {
			id: receipt.id,
			available: true,
			graphHash: summary.graphHash,
			...semanticEvidencePage(graph, q),
		};
	}
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
			recovery: store.recovery(receipt.id),
			limitations: result?.limitations,
			comparison: result?.comparison
				? {
						added: result.comparison.added,
						removed: result.comparison.removed,
						changed: result.comparison.changed,
						findingsCount: result.comparison.findings?.length ?? 0,
						limitations: result.comparison.limitations,
					}
				: undefined,
			verifiedBehavior: false,
			note: "Receipt integrity and static inspection are not behavioral certification.",
		};
	const all =
		q.view === "artifacts"
			? (result?.artifacts ?? [])
			: q.view === "graph"
				? (result?.edges ?? [])
				: q.view === "comparison"
					? (result?.comparison?.findings ?? [])
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
		available:
			q.view !== "comparison" || result?.comparison?.findings !== undefined,
		total: filtered.length,
		offset: q.offset,
		items: filtered.slice(q.offset, q.offset + q.limit),
		nextOffset:
			q.offset + q.limit < filtered.length ? q.offset + q.limit : null,
	};
}

export { correlateSavedEvidence } from "./correlation";
export {
	reconcileProcessScenario,
	ScenarioExpectationSchema,
} from "./scenario";

export { semanticSourceNotices } from "./semantic-engine/notices";

export {
	querySavedNativeValueFlow,
	NativeFlowQuerySchema,
} from "./native-value-flow";
