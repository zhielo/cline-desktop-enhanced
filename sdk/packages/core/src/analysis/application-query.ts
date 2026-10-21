import { createHash } from "node:crypto";
import { posix } from "node:path";
import type { z } from "zod";
import {
	type EvidenceQuerySchema,
	semanticEvidencePage,
} from "./evidence-query";
import { parseJavaScriptApplicationGraph } from "./semantic-engine/application";
import { compareJavaScriptApplicationVersions } from "./semantic-engine/upstream/src/domain/javascript/javascriptApplicationVersionComparison";
import { compareJavaScriptExportShapes } from "./semantic-engine/upstream/src/domain/javascript/javascriptExportShapeComparison";
import { traceApplicationFeature } from "./semantic-engine/upstream/src/domain/javascript/javascriptFeatureTrace";
import { compareSourceToBundle } from "./semantic-engine/upstream/src/domain/javascript/sourceToBundleComparison";
import {
	createHistoricalSourceGraph,
	historicalSourceLanguages,
	historicalSourceManifests,
} from "./semantic-engine/upstream/src/domain/referenceSourceGraph";
import type { FirstPartyAnalysisStore } from "./store";

/** Pure queries over session-owned, hash-validated evidence; never opens a provider. */
export function queryApplicationEvidence(
	sessionId: string,
	q: z.infer<typeof EvidenceQuerySchema>,
	store: FirstPartyAnalysisStore,
) {
	const receipt = store.get(sessionId, q.receiptId);
	const summary = receipt.result?.applicationGraph;
	if (!summary || q.view === "application-summary")
		return {
			id: receipt.id,
			status: receipt.status,
			available: !!summary,
			summary,
		};
	const graph = parseJavaScriptApplicationGraph(
		store.applicationGraph(sessionId, receipt.id),
	);
	const identity = (r: typeof receipt) =>
		`ev_${createHash("sha256")
			.update(JSON.stringify([r.id, r.resultHash]))
			.digest("hex")}`;
	const evidenceId = identity(receipt);
	const source = {
		receiptId: receipt.id,
		resultHash: receipt.resultHash,
		graphHash: summary.graphHash,
	};
	if (q.view === "application-nodes" || q.view === "application-edges")
		return {
			id: receipt.id,
			available: true,
			source,
			...semanticEvidencePage(graph, q),
		};
	let workflow: Record<string, unknown>;
	let other: typeof source | undefined;
	if (q.view === "application-trace") {
		if (!q.applicationTrace)
			throw new Error("Application trace input required");
		const result = traceApplicationFeature({
			sourceEvidenceId: evidenceId,
			graph,
			nativeEvidence: [],
			...q.applicationTrace,
		});
		workflow = {
			...result,
			nodes: result.graph?.nodes ?? [],
			edges: result.graph?.edges ?? [],
		};
	} else {
		if (!q.compareReceiptId) throw new Error("Comparison receipt required");
		const right = store.get(sessionId, q.compareReceiptId);
		const rightSummary = right.result?.applicationGraph;
		if (!rightSummary)
			throw new Error("Comparison receipt has no application graph");
		const rightGraph = parseJavaScriptApplicationGraph(
			store.applicationGraph(sessionId, right.id),
		);
		other = {
			receiptId: right.id,
			resultHash: right.resultHash,
			graphHash: rightSummary.graphHash,
		};
		if (q.view === "application-source-bundle") {
			const entries = summary.sources.map((f) => ({
				kind: "file" as const,
				path: f.path,
				classifications: [
					posix.basename(f.path) === "package.json"
						? ("manifest" as const)
						: /\.[cm]?[jt]sx?$/i.test(f.path) || /\.html?$/i.test(f.path)
							? ("source" as const)
							: /\.map$/i.test(f.path)
								? ("generated" as const)
								: /\.json$/i.test(f.path)
									? ("config" as const)
									: ("unknown" as const),
				],
				limitations: [],
				language: /\.[cm]?tsx?$/i.test(f.path)
					? "TypeScript"
					: /\.[cm]?jsx?$/i.test(f.path)
						? "JavaScript"
						: /\.html?$/i.test(f.path)
							? "HTML"
							: null,
				sha256: f.sha256,
				size: f.bytes,
				content_state: "hashed" as const,
			}));
			const reference = createHistoricalSourceGraph({
				schema: "HistoricalSourceGraph",
				authority: "historical-reference",
				root_alias: "$REFERENCE_ROOT",
				inventory_state: "partial",
				entries,
				relationships: [],
				parse_failures: [],
				exclusions: [],
				languages: historicalSourceLanguages(entries),
				manifests: historicalSourceManifests(entries),
				vcs: null,
				provenance: {
					importer: "cline-admitted-source-manifest",
					importer_version: "1",
					caller: "cline-desktop",
				},
				limitations: [
					"Only receipt-admitted source metadata is available. Complete repository inventory and import relationships are not claimed.",
				],
			});
			const result = compareSourceToBundle({
				reference,
				application: {
					evidenceId: identity(right),
					rootArtifactSha256: rightSummary.rootManifestHash,
					graph: rightGraph,
				},
			});
			workflow = { ...result };
		} else if (q.view === "application-exports") {
			if (!q.exportSelectors)
				throw new Error("Exact export selectors required");
			const result = compareJavaScriptExportShapes({
				left: { evidenceId, graph, ...q.exportSelectors.left },
				right: {
					evidenceId: identity(right),
					graph: rightGraph,
					...q.exportSelectors.right,
				},
			});
			workflow = { ...result };
		} else {
			const result = compareJavaScriptApplicationVersions({
				left: {
					evidenceId,
					rootArtifactSha256: summary.rootManifestHash,
					graph,
				},
				right: {
					evidenceId: identity(right),
					rootArtifactSha256: rightSummary.rootManifestHash,
					graph: rightGraph,
				},
				leftNativeEvidence: [],
				rightNativeEvidence: [],
			});
			workflow = {
				...result,
				nodes: result.graph?.nodes ?? [],
				edges: result.graph?.edges ?? [],
			};
		}
	}
	const limitations = Array.isArray(workflow.limitations)
		? (workflow.limitations as string[])
		: [];
	const metadata = (value: unknown) =>
		Buffer.byteLength(JSON.stringify(value ?? null)) > 8192
			? { displayOmitted: true }
			: value;
	return {
		id: receipt.id,
		available: true,
		source,
		other,
		workflowId: workflow.trace_id ?? workflow.comparison_id,
		summary: metadata(workflow.summary),
		coverage: metadata(workflow.coverage),
		limitations: limitations.slice(0, 20).map((s) => s.slice(0, 1000)),
		omittedLimitations: Math.max(0, limitations.length - 20),
		providerCalls: 0,
		verifiedBehavior: false,
		...semanticEvidencePage(workflow, q),
	};
}
