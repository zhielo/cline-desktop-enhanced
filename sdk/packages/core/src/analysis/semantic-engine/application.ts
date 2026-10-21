import { createHash } from "node:crypto";
import { posix } from "node:path";
import type { SourceArtifact } from "../parser";
import { digestCanonicalValue, SEMANTIC_REVISION } from "./engine";
import { completeJavaScriptAnalysisSteps } from "./upstream/src/application/javascript/JavaScriptAnalysisControl";
import { analyzeAndProjectJavaScriptArtifactFiles } from "./upstream/src/application/javascript/JavaScriptArtifactAnalysis";
import { buildImmutableJavaScriptArtifactGraphSteps } from "./upstream/src/application/javascript/JavaScriptArtifactGraphBuilder";
import { createJavaScriptSemanticGraphProjection } from "./upstream/src/application/javascript/JavaScriptSemanticGraphBuilder";
import { artifactInventoryResultSchema } from "./upstream/src/domain/artifactGraph";
import {
	artifactGraphDigest,
	artifactIdForContent,
	artifactManifestId,
	occurrenceIdForLocation,
} from "./upstream/src/domain/artifactIdentity";
import {
	createJavaScriptApplicationGraph,
	type JavaScriptApplicationGraph,
	parseJavaScriptApplicationGraph,
} from "./upstream/src/domain/javascript/javascriptApplicationGraph";
import type {
	JavaScriptArtifactFile,
	JavaScriptArtifactFileSet,
} from "./upstream/src/domain/javascript/javascriptArtifactFiles";
import type { JavaScriptSemanticGraph } from "./upstream/src/domain/javascript/javascriptSemanticGraph";
import { compareUnicodeCodePoints } from "./upstream/src/domain/unicodeCodePointOrder";

export { parseJavaScriptApplicationGraph };
export const APPLICATION_PROFILE = "cline-application/1";
export const APPLICATION_SCOPE =
	"Admitted source set only: root identifies a virtual path/hash manifest, not original application/container bytes. Unselected files and external modules remain unknown.";

function kind(path: string): JavaScriptArtifactFile["kind"] | undefined {
	if (posix.basename(path) === "package.json") return "package-json";
	if (/\.(?:[cm]?[jt]s|[jt]sx)$/i.test(path)) return "javascript";
	if (/\.map$/i.test(path)) return "source-map";
	if (/\.json$/i.test(path)) return "json";
	if (/\.html?$/i.test(path)) return "html";
	if (/\.node$/i.test(path)) return "native-addon";
	return undefined;
}

/** A validated virtual inventory of bytes already admitted by the owning reader. */
export function applicationArtifacts(sources: readonly SourceArtifact[]) {
	const paths = new Set<string>();
	const selected = sources
		.filter((s) => kind(s.path))
		.map((s) => {
			const path = s.path.normalize("NFC");
			if (
				posix.isAbsolute(path) ||
				path.includes("\\") ||
				/[\0\r\n]/.test(path) ||
				path.split("/").some((p) => !p || p === "." || p === "..") ||
				paths.has(path)
			)
				throw new Error("Invalid or duplicate application source path");
			paths.add(path);
			const bytes = s.binary ?? s.rawBytes ?? Buffer.from(s.source, "utf8");
			if (
				bytes.length !== s.bytes ||
				createHash("sha256").update(bytes).digest("hex") !== s.sha256
			)
				throw new Error("Application source hash or byte count mismatch");
			return { ...s, path };
		})
		.sort((a, b) => compareUnicodeCodePoints(a.path, b.path));
	const manifest = selected.map((s) => ({
		path: s.path,
		sha256: s.sha256,
		bytes: s.bytes,
	}));
	const manifestBytes = Buffer.from(JSON.stringify(manifest));
	const rootHash = createHash("sha256").update(manifestBytes).digest("hex");
	const rootId = artifactIdForContent(rootHash);
	const files: JavaScriptArtifactFile[] = selected.map((s) => ({
		path: s.path,
		sha256: s.sha256,
		bytes: s.bytes,
		container_sha256: rootHash,
		inventory_artifact_id: artifactIdForContent(s.sha256),
		kind: kind(s.path)!,
		unpacked: false,
		text: s.binary
			? { included: false, reason: "not-applicable" }
			: s.rawBytes
				? { included: false, reason: "invalid-utf8" }
				: { included: true, value: s.source },
	}));
	const dirs = new Set(["."]);
	for (const f of files) {
		for (let d = posix.dirname(f.path); d !== "."; d = posix.dirname(d))
			dirs.add(d);
	}
	const node = (sha256: string, size: number, virtual = false) => ({
		artifact_id: artifactIdForContent(sha256),
		format: virtual ? "directory" : "unknown",
		sha256,
		size,
		media_type: null,
		architecture: null,
		content_state: virtual ? "virtual" : "materialized",
		limitations: virtual ? [APPLICATION_SCOPE] : [],
	});
	const nodes = [
		...new Map(
			[
				node(rootHash, manifestBytes.length, true),
				...files.map((f) => node(f.sha256, f.bytes)),
			].map((n) => [n.artifact_id, n]),
		).values(),
	];
	const occurrence = (
		path: string,
		directory: boolean,
		file?: JavaScriptArtifactFile,
	) => ({
		occurrence_id: occurrenceIdForLocation({
			rootArtifactId: rootId,
			logicalPath: path,
			entryKind: directory ? "directory" : "file",
		}),
		artifact_id: file?.inventory_artifact_id ?? (path === "." ? rootId : null),
		parent_occurrence_id:
			path === "."
				? null
				: occurrenceIdForLocation({
						rootArtifactId: rootId,
						logicalPath: posix.dirname(path),
						entryKind: "directory",
					}),
		logical_path: path,
		entry_kind: directory ? "directory" : "file",
		artifact_kind: directory
			? "container"
			: file?.kind === "javascript"
				? "javascript"
				: "resource",
		artifact_format: directory ? "directory" : "unknown",
		declared_size: file?.bytes ?? null,
		compressed_size: null,
		executable: false,
		encrypted: false,
		hash_status: file ? "verified" : "not-hashed",
		source_location: null,
		limitations: [],
	});
	const occurrences = [
		...[...dirs].sort(compareUnicodeCodePoints).map((d) => occurrence(d, true)),
		...files.map((f) => occurrence(f.path, false, f)),
	];
	const parsed = artifactInventoryResultSchema.parse({
		manifest: {
			root_artifact_id: rootId,
			root_sha256: rootHash,
			root_format: "directory",
			graph_sha256: "0".repeat(64),
			manifest_id: `agm_${"0".repeat(64)}`,
			node_count: nodes.length,
			occurrence_count: occurrences.length,
			edge_count: 0,
		},
		nodes,
		occurrences,
		edges: [],
		provenance: [],
		integrity_contradictions: [],
		coverage: { scope: "container-entries", status: "unknown" },
		limitations: [APPLICATION_SCOPE],
	});
	const graphHash = artifactGraphDigest({ ...parsed, contradictions: [] });
	const snapshot = {
		...parsed,
		manifest: {
			...parsed.manifest,
			graph_sha256: graphHash,
			manifest_id: artifactManifestId(rootId, graphHash),
		},
	};
	const fileSet: JavaScriptArtifactFileSet = {
		files,
		containers: [],
		unavailable_relevant_files: [],
		text_bytes_read: files.reduce(
			(n, f) => n + (f.text.included ? f.bytes : 0),
			0,
		),
		invalid_utf8_files: files.filter(
			(f) => !f.text.included && f.text.reason === "invalid-utf8",
		).length,
	};
	return { snapshot, fileSet, manifest };
}

/** Original pure graph algorithms, executed inside the existing owned child. */
export async function analyzeApplicationSources(
	sources: readonly SourceArtifact[],
	signal?: AbortSignal,
) {
	if (signal?.aborted) throw new Error("Application analysis cancelled");
	const { snapshot, fileSet, manifest } = applicationArtifacts(sources);
	const projection = createJavaScriptSemanticGraphProjection();
	const analysis = await analyzeAndProjectJavaScriptArtifactFiles(
		fileSet,
		(f, ir) => projection.projectFileSteps(f, ir),
		undefined,
		signal,
	);
	for (const item of analysis.files) {
		if (item.file.kind === "javascript" && item.semantic === null)
			projection.recordUnavailableFile(
				item.file,
				item.file.text.included
					? "Source could not be parsed"
					: "Source text unavailable",
				null,
				"incomplete-module",
			);
	}
	const full = await completeJavaScriptAnalysisSteps(
		buildImmutableJavaScriptArtifactGraphSteps(snapshot, fileSet, analysis),
		signal,
	);
	// Never upgrade the admitted subset to a claim of complete container inventory.
	const application = createJavaScriptApplicationGraph({
		schema: full.schema,
		root_node_ids: full.root_node_ids,
		nodes: full.nodes,
		edges: full.edges,
		coverage: { ...full.coverage, status: "partial" },
		limitations: [...full.limitations, APPLICATION_SCOPE],
	});
	const semantic = await completeJavaScriptAnalysisSteps(
		projection.finishImmutableSteps(snapshot.manifest.root_sha256, application),
		signal,
	);
	return { application, semantic, manifest };
}

export function applicationSummary(
	graph: JavaScriptApplicationGraph,
	semantic: JavaScriptSemanticGraph,
	sources: readonly { path: string; sha256: string; bytes: number }[],
) {
	if (
		semantic.application_graph_id !== graph.graph_id ||
		createHash("sha256").update(JSON.stringify(sources)).digest("hex") !==
			semantic.root_artifact_sha256
	)
		throw new Error("Application/semantic graph binding mismatch");
	return {
		profile: APPLICATION_PROFILE as typeof APPLICATION_PROFILE,
		upstreamRevision: SEMANTIC_REVISION,
		graphId: graph.graph_id,
		graphHash: digestCanonicalValue(graph),
		semanticGraphHash: digestCanonicalValue(semantic),
		rootManifestHash: semantic.root_artifact_sha256,
		sources: [...sources],
		nodes: graph.nodes.length,
		edges: graph.edges.length,
		coverage: graph.coverage,
		scope: "admitted-application-sources" as const,
		limitations: [
			APPLICATION_SCOPE,
			"Static relationships are not runtime observations or behavioral equivalence.",
		],
	};
}
