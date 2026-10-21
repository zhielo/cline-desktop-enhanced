/// <reference lib="es2023.array" />
import { createHash } from "node:crypto";
import { setImmediate } from "node:timers/promises";
import type { SourceArtifact } from "../parser";
import { createJavaScriptSemanticGraphProjection } from "./upstream/src/application/javascript/JavaScriptSemanticGraphBuilder";
import { digestCanonicalValue } from "./upstream/src/domain/canonicalDigest";
import { analyzeParsedJavaScriptSemantics } from "./upstream/src/domain/javascript/javascriptSemanticAnalysis";
import {
	type JavaScriptSemanticGraph,
	javaScriptSemanticGraphSchema,
} from "./upstream/src/domain/javascript/javascriptSemanticGraph";
import { queryJavaScriptSemanticGraph } from "./upstream/src/domain/javascript/javascriptSemanticQuery";
import { parseJavaScriptSource } from "./upstream/src/domain/javascript/javascriptSourceParser";
import { compareUnicodeCodePoints } from "./upstream/src/domain/unicodeCodePointOrder";

export const SEMANTIC_PROFILE = "cline-semantic/1";
export const SEMANTIC_REVISION = "d0067ba34a39ea47dd7e11bb2e6169bc0938cc3f";
export const SEMANTIC_MAX_BYTES = 128 * 1024 * 1024;
export {
	queryJavaScriptSemanticGraph,
	javaScriptSemanticGraphSchema,
	digestCanonicalValue,
};
export type { JavaScriptSemanticGraph };
export type SemanticSummary = ReturnType<typeof semanticSummary>;
export function semanticSummary(graph: JavaScriptSemanticGraph) {
	return {
		profile: SEMANTIC_PROFILE as typeof SEMANTIC_PROFILE,
		upstreamRevision: SEMANTIC_REVISION,
		graphId: graph.graph_id,
		graphHash: digestCanonicalValue(graph),
		nodes: graph.nodes.length,
		relations: graph.relations.length,
		unknowns: graph.unknowns.length,
		fingerprints: graph.fingerprints.length,
		coverage: graph.coverage,
		scope: "file-local-semantics" as const,
		limitations: [
			"Static syntax and conservative relationship candidates, not observed execution or behavioral equivalence.",
			"Graph root identifies the admitted path/hash manifest, not original application or container bytes.",
			"This port projects file-local semantic graphs. Cross-module application linking, full REA application workflows and native analysis parity are not established.",
		],
	};
}
/** Runs only in the app-owned analysis worker. Never imports or executes target code. */
export async function analyzeSemanticSources(
	sources: readonly SourceArtifact[],
	signal?: AbortSignal,
) {
	const projection = createJavaScriptSemanticGraphProjection();
	const selected = sources
		.filter((s) => /\.(?:[cm]?[jt]s|[jt]sx)$/i.test(s.path))
		.sort((a, b) => compareUnicodeCodePoints(a.path, b.path));
	const root = digestCanonicalValue(
		selected.map((s) => ({ path: s.path, sha256: s.sha256 })),
	);
	for (const source of selected) {
		await setImmediate();
		if (signal?.aborted) throw new Error("Semantic analysis cancelled");
		if (
			createHash("sha256").update(source.source).digest("hex") !== source.sha256
		)
			throw new Error("Semantic source hash mismatch");
		const file = {
			path: source.path,
			container_sha256: root,
			sha256: source.sha256,
			bytes: source.bytes,
			inventory_artifact_id: `art_${source.sha256}`,
			kind: "javascript" as const,
			unpacked: false,
			text: { included: true as const, value: source.source },
		};
		const parsed = parseJavaScriptSource(source.source, source.path);
		if (parsed === null) {
			projection.recordUnavailableFile(
				file,
				"Source could not be parsed",
				null,
				"incomplete-module",
			);
			continue;
		}
		projection.projectFile(file, analyzeParsedJavaScriptSemantics(parsed));
	}
	return projection.finish(root, { graph_id: `jag_${root}`, nodes: [] });
}
