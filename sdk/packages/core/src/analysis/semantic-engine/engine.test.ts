import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import {
	analyzeSemanticSources,
	queryJavaScriptSemanticGraph,
	semanticSummary,
} from "./engine";

const source = (text: string, path = "app.js") => ({
	path,
	source: text,
	bytes: Buffer.byteLength(text),
	sha256: createHash("sha256").update(text).digest("hex"),
});
it("retains interprocedural and closure relationships without executing targets", async () => {
	const graph = await analyzeSemanticSources([
		source(
			`const outer=2; function add(value){return value+outer;} const answer=add(40); throw new Error('MUST_NOT_EXECUTE');`,
		),
	]);
	const relations = new Set(graph.relations.map((r) => r.relation));
	for (const kind of [
		"argument-to-parameter",
		"returns-to-call",
		"captures",
		"calls",
	])
		expect(relations.has(kind as never)).toBe(true);
	const parameter = graph.nodes.find(
		(n) => n.kind === "parameter" && n.label === "value",
	);
	expect(parameter).toBeDefined();
	const trace = queryJavaScriptSemanticGraph(graph, {
		seed: { kind: "semantic-node", node_id: parameter!.node_id },
		direction: "backward-provenance",
	});
	expect(trace.summary.traversed_relations).toBeGreaterThan(0);
	expect(semanticSummary(graph).scope).toBe("file-local-semantics");
});
it("is deterministic and rejects source hashes that do not match inspected bytes", async () => {
	const input = [source("const a = 1; const b = a;")];
	expect(semanticSummary(await analyzeSemanticSources(input))).toEqual(
		semanticSummary(await analyzeSemanticSources(input)),
	);
	await expect(
		analyzeSemanticSources([{ ...input[0]!, sha256: "0".repeat(64) }]),
	).rejects.toThrow("hash mismatch");
});
it("uses filename-specific JavaScript grammar, preserves parse failure and ignores non-source files", async () => {
	const graph = await analyzeSemanticSources([
		source("function broken( {", "bad.js"),
		source("this is not JS", "image.png"),
	]);
	expect(graph.coverage.status).not.toBe("complete");
	expect(graph.unknowns.length).toBeGreaterThan(0);
});
it("honours pre-cancellation", async () => {
	const abort = new AbortController();
	abort.abort();
	await expect(
		analyzeSemanticSources([source("const x=1")], abort.signal),
	).rejects.toThrow("cancelled");
});
