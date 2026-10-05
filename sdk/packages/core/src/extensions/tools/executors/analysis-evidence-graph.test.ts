import { describe, it, expect } from "vitest";
import {
	buildEvidenceGraph,
	queryEvidenceGraph,
	graphResult,
} from "./analysis-evidence-graph";
const result = {
	protocol: "cline-advanced-analysis/v1",
	status: "partial",
	engine: "androguard",
	engineVersion: "4.1.4",
	limitations: ["Not a complete call graph"],
	input: { sha256: "a".repeat(64), bytes: 240, format: "dex" },
	evidence: {
		classes: ["LFixture;"],
		methods: [{ id: "LFixture;->a()V" }, { id: "LFixture;->b()V" }],
		calls: [
			{ source: "LFixture;->a()V", operand: "v0, LFixture;->b()V" },
			{ source: "LFixture;->a()V", operand: "unknown reflective target" },
		],
	},
};
const manifest = { schemaVersion: 1, results: [result] };
describe("bounded evidence graph", () => {
	it("uses stable IDs and preserves partial coverage", () => {
		const a = buildEvidenceGraph(manifest),
			b = buildEvidenceGraph(manifest);
		expect(a.nodes.map((n) => n.id)).toEqual(b.nodes.map((n) => n.id));
		expect(a.coverage.join(" ")).toContain("partial");
		expect(a.sourceHashes[0]).toMatch(/^[a-f0-9]{64}$/);
	});
	it("keeps candidate calls distinct from verified facts", () => {
		const graph = buildEvidenceGraph(manifest);
		expect(
			graph.edges
				.filter((e) => e.relation === "invokes-candidate")
				.every((e) => e.confidence === "candidate"),
		).toBe(true);
		expect(
			graph.nodes.find((n) => n.kind === "unresolved-call")?.confidence,
		).toBe("unresolved");
	});
	it("filters kinds and literal text", () => {
		const answer = queryEvidenceGraph(buildEvidenceGraph(manifest), {
			kind: "dex-method",
			text: "b()V",
		});
		expect(answer.nodes).toHaveLength(1);
		expect(answer.integrity).toBe("content-identity-not-authentication");
	});
	it("does not evaluate regex or query code", () => {
		expect(
			queryEvidenceGraph(buildEvidenceGraph(manifest), { text: ".*" }).nodes,
		).toHaveLength(0);
	});
	it("traverses outgoing edges under a depth budget", () => {
		const graph = buildEvidenceGraph(manifest);
		const root = graph.nodes.find((n) => n.kind === "artifact");
		expect(root).toBeDefined();
		expect(
			queryEvidenceGraph(graph, { startId: root?.id, depth: 0 }).nodes,
		).toHaveLength(1);
		expect(
			queryEvidenceGraph(graph, { startId: root?.id, depth: 1 }).nodes.length,
		).toBeGreaterThan(1);
	});
	it("reports truncation", () => {
		expect(
			queryEvidenceGraph(buildEvidenceGraph(manifest), { limit: 1 }).truncated,
		).toBe(true);
	});
	it("rejects dangling graph edges", () => {
		const graph = buildEvidenceGraph(manifest);
		graph.edges.push({
			source: "missing",
			target: graph.nodes[0].id,
			relation: "contains",
			confidence: "reported",
		});
		expect(() => queryEvidenceGraph(graph)).toThrow("Dangling");
	});
	it("rejects unknown query fields and invalid manifests", () => {
		expect(() =>
			queryEvidenceGraph(buildEvidenceGraph(manifest), {
				script: "bad",
			} as never),
		).toThrow();
		expect(() => buildEvidenceGraph({ results: [] })).toThrow();
	});
	it("reports limited imported-evidence coverage", () => {
		expect(
			graphResult("graph_build", manifest).limitations.join(" "),
		).toContain("untrusted");
	});
});
