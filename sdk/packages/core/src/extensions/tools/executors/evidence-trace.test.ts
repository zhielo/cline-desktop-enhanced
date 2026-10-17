import { it, expect } from "vitest";
import { traceEvidence } from "./evidence-trace";
import { ANALYSIS_PROFILE } from "../../../analysis/contracts";
const h = "a".repeat(64);
const node = (id: string) => ({
	id,
	kind: "native-symbol",
	label: id,
	artifactSha256: h,
	confidence: "candidate",
	evidenceIndex: 0,
});
const graph = () => ({
	schemaVersion: 1,
	nodes: [node("a"), node("b"), node("c")],
	edges: [
		{
			source: "a",
			target: "b",
			relation: "references-candidate",
			confidence: "candidate",
		},
		{
			source: "b",
			target: "c",
			relation: "jni-export-name-candidate",
			confidence: "candidate",
		},
	],
	sourceHashes: [h],
	coverage: ["declared candidates only"],
});
it("traces declared candidates without promoting to observed execution", () => {
	const r = traceEvidence(graph(), { start_id: "a", end_id: "c" }, false);
	expect(r.route).toEqual(["a", "b", "c"]);
	expect(r.observedExecution).toBe(false);
	expect(r.authority).toBe("untrusted-imported-report");
	expect(r.edges[1].provenance).toMatchObject({ confidence: "candidate" });
});
it("does not treat a relationship path as data flow", () => {
	const r = traceEvidence(graph(), { start_id: "a", end_id: "c" }, true);
	expect(r.route).toEqual([]);
	expect(r.nodes).toHaveLength(1);
	expect(r.endpointReachableInSelectedGraph).toBe(false);
});
it("traverses only declared first-party data-flow edges", () => {
	const fact = (id: string) => ({
		id: `ev_${id.repeat(64)}`,
		kind: "function",
		value: id,
		confidence: "derived",
		authority: "shipped-artifact",
		location: { path: "owned.ts", sha256: h, line: 1, column: 1 },
		limitations: [],
	});
	const a = fact("a"),
		b = fact("b"),
		c = fact("c");
	const r = traceEvidence(
		{
			profile: ANALYSIS_PROFILE,
			parserVersion: "owned",
			status: "completed",
			artifacts: [],
			facts: [a, b, c],
			edges: [
				{
					source: a.id,
					target: b.id,
					kind: "data-flow",
					confidence: "derived",
					limitations: [],
				},
				{
					source: b.id,
					target: c.id,
					kind: "calls",
					confidence: "derived",
					limitations: [],
				},
			],
			limitations: [],
			counters: { entries: 1, bytes: 1, nodes: 3 },
		},
		{ start_id: a.id, end_id: c.id },
		true,
	);
	expect(r.nodes).toHaveLength(2);
	expect(r.edges).toHaveLength(1);
	expect(r.endpointReachableInSelectedGraph).toBe(false);
});
it("bounds depth, node and edge coverage and reports partial", () => {
	for (const options of [
		{ max_depth: 1 },
		{ max_nodes: 1 },
		{ max_edges: 1 },
	]) {
		const r = traceEvidence(graph(), { start_id: "a", ...options }, false);
		expect(r.truncated).toBe(true);
		expect(r.status).toBe("partial");
	}
});
it("handles cycles without inventing routes or looping", () => {
	const g = graph();
	g.edges.push({
		source: "c",
		target: "a",
		relation: "references-candidate",
		confidence: "candidate",
	});
	const r = traceEvidence(g, { start_id: "a", end_id: "c" }, false);
	expect(r.nodes).toHaveLength(3);
	expect(r.route).toHaveLength(3);
});
it("rejects duplicate nodes, dangling edges and unknown endpoints", () => {
	const g = graph();
	g.nodes.push(node("a"));
	expect(() => traceEvidence(g, { start_id: "a" }, false)).toThrow("Duplicate");
	const d = graph();
	d.edges[0].target = "missing";
	expect(() => traceEvidence(d, { start_id: "a" }, false)).toThrow("Dangling");
	expect(() => traceEvidence(graph(), { start_id: "missing" }, false)).toThrow(
		"Unknown",
	);
});

it("rejects oversized seed coverage instead of returning an unbounded trace", () => {
	const g = graph();
	g.coverage = Array.from({ length: 100 }, () => "x".repeat(1000));
	expect(() => traceEvidence(g, { start_id: "a" }, false)).toThrow(
		"output byte budget",
	);
});
