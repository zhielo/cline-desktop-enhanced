import { expect, it } from "vitest";
import { traceSourceSink } from "./source-sink-trace";
import { ANALYSIS_PROFILE } from "../../../analysis/contracts";
const id = (c: string) => `ev_${c.repeat(64)}`;
function report() {
	return {
		profile: ANALYSIS_PROFILE,
		parserVersion: "owned",
		status: "completed",
		artifacts: [],
		facts: ["a", "b", "c", "d"].map((c) => ({
			id: id(c),
			kind: "function",
			value: c,
			confidence: "derived",
			authority: "shipped-artifact",
			location: {
				path: "owned.ts",
				sha256: "a".repeat(64),
				line: 1,
				column: 1,
			},
			limitations: [],
		})),
		edges: [
			["a", "b", "data-flow"],
			["b", "c", "data-flow"],
			["a", "d", "calls"],
			["c", "a", "data-flow"],
		].map(([a, b, kind]) => ({
			source: id(a),
			target: id(b),
			kind,
			confidence: "derived",
			limitations: [],
		})),
		limitations: ["owned declared edges only"],
		counters: { entries: 1, bytes: 1, nodes: 4 },
	};
}
const query = { source_ids: [id("a"), id("b")], sink_ids: [id("c"), id("d")] };
it("returns multi-source witnesses retaining provenance without promoting to taint proof", () => {
	const r = traceSourceSink(report(), query);
	expect(r.witnesses.map((w) => w.route)).toEqual([
		[id("a"), id("b"), id("c")],
		[id("b"), id("c")],
	]);
	expect(r.nodes[0].provenance).toMatchObject({ confidence: "derived" });
	expect(
		r.pairs.filter((p) => p.result === "declared-path-found"),
	).toHaveLength(2);
	expect(r.observedExecution).toBe(false);
	expect(r.authority).toBe("untrusted-imported-report");
});
it("requires explicit relationship mode to follow non-data-flow edges", () => {
	const r = traceSourceSink(report(), {
		...query,
		relation: "declared-relationships",
	});
	expect(r.witnesses.some((w) => w.sinkId === id("d"))).toBe(true);
});
it("treats stop IDs as boundaries, not verified sanitizers", () => {
	const r = traceSourceSink(report(), { ...query, stop_ids: [id("b")] });
	expect(r.witnesses).toEqual([]);
	expect(r.stoppedAt).toEqual([id("b")]);
	expect(r.limitations.join(" ")).toContain("NOT validated sanitizers");
});
it.each([
	{ max_depth: 1 },
	{ max_states: 1 },
	{ max_edge_visits: 1 },
])("enforces traversal budget %j", (bounds) => {
	const r = traceSourceSink(report(), { ...query, ...bounds });
	expect(r.status).toBe("partial");
	expect(r.truncated).toBe(true);
	expect(r.counters.states).toBeLessThanOrEqual(bounds.max_states ?? 1000);
	expect(r.counters.edgeVisits).toBeLessThanOrEqual(
		bounds.max_edge_visits ?? 4000,
	);
});
it("accepts a zero-edge source/sink witness and terminates on cycles", () => {
	const r = traceSourceSink(report(), {
		source_ids: [id("a")],
		sink_ids: [id("a"), id("c")],
	});
	expect(r.witnesses[0].route).toEqual([id("a")]);
	expect(r.counters.states).toBe(3);
});
it("rejects unknown, duplicate, dangling and excessive input", () => {
	expect(() =>
		traceSourceSink(report(), { ...query, source_ids: [id("e")] }),
	).toThrow("Unknown");
	expect(() =>
		traceSourceSink(report(), { ...query, source_ids: [id("a"), id("a")] }),
	).toThrow("Duplicate");
	const r = report();
	r.edges[0].target = id("e");
	expect(() => traceSourceSink(r, query)).toThrow("Dangling");
	expect(() =>
		traceSourceSink(report(), {
			...query,
			source_ids: Array(17).fill(id("a")),
		}),
	).toThrow();
});
it("reports partial instead of silently exceeding the witness budget", () => {
	const r = report();
	r.facts = Array.from({ length: 16 }, (_, i) => ({
		...r.facts[0],
		id: `ev_${i.toString(16).padStart(64, "0")}`,
	}));
	r.edges = r.facts.flatMap((source) =>
		r.facts
			.filter((f) => f.id !== source.id)
			.map((f) => ({
				source: source.id,
				target: f.id,
				kind: "data-flow",
				confidence: "derived",
				limitations: [],
			})),
	);
	const q = {
		source_ids: r.facts.map((f) => f.id),
		sink_ids: r.facts.map((f) => f.id),
		relation: "data-flow",
	};
	// Dense cyclic graph exceeds the bounded witness/output budget without fabricating paths.
	const result = traceSourceSink(r, q);
	expect(result.witnesses.length).toBeLessThanOrEqual(64);
	expect(result.status).toBe("partial");
	expect(Buffer.byteLength(JSON.stringify(result))).toBeLessThan(98304);
});
