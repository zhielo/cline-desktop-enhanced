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

it("maps Android JNI export names as candidate edges, never execution proofs", () => {
	const input = {
		...result,
		engine: "android-static",
		engineVersion: "android-static/v2",
		evidence: {
			artifacts: [
				{
					id: "dex",
					sha256: "a".repeat(64),
					format: "dex",
					dex: {
						methods: [
							{
								id: "method",
								defined: true,
								classDescriptor: "LFixture;",
								name: "native_work",
								descriptor: "()V",
							},
						],
						loaderReferences: [
							{
								id: "loader",
								classDescriptor: "Ljava/lang/System;",
								name: "loadLibrary",
							},
						],
					},
				},
				{
					id: "lib",
					sha256: "b".repeat(64),
					format: "elf",
					native: {
						functions: [
							{
								id: "symbol",
								name: "Java_Fixture_native_1work",
								addressHex: "0x4000c0",
							},
						],
					},
				},
			],
			relationships: [
				{
					kind: "jni-export-match-candidate",
					methodId: "method",
					nativeSymbolId: "symbol",
					verifiedBinding: false,
				},
			],
		},
	};
	const graph = buildEvidenceGraph({ schemaVersion: 1, results: [input] });
	expect(
		graph.edges.filter((e) => e.relation === "jni-export-name-candidate"),
	).toEqual([expect.objectContaining({ confidence: "candidate" })]);
	expect(graph.edges.some((e) => e.relation === "references-candidate")).toBe(
		true,
	);
	expect(
		graph.nodes.filter((n) => n.kind === "native-symbol")[0].artifactSha256,
	).toBe("b".repeat(64));
});

it("includes exact selections outside truncated inventory with original artifact provenance", () => {
	const graph = buildEvidenceGraph({
		schemaVersion: 1,
		results: [
			{
				...result,
				engine: "android-static",
				evidence: {
					artifacts: [
						{
							id: "lib",
							sha256: "b".repeat(64),
							format: "elf",
							native: { functions: [] },
						},
					],
					selectedFunctions: [
						{
							id: "selected",
							artifactId: "lib",
							name: "outside_listing",
							addressHex: "0x1000",
						},
					],
					relationships: [],
				},
			},
		],
	});
	expect(graph.nodes.find((n) => n.kind === "native-symbol")).toEqual(
		expect.objectContaining({
			artifactSha256: "b".repeat(64),
			label: expect.stringContaining("outside_listing"),
		}),
	);
});
