import { randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import {
	ANALYSIS_PROFILE,
	type AnalysisReceipt,
	byteDigest,
	digest,
} from "./contracts";
import { EvidenceQuerySchema, semanticEvidencePage } from "./evidence-query";
import { queryFirstPartyEvidence } from "./index";
import { analyzeSources } from "./parser";
import {
	analyzeSemanticSources,
	semanticSummary,
} from "./semantic-engine/engine";
import { FirstPartyAnalysisStore } from "./store";
import { analyzeTarget } from "./worker";

let root: string;
beforeEach(() => {
	root = mkdtempSync(join(tmpdir(), "cline-semantic-test-"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));
const source = (text: string) => ({
	path: "app.js",
	source: text,
	bytes: Buffer.byteLength(text),
	sha256: byteDigest(Buffer.from(text)),
});
it("stores graph and receipt atomically, queries scoped pages and retains legacy evidence", async () => {
	const db = new FirstPartyAnalysisStore(join(root, "evidence.sqlite"));
	try {
		db.setMode("owner", root, "static");
		const input = [
			source("function add(value){return value+1}; const result=add(4);"),
		];
		const graph = await analyzeSemanticSources(input);
		const receipt: AnalysisReceipt = {
			id: randomUUID(),
			sessionId: "owner",
			workspace: root,
			profile: ANALYSIS_PROFILE,
			input: { target: "app.js", semanticGraph: true },
			requestHash: digest("request"),
			createdAt: new Date().toISOString(),
			status: "running",
		};
		db.start(receipt);
		receipt.status = "completed";
		receipt.result = {
			...analyzeSources(input),
			semanticGraph: semanticSummary(graph),
		};
		receipt.resultHash = digest(receipt.result);
		expect(() => db.save(receipt, { ...graph, graph_id: "tampered" })).toThrow(
			"integrity",
		);
		expect(db.get("owner", receipt.id).status).toBe("running");
		db.save(receipt, graph);
		const page = queryFirstPartyEvidence(
			"owner",
			{ receiptId: receipt.id, view: "semantic-nodes", limit: 2 },
			db,
		) as { items: unknown[]; total: number; nextOffset: number };
		expect(page.items).toHaveLength(2);
		expect(page.total).toBe(graph.nodes.length);
		expect(page.nextOffset).toBe(2);
		expect(db.semanticGraph("owner", receipt.id)).toEqual(graph);
		expect(() => db.semanticGraph("foreign", receipt.id)).toThrow("not found");
		expect(() => db.save(receipt, graph)).toThrow();
		db.setMode("owner", root, "off");
		expect(db.semanticGraph("owner", receipt.id)).toEqual(graph);
		expect(
			queryFirstPartyEvidence(
				"owner",
				{ receiptId: receipt.id, view: "verification" },
				db,
			),
		).toHaveProperty("verifiedBehavior", false);
	} finally {
		db.close();
	}
});
it("uses private transfer output, never overwrites it and rejects unsupported comparisons", async () => {
	writeFileSync(
		join(root, "app.js"),
		"const input=40; function add(v){return v+2}; add(input);",
	);
	const output = join(root, "graph.json");
	const result = await analyzeTarget(
		root,
		{ target: "app.js", semanticGraph: true },
		output,
	);
	expect(result.semanticGraph?.nodes).toBeGreaterThan(0);
	expect(JSON.parse(readFileSync(output, "utf8")).graph_id).toBe(
		result.semanticGraph?.graphId,
	);
	await expect(
		analyzeTarget(root, { target: "app.js", semanticGraph: true }, output),
	).rejects.toThrow();
	await expect(
		analyzeTarget(root, { target: "app.js", semanticGraph: true }),
	).rejects.toThrow("Owned");
	await expect(
		analyzeTarget(
			root,
			{ target: "app.js", semanticGraph: true, compareTarget: "app.js" },
			join(root, "other.json"),
		),
	).rejects.toThrow("comparison");
});
it("bounds query output and advances past oversized records", () => {
	const q = EvidenceQuerySchema.parse({
		receiptId: randomUUID(),
		view: "semantic-nodes",
		limit: 2,
	});
	const page = semanticEvidencePage(
		{
			nodes: [
				{ label: "x".repeat(100_000) },
				{ label: "small" },
				{ label: "next" },
			],
		},
		q,
	);
	expect(page.items[0]).toHaveProperty("displayOmitted", true);
	expect(page.nextOffset).toBe(2);
	expect(Buffer.byteLength(JSON.stringify(page))).toBeLessThan(196608);
	expect(() =>
		EvidenceQuerySchema.parse({
			receiptId: randomUUID(),
			view: "semantic-nodes",
			offset: 1_000_001,
		}),
	).toThrow();
});
