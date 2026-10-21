import { randomUUID } from "node:crypto";
import {
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeAll, beforeEach, expect, it } from "vitest";
import {
	ANALYSIS_PROFILE,
	AnalysisInputSchema,
	type AnalysisReceipt,
	digest,
} from "./contracts";
import { EvidenceQuerySchema } from "./evidence-query";
import { queryFirstPartyEvidence } from "./index";
import { analyzeSources } from "./parser";
import {
	analyzeApplicationSources,
	applicationSummary,
} from "./semantic-engine/application";
import { ownedApplication } from "./semantic-engine/application.fixture";
import { semanticSummary } from "./semantic-engine/engine";
import { FirstPartyAnalysisStore } from "./store";
import { analyzeTarget, readSources } from "./worker";

let a: Awaited<ReturnType<typeof analyzeApplicationSources>>,
	b: typeof a,
	root: string;
beforeAll(async () => {
	a = await analyzeApplicationSources(ownedApplication());
	b = await analyzeApplicationSources(ownedApplication(2));
});
beforeEach(() => {
	root = mkdtempSync(join(tmpdir(), "cline-application-test-"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));
function receipt(graphs: typeof a, version = 1): AnalysisReceipt {
	const result = {
		...analyzeSources(ownedApplication(version)),
		semanticGraph: semanticSummary(graphs.semantic, true),
		applicationGraph: applicationSummary(
			graphs.application,
			graphs.semantic,
			graphs.manifest,
		),
	};
	return {
		id: randomUUID(),
		sessionId: "owner",
		workspace: root,
		profile: ANALYSIS_PROFILE,
		input: { target: ".", semanticGraph: true, applicationGraph: true },
		requestHash: digest("owned"),
		createdAt: new Date().toISOString(),
		status: "running",
		result,
		resultHash: digest(result),
	};
}
function save(db: FirstPartyAnalysisStore, graphs: typeof a, version = 1) {
	const r = receipt(graphs, version);
	db.start(r);
	r.status = "partial";
	db.save(r, graphs.semantic, graphs.application);
	return r;
}
it("stores paired graphs atomically and permits scoped paginated reads in Off", () => {
	const db = new FirstPartyAnalysisStore(join(root, "evidence.sqlite"));
	try {
		db.setMode("owner", root, "static");
		const r = save(db, a);
		db.setMode("owner", root, "off");
		const page = queryFirstPartyEvidence(
			"owner",
			{ receiptId: r.id, view: "application-nodes", limit: 2 },
			db,
		) as { items: unknown[]; nextOffset: number; total: number };
		expect(page.items).toHaveLength(2);
		expect(page.nextOffset).toBe(2);
		expect(page.total).toBe(a.application.nodes.length);
		expect(db.applicationGraph("owner", r.id)).toEqual(a.application);
		expect(() => db.applicationGraph("foreign", r.id)).toThrow(/not found/);
		expect(() => db.save(r, a.semantic, a.application)).toThrow();
	} finally {
		db.close();
	}
});
it("runs original feature/version/export/source-to-bundle algorithms on saved graphs without provider calls", () => {
	const db = new FirstPartyAnalysisStore(join(root, "evidence.sqlite"));
	try {
		db.setMode("owner", root, "static");
		const left = save(db, a),
			right = save(db, b, 2),
			identical = save(db, a);
		db.setMode("owner", root, "off");
		const run = (q: Record<string, unknown>) =>
			queryFirstPartyEvidence(
				"owner",
				{ receiptId: left.id, limit: 2, ...q },
				db,
			) as {
				providerCalls: number;
				verifiedBehavior: boolean;
				items: unknown[];
				summary: Record<string, number>;
				coverage: Record<string, unknown>;
			};
		const trace = run({
			view: "application-trace",
			applicationTrace: {
				seed: { kind: "channel", value: "owned:add" },
				direction: "both",
			},
		});
		expect(trace.providerCalls).toBe(0);
		expect(trace.verifiedBehavior).toBe(false);
		expect(trace.summary.matched_seeds).toBeGreaterThan(0);
		expect(trace.items.length).toBeLessThanOrEqual(2);
		const unchanged = run({
			view: "application-comparison",
			compareReceiptId: identical.id,
		});
		expect(unchanged.summary.changed).toBe(0);
		// Partial admitted-source coverage must not assert globally unchanged behavior.
		expect(unchanged.summary.unknown).toBeGreaterThan(0);
		const changed = run({
			view: "application-comparison",
			compareReceiptId: right.id,
		});
		expect(changed.summary.changed).toBeGreaterThan(0);
		const exports = run({
			view: "application-exports",
			compareReceiptId: right.id,
			exportSelectors: {
				left: { modulePath: "api.cjs", exportName: "add" },
				right: { modulePath: "api.cjs", exportName: "add" },
			},
		});
		expect(exports.providerCalls).toBe(0);
		expect(exports.items.length).toBeGreaterThan(0);
		const bundle = run({
			view: "application-source-bundle",
			compareReceiptId: left.id,
		});
		expect(bundle.providerCalls).toBe(0);
		expect(bundle.items.length).toBeGreaterThan(0);
		expect(JSON.stringify(bundle.coverage)).toMatch(/partial/);
		expect(() =>
			run({ view: "application-comparison", compareReceiptId: randomUUID() }),
		).toThrow(/not found/);
	} finally {
		db.close();
	}
});
it("rejects unbound graphs and modified source manifests with transaction rollback", () => {
	const db = new FirstPartyAnalysisStore(join(root, "evidence.sqlite"));
	try {
		db.setMode("owner", root, "static");
		const r = receipt(a);
		db.start(r);
		r.status = "partial";
		expect(() => db.save(r, a.semantic, b.application)).toThrow(/binding/);
		expect(db.get("owner", r.id).status).toBe("running");
		r.result!.applicationGraph!.sources[0]!.bytes++;
		r.resultHash = digest(r.result);
		expect(() => db.save(r, a.semantic, a.application)).toThrow(/binding/);
		r.result!.applicationGraph!.sources[0]!.bytes--;
		r.resultHash = digest(r.result);
		db.save(r, a.semantic, a.application);
		expect(db.applicationGraph("owner", r.id)).toEqual(a.application);
	} finally {
		db.close();
	}
});
it("requires explicit graph opt-in and exact workflow inputs", () => {
	expect(
		AnalysisInputSchema.safeParse({ target: ".", applicationGraph: true })
			.success,
	).toBe(false);
	const id = randomUUID();
	for (const q of [
		{ view: "application-trace" },
		{ view: "application-comparison" },
		{ view: "application-exports", compareReceiptId: id },
		{ view: "application-summary", compareReceiptId: id },
		{
			view: "semantic-nodes",
			applicationTrace: { seed: { kind: "module", value: "x" } },
		},
	])
		expect(EvidenceQuerySchema.safeParse({ receiptId: id, ...q }).success).toBe(
			false,
		);
});
it("transfers paired graphs privately and keeps legacy inventory behavior unchanged", async () => {
	const target = join(root, "owned");
	mkdirSync(target);
	for (const s of ownedApplication())
		writeFileSync(join(target, s.path), s.source);
	const legacy = await readSources(root, "owned");
	expect(legacy.sources.some((s) => s.path.endsWith(".html"))).toBe(false);
	const output = join(root, "graph-transfer.json");
	const r = await analyzeTarget(
		root,
		{ target: "owned", semanticGraph: true, applicationGraph: true },
		output,
	);
	expect(r.status).toBe("partial");
	expect(r.applicationGraph?.sources.map((s) => s.path)).toContain(
		"index.html",
	);
	expect(r.applicationGraph?.sources.map((s) => s.path)).not.toContain(
		"owned/index.html",
	);
	const pair = JSON.parse(readFileSync(output, "utf8"));
	expect(pair.application.graph_id).toBe(r.applicationGraph?.graphId);
	expect(pair.semantic.application_graph_id).toBe(pair.application.graph_id);
	await expect(
		analyzeTarget(
			root,
			{ target: "owned", semanticGraph: true, applicationGraph: true },
			output,
		),
	).rejects.toThrow();
});
