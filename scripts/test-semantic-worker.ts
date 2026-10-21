import { strict as assert } from "node:assert";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { queryFirstPartyEvidence } from "../sdk/packages/core/src/analysis/index";
import { runFirstPartyAnalysis } from "../sdk/packages/core/src/analysis/service";
import { FirstPartyAnalysisStore } from "../sdk/packages/core/src/analysis/store";

const root = await realpath(
	await mkdtemp(join(tmpdir(), "cline-semantic-smoke-")),
);
const store = new FirstPartyAnalysisStore(join(root, "evidence.sqlite"));
try {
	await writeFile(
		join(root, "main.js"),
		"const outer=2; function add(value){return value+outer}; const answer=add(40); throw new Error('MUST_NOT_EXECUTE');",
	);
	store.setMode("owned-semantic-smoke", root, "static");
	const host = JSON.stringify({
		executable: process.execPath,
		args: [resolve(import.meta.dirname, "semantic-worker-entry.ts")],
	});
	const receipt = await runFirstPartyAnalysis(
		"owned-semantic-smoke",
		{ target: "main.js", semanticGraph: true },
		undefined,
		store,
		host,
	);
	assert.ok(["completed", "partial"].includes(receipt.status), receipt.error);
	assert.ok(receipt.result?.semanticGraph?.nodes);
	const page = queryFirstPartyEvidence(
		"owned-semantic-smoke",
		{ receiptId: receipt.id, view: "semantic-nodes", limit: 2 },
		store,
	) as { items: unknown[] };
	assert.equal(page.items.length, 2);
	const graph = store.semanticGraph("owned-semantic-smoke", receipt.id)!;
	const parameter = (
		graph.nodes as Array<{ node_id: string; kind: string; label: string }>
	).find((n) => n.kind === "parameter" && n.label === "value");
	assert.ok(parameter);
	const trace = queryFirstPartyEvidence(
		"owned-semantic-smoke",
		{
			receiptId: receipt.id,
			view: "semantic-trace",
			trace: {
				seed: { kind: "semantic-node", node_id: parameter.node_id },
				direction: "backward-provenance",
			},
			limit: 2,
		},
		store,
	) as { summary: { traversed_relations: number }; items: unknown[] };
	assert.ok(trace.summary.traversed_relations > 0);
	assert.ok(trace.items.length <= 2);
	console.log(
		JSON.stringify({
			status: "passed",
			profile: receipt.result.semanticGraph.profile,
			nodes: receipt.result.semanticGraph.nodes,
			scope:
				"owned-worker-and-scoped-persistence; not installed-Windows acceptance",
		}),
	);
} finally {
	store.close();
	await rm(root, { recursive: true, force: true });
}
