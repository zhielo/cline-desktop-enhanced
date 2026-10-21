import { strict as assert } from "node:assert";
import {
	access,
	mkdir,
	mkdtemp,
	realpath,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { queryFirstPartyEvidence } from "../sdk/packages/core/src/analysis/index";
import { runFirstPartyAnalysis } from "../sdk/packages/core/src/analysis/service";
import { FirstPartyAnalysisStore } from "../sdk/packages/core/src/analysis/store";

import { ownedApplication } from "../sdk/packages/core/src/analysis/semantic-engine/application.fixture";
import { ownedFusePe } from "../sdk/packages/core/src/analysis/electron-fuses.fixture";

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
	await mkdir(join(root, "application"));
	for (const file of ownedApplication())
		await writeFile(join(root, "application", file.path), file.source);
	const sentinel = join(root, "MUST_NOT_EXECUTE");
	await writeFile(
		join(root, "application", "never.cjs"),
		`require('node:fs').writeFileSync(${JSON.stringify(sentinel)},'BAD');throw new Error('MUST_NOT_EXECUTE');`,
	);
	const applicationReceipt = await runFirstPartyAnalysis(
		"owned-semantic-smoke",
		{ target: "application", semanticGraph: true, applicationGraph: true },
		undefined,
		store,
		host,
	);
	assert.equal(applicationReceipt.status, "partial", applicationReceipt.error);
	assert.equal(
		applicationReceipt.result?.applicationGraph?.profile,
		"cline-application/1",
	);
	assert.equal(
		applicationReceipt.result?.semanticGraph?.profile,
		"cline-semantic/2",
	);
	store.setMode("owned-semantic-smoke", root, "off");
	const applicationTrace = queryFirstPartyEvidence(
		"owned-semantic-smoke",
		{
			receiptId: applicationReceipt.id,
			view: "application-trace",
			applicationTrace: {
				seed: { kind: "channel", value: "owned:add" },
				direction: "both",
			},
			limit: 2,
		},
		store,
	) as {
		providerCalls: number;
		summary: { matched_seeds: number };
		items: unknown[];
	};
	assert.equal(applicationTrace.providerCalls, 0);
	const acquired = queryFirstPartyEvidence(
		"owned-semantic-smoke",
		{
			receiptId: applicationReceipt.id,
			view: "source-acquisition",
			limit: 50,
		},
		store,
	) as {
		selectedPath: string;
		providerCalls: number;
		targetExecuted: boolean;
		items: unknown[];
	};
	assert.equal(acquired.selectedPath, "application");
	assert.equal(acquired.providerCalls, 0);
	assert.equal(acquired.targetExecuted, false);
	assert.ok(acquired.items.length > 1);
	assert.ok(applicationTrace.summary.matched_seeds > 0);
	assert.ok(applicationTrace.items.length <= 2);
	assert.equal(
		await access(sentinel).then(
			() => true,
			() => false,
		),
		false,
	);
	store.setMode("owned-semantic-smoke", root, "static");
	await writeFile(join(root, "owned-fuses.exe"), ownedFusePe());
	const fuseReceipt = await runFirstPartyAnalysis(
		"owned-semantic-smoke",
		{ target: "owned-fuses.exe", electronFuses: true },
		undefined,
		store,
		host,
	);
	assert.equal(fuseReceipt.status, "partial", fuseReceipt.error);
	assert.equal(
		fuseReceipt.result?.electronFuses?.slices[0].sentinels[0].fuses[0].name,
		"RunAsNode",
	);
	store.setMode("owned-semantic-smoke", root, "off");
	const fusePage = queryFirstPartyEvidence(
		"owned-semantic-smoke",
		{
			receiptId: fuseReceipt.id,
			view: "electron-fuses",
			fuseSection: "runtime_implications",
			limit: 2,
		},
		store,
	) as { items: unknown[]; targetExecuted: boolean };
	assert.equal(fusePage.items.length, 2);
	assert.equal(fusePage.targetExecuted, false);
	console.log(
		JSON.stringify({
			status: "passed",
			profile: receipt.result.semanticGraph.profile,
			applicationProfile: applicationReceipt.result?.applicationGraph?.profile,
			nodes: receipt.result.semanticGraph.nodes,
			scope:
				"owned-worker-and-scoped-persistence; not installed-Windows acceptance",
		}),
	);
} finally {
	store.close();
	await rm(root, { recursive: true, force: true });
}
