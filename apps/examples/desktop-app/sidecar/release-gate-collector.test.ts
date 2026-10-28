import { it as test } from "vitest";
import { strict as assert } from "node:assert";
import { collectReleaseGate } from "./release-gate-collector";
import { sha256 } from "./release-gate-verifier";
import { fixture, repeatedE2EEvidence } from "./__fixtures__/release-gate";
import { zip } from "./__fixtures__/incident";
const head = "a".repeat(40);
function network(
	options: {
		badDigest?: boolean;
		repeatedE2E?: boolean;
		unsafeZip?: boolean;
		missingCore?: boolean;
		movedHead?: boolean;
		movedBase?: boolean;
		changedAttempt?: boolean;
		redirect?: string;
		pending?: boolean;
		missingDigest?: boolean;
		overflow?: boolean;
		staleCoreAttempt?: boolean;
		retainedCoreAttempt?: boolean;
	} = {},
) {
	const e = options.repeatedE2E ? repeatedE2EEvidence() : fixture(),
		urls: string[] = [];
	let pulls = 0;
	let core = zip([
		{ name: "core/summary.json", bytes: Buffer.from(JSON.stringify(e.core)) },
		{
			name: "engines/summary.json",
			bytes: Buffer.from(JSON.stringify(e.engines)),
		},
		...(options.unsafeZip
			? [{ name: "../escape", bytes: Buffer.from("unsafe") }]
			: []),
	]);
	if (options.missingCore)
		core = zip([
			{
				name: "engines/summary.json",
				bytes: Buffer.from(JSON.stringify(e.engines)),
			},
		]);
	const installed = zip([
		{ name: "summary.json", bytes: Buffer.from(JSON.stringify(e.installed)) },
	]);
	const artifacts = [core, installed];
	artifacts.forEach((b, i) => {
		e.artifacts.artifacts[i].digest = `sha256:${sha256(b)}`;
		e.artifacts.artifacts[i].size_in_bytes = b.length;
	});
	if (options.badDigest) core[0] ^= 1;
	if (options.missingDigest) e.artifacts.artifacts[0].digest = "";
	if (options.staleCoreAttempt)
		e.artifacts.artifacts[0].name = `consolidated-validation-${e.run.id}-0`;
	if (options.retainedCoreAttempt) {
		e.artifacts.artifacts.push({
			...e.artifacts.artifacts[0],
			id: 9,
			name: `consolidated-validation-${e.run.id}-0`,
		});
		e.artifacts.total_count++;
	}
	const response = (data: unknown) => new Response(JSON.stringify(data));
	const fetcher = (async (url: any, init: any) => {
		const u = new URL(String(url));
		urls.push(u.href);
		assert.equal(init.credentials, "omit");
		assert.equal(init.redirect, "manual");
		assert.equal(init.headers.Authorization, undefined);
		assert.ok(init.signal);
		if (u.hostname === "nightly.link") {
			if (options.redirect)
				return new Response(null, {
					status: 302,
					headers: { location: options.redirect },
				});
			if (options.overflow)
				return new Response(Buffer.alloc(4 * 1024 * 1024 + 1));
			return new Response(u.pathname.includes("/1.zip") ? core : installed);
		}
		const path = u.pathname.replace(
			"/repos/zhielo/cline-desktop-enhanced/",
			"",
		);
		if (path === "pulls/133") {
			pulls++;
			return response(
				options.movedBase && pulls > 1
					? { ...e.pull, base: { ...e.pull.base, sha: "f".repeat(40) } }
					: options.movedHead && pulls > 1
						? { ...e.pull, head: { ...e.pull.head, sha: "e".repeat(40) } }
						: e.pull,
			);
		}
		if (path.endsWith("/check-runs")) return response(e.checks);
		if (path === "actions/runs")
			return response({
				total_count: 1 + (e.workflowRuns?.workflow_runs.length ?? 0),
				workflow_runs: [
					options.pending
						? { ...e.run, status: "in_progress", conclusion: null }
						: e.run,
					...(e.workflowRuns?.workflow_runs ?? []),
				],
			});
		if (path.endsWith("/jobs")) return response(e.jobs);
		if (path.endsWith("/artifacts")) return response(e.artifacts);
		if (path === "actions/runs/123456")
			return response(
				options.changedAttempt ? { ...e.run, run_attempt: 2 } : e.run,
			);
		if (path === `git/commits/${head}`) return response(e.headCommit);
		if (path === `git/commits/${"b".repeat(40)}`)
			return response(e.testedCommit);
		if (path.startsWith("contents/")) {
			const b = e.policyFileBytes[path.slice(9)];
			assert.ok(b);
			return response({
				type: "file",
				encoding: "base64",
				size: b.length,
				content: b.toString("base64"),
			});
		}
		throw Error("Unexpected endpoint " + u.hostname + path);
	}) as typeof fetch;
	return { fetcher, urls };
}

test("complete authenticated owned artifacts with finite read-only calls", async () => {
	const n = network();
	const r = await collectReleaseGate(133, head, { fetch: n.fetcher });
	assert.equal(r.status, "passed");
	assert.ok(r.requests <= 30);
	assert.ok(n.urls.every((u) => !u.includes("/3.zip")));
	assert.equal(r.evidenceSources.length, r.requests);
});
for (const [name, opts, pattern] of [
	["altered artifact bytes", { badDigest: true }, /SHA256/],
	["unsafe artifact entries", { unsafeZip: true }, /Unsafe/],
	["missing core receipt", { missingCore: true }, /exactly core/],
	["missing digest", { missingDigest: true }, /digest/],
	[
		"consolidated artifact from another attempt",
		{ staleCoreAttempt: true },
		/Missing or ambiguous evidence artifact/,
	],
	["head changed during collection", { movedHead: true }, /changed during/],
	[
		"run attempt changed during collection",
		{ changedAttempt: true },
		/changed during/,
	],
	[
		"unapproved redirect host",
		{ redirect: "https://127.0.0.1/private" },
		/transport host/,
	],
	[
		"HTTP redirect",
		{ redirect: "http://nightly.link/private" },
		/transport host/,
	],
	[
		"redirect loop",
		{ redirect: "https://nightly.link/loop" },
		/redirect budget/,
	],
	["pending Windows run", { pending: true }, /not successfully completed/],
	["oversized artifact", { overflow: true }, /byte budget/],
] as const)
	test(name + " blocks", async () => {
		const n = network(opts);
		await assert.rejects(
			() => collectReleaseGate(133, head, { fetch: n.fetcher }),
			pattern,
		);
	});
test("pre-cancel makes no request", async () => {
	const n = network();
	const controller = new AbortController();
	controller.abort();
	await assert.rejects(() =>
		collectReleaseGate(133, head, {
			fetch: n.fetcher,
			signal: controller.signal,
		}),
	);
	assert.equal(n.urls.length, 0);
});
test("arbitrary head/URL never reaches network", async () => {
	const n = network();
	await assert.rejects(() =>
		collectReleaseGate(133, "https://attacker.invalid/", { fetch: n.fetcher }),
	);
	assert.equal(n.urls.length, 0);
});

test("rejects a base advance during final collection with an unchanged head", async () => {
	await assert.rejects(
		() =>
			collectReleaseGate(133, head, {
				fetch: network({ movedBase: true }).fetcher,
			}),
		/base.*changed/,
	);
});

test("collector retains authoritative workflow provenance for every successful repeated E2E suite", async () => {
	const n = network({ repeatedE2E: true });
	const r = await collectReleaseGate(133, head, { fetch: n.fetcher });
	assert.equal(r.status, "passed");
});

test("collector selects the exact current attempt without downloading or deleting retained older evidence", async () => {
	const n = network({ retainedCoreAttempt: true });
	const r = await collectReleaseGate(133, head, { fetch: n.fetcher });
	assert.equal(r.status, "passed");
	assert.ok(!n.urls.some((u) => u.includes("/9.zip")));
	assert.ok(r.artifacts[0].name.endsWith(`-${r.runAttempt}`));
});
