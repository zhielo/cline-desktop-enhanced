import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import {
	idaDatabaseKey,
	prepareIdaAttempt,
	publishIdaDatabase,
} from "./ida-analysis-workspace";
const roots: string[] = [];
afterEach(async () => {
	await Promise.all(
		roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
	);
});
async function fixture() {
	const root = await mkdtemp(join(tmpdir(), "ida-workspace-"));
	roots.push(root);
	return root;
}
it("reuses database compatibility independently of selected-function output and preserves accepted snapshots", async () => {
	const root = await fixture(),
		key = idaDatabaseKey("target", "engine", "config");
	const first = await prepareIdaAttempt(root, key, true);
	expect(first.reusedAnalysis).toBe(false);
	await writeFile(
		join(first.outputDir, "analysis.i64"),
		"owned saved database",
	);
	await publishIdaDatabase(root, first.outputDir, key);
	const second = await prepareIdaAttempt(root, key, true);
	expect(second.reusedAnalysis).toBe(true);
	expect(second.outputDir).not.toBe(first.outputDir);
	await writeFile(
		join(second.outputDir, "analysis.i64"),
		"different function run, failed",
	);
	expect(await readFile(join(first.outputDir, "analysis.i64"), "utf8")).toBe(
		"owned saved database",
	);
	const retry = await prepareIdaAttempt(root, key, true);
	expect(await readFile(join(retry.outputDir, "analysis.i64"), "utf8")).toBe(
		"owned saved database",
	);
});
it("fresh and stale-key runs never overwrite pre-existing or partial databases", async () => {
	const root = await fixture(),
		key = idaDatabaseKey("target", "engine", "config");
	await writeFile(join(root, "analysis.id0"), "partial");
	await writeFile(join(root, "analysis.i64"), "old");
	const first = await prepareIdaAttempt(root, key, false);
	await writeFile(join(first.outputDir, "analysis.i64"), "accepted");
	await publishIdaDatabase(root, first.outputDir, key);
	const fresh = await prepareIdaAttempt(root, key, false),
		changed = await prepareIdaAttempt(
			root,
			idaDatabaseKey("target", "replacement-engine", "config"),
			true,
		);
	expect(fresh.reusedAnalysis).toBe(false);
	expect(changed.reusedAnalysis).toBe(false);
	expect(await readFile(join(root, "analysis.id0"), "utf8")).toBe("partial");
	expect(await readFile(join(root, "analysis.i64"), "utf8")).toBe("old");
});
it("corrupt pointers, changed database bytes and empty publication fail safely", async () => {
	const root = await fixture(),
		key = idaDatabaseKey("target", "engine", "config");
	const first = await prepareIdaAttempt(root, key, true);
	await writeFile(join(first.outputDir, "analysis.i64"), "accepted");
	await publishIdaDatabase(root, first.outputDir, key);
	await writeFile(join(first.outputDir, "analysis.i64"), "tampered");
	expect((await prepareIdaAttempt(root, key, true)).reusedAnalysis).toBe(false);
	await writeFile(
		join(root, "cline-ida-database.json"),
		JSON.stringify({
			schema: "ida-database/v1",
			key,
			attempt: "../outside",
			sha256: "a".repeat(64),
		}),
	);
	const clean = await prepareIdaAttempt(root, key, true);
	expect(clean.reusedAnalysis).toBe(false);
	await writeFile(join(clean.outputDir, "analysis.i64"), "");
	await expect(publishIdaDatabase(root, clean.outputDir, key)).rejects.toThrow(
		"bounded",
	);
});
