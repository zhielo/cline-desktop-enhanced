import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { AdvancedResult } from "./advanced-analysis";
import {
	persistInvestigation,
	queryInvestigation,
} from "./android-investigation-index";

const dirs: string[] = [];
async function temp() {
	const p = await mkdtemp(join(tmpdir(), "android-index-"));
	dirs.push(p);
	return p;
}
afterEach(async () => {
	await Promise.all(
		dirs.splice(0).map((p) => rm(p, { recursive: true, force: true })),
	);
});
function result(): AdvancedResult {
	return {
		protocol: "cline-advanced-analysis/v1",
		status: "partial",
		engine: "android-static",
		engineVersion: "android-static/v1",
		input: { sha256: "a".repeat(64), bytes: 20, format: "dex" },
		limitations: ["Static candidates only"],
		evidence: {
			coverage: { truncated: true },
			artifacts: [
				{
					id: "a".repeat(32),
					sha256: "a".repeat(64),
					validation: "integrity-and-bounded-structure",
					dex: {
						methods: [{ id: "b".repeat(32), name: "native_method" }],
						loaderReferences: [{ id: "c".repeat(32), name: "loadLibrary" }],
					},
				},
			],
			relationships: [
				{
					id: "d".repeat(32),
					verifiedBinding: false,
					shortName: "Java_Foo_native_1method",
				},
			],
		},
	};
}
describe("Android investigation evidence index", () => {
	it("persists immutable content-addressed evidence and reuses identical runs", async () => {
		const dir = await temp();
		const a = await persistInvestigation(dir, result());
		const b = await persistInvestigation(dir, result());
		expect(a?.id).toBe(b?.id);
		expect(b?.reused).toBe(true);
		const query = await queryInvestigation(a!.file, {
			kind: "jni-name-candidate",
		});
		expect(query.status).toBe("partial");
		expect(query.evidence.coverage).toEqual({ truncated: true });
		expect(query.evidence.rows).toEqual([
			expect.objectContaining({ verifiedBinding: false }),
		]);
	});
	it("atomically publishes simultaneous identical investigations", async () => {
		const dir = await temp();
		const indexes = await Promise.all(
			Array.from({ length: 5 }, () => persistInvestigation(dir, result())),
		);
		expect(new Set(indexes.map((i) => i?.id)).size).toBe(1);
		await expect(queryInvestigation(indexes[0]!.file)).resolves.toBeDefined();
	});
	it("changes identity when source engine or evidence changes", async () => {
		const dir = await temp();
		const changed = result();
		changed.engineVersion = "android-static/v2";
		expect((await persistInvestigation(dir, changed))?.id).not.toBe(
			(await persistInvestigation(dir, result()))?.id,
		);
	});
	it("queries literal text with pagination, not executable regex", async () => {
		const index = await persistInvestigation(await temp(), result());
		const first = await queryInvestigation(index!.file, { limit: 1 });
		expect(first.evidence.nextOffset).toBe(1);
		const methods = await queryInvestigation(index!.file, {
			kind: "method",
			text: "NATIVE_METHOD",
		});
		expect(methods.evidence.totalMatches).toBe(1);
		const regex = await queryInvestigation(index!.file, { text: ".*" });
		expect(regex.evidence.totalMatches).toBe(0);
	});
	it("rejects corrupt manifests and does not silently overwrite", async () => {
		const dir = await temp();
		const index = await persistInvestigation(dir, result());
		const body = JSON.parse(await readFile(index!.file, "utf8"));
		body.result.status = "completed";
		await writeFile(index!.file, JSON.stringify(body));
		await expect(queryInvestigation(index!.file)).rejects.toThrow(
			"hash mismatch",
		);
		await expect(persistInvestigation(dir, result())).rejects.toThrow(
			"hash mismatch",
		);
	});
	it("rejects non-index documents, relative paths, malformed rows and oversized files", async () => {
		const dir = await temp();
		const path = join(dir, "bad.json");
		await writeFile(path, "{}");
		await expect(queryInvestigation(path)).rejects.toThrow();
		await expect(queryInvestigation("bad.json")).rejects.toThrow("absolute");
		await writeFile(path, " ".repeat(1024 * 1024 + 1));
		await expect(queryInvestigation(path)).rejects.toThrow("limit");
		const bad = result();
		bad.evidence.artifacts = [{ id: "not-an-id" }];
		const index = await persistInvestigation(dir, bad);
		await expect(queryInvestigation(index!.file)).rejects.toThrow(
			"evidence ID",
		);
	});
	it("does not persist failed, blocked, cancelled or unrelated results", async () => {
		const dir = await temp();
		for (const status of ["failed", "blocked", "cancelled"] as const)
			expect(
				await persistInvestigation(dir, { ...result(), status }),
			).toBeUndefined();
		expect(
			await persistInvestigation(dir, { ...result(), engine: "other" }),
		).toBeUndefined();
	});
	it.skipIf(process.platform === "win32")(
		"rejects symlink targets and cache roots",
		async () => {
			const dir = await temp();
			const index = await persistInvestigation(join(dir, "real"), result());
			await symlink(index!.file, join(dir, "link"));
			await expect(queryInvestigation(join(dir, "link"))).rejects.toThrow(
				"symlink",
			);
			await symlink(join(dir, "real"), join(dir, "root"));
			await expect(
				persistInvestigation(join(dir, "root"), result()),
			).rejects.toThrow("symlink");
		},
	);
});
