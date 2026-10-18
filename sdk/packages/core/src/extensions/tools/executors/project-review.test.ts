import { strict as assert } from "node:assert";
import * as fs from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { candidateHash } from "./candidate-files";
import {
	ProjectReviewManifestSchema,
	projectInventoryHash,
	reviewProjectFiles,
} from "./project-review";
import { it, vi, afterEach } from "vitest";
const mutation = vi.hoisted(() => ({
	run: undefined as undefined | ((directory: string) => Promise<void>),
}));
vi.mock("node:fs/promises", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs/promises")>();
	return {
		...actual,
		opendir: async (...args: unknown[]) => {
			const result = await (
				actual.opendir as (...args: unknown[]) => Promise<unknown>
			)(...args);
			await mutation.run?.(String(args[0]));
			return result;
		},
	};
});
afterEach(() => {
	mutation.run = undefined;
});
async function fixture(
	before: Record<string, string>,
	after: Record<string, string>,
) {
	const root = await fs.mkdtemp(join(tmpdir(), "owned-project-review-"));
	for (const [dir, files] of Object.entries({ before, after }))
		for (const [p, s] of Object.entries(files)) {
			const file = join(root, dir, p);
			await fs.mkdir(join(file, ".."), { recursive: true });
			await fs.writeFile(file, s);
		}
	for (const d of ["before", "after"])
		await fs.mkdir(join(root, d), { recursive: true });
	const manifest = {
		protocol: "cline-project-review/v1",
		baseline: {
			directory: "before",
			inventory_sha256: projectInventoryHash(
				Object.entries(before).map(([path, s]) => ({
					path,
					bytes: Buffer.byteLength(s),
					sha256: candidateHash(s),
				})),
			),
		},
		candidate: {
			directory: "after",
			inventory_sha256: projectInventoryHash(
				Object.entries(after).map(([path, s]) => ({
					path,
					bytes: Buffer.byteLength(s),
					sha256: candidateHash(s),
				})),
			),
		},
		approved_changes: [] as Array<{
			path: string;
			before_sha256: string | null;
			after_sha256: string | null;
		}>,
	};
	const file = join(root, "manifest.json");
	await fs.writeFile(file, JSON.stringify(manifest));
	return {
		root,
		file,
		manifest,
		cleanup: () => fs.rm(root, { recursive: true, force: true }),
	};
}
it("approved exact changed/added/deleted files, dotfiles included, originals unchanged", async () => {
	const f = await fixture(
		{ "src/main.ts": "old", gone: "remove", ".env.sample": "EMPTY" },
		{ "src/main.ts": "new", added: "add", ".env.sample": "EMPTY" },
	);
	try {
		f.manifest.approved_changes = [
			{
				path: "src/main.ts",
				before_sha256: candidateHash("old"),
				after_sha256: candidateHash("new"),
			},
			{
				path: "gone",
				before_sha256: candidateHash("remove"),
				after_sha256: null,
			},
			{
				path: "added",
				before_sha256: null,
				after_sha256: candidateHash("add"),
			},
		];
		const r = await reviewProjectFiles(f.file, f.manifest);
		assert.equal(r.status, "completed");
		assert.equal(r.changedFiles, 3);
		assert.equal(r.passes, 2);
		assert.equal(
			await fs.readFile(join(f.root, "before/src/main.ts"), "utf8"),
			"old",
		);
		assert.equal(
			await fs.readFile(join(f.root, "after/src/main.ts"), "utf8"),
			"new",
		);
	} finally {
		await f.cleanup();
	}
});
it("undeclared edits, additions and deletion never pass", async () => {
	const f = await fixture({ a: "1", b: "2" }, { a: "3", c: "4" });
	try {
		const r = await reviewProjectFiles(f.file, f.manifest);
		assert.equal(r.status, "failed");
		assert.equal(r.unexpectedChanges, 3);
	} finally {
		await f.cleanup();
	}
});
it("stale inventory blocks even equal mutation in both roots", async () => {
	const f = await fixture({ a: "1" }, { a: "1" });
	try {
		await fs.writeFile(join(f.root, "before/a"), "2");
		await fs.writeFile(join(f.root, "after/a"), "2");
		await assert.rejects(
			() => reviewProjectFiles(f.file, f.manifest),
			/fingerprint/,
		);
	} finally {
		await f.cleanup();
	}
});
it("wrong before/after approval and no-op declaration fail", async () => {
	const f = await fixture({ a: "1", b: "2" }, { a: "3", b: "2" });
	try {
		f.manifest.approved_changes = [
			{
				path: "a",
				before_sha256: candidateHash("wrong"),
				after_sha256: candidateHash("3"),
			},
			{
				path: "missing",
				before_sha256: null,
				after_sha256: candidateHash("new"),
			},
		];
		const r = await reviewProjectFiles(f.file, f.manifest);
		assert.equal(r.status, "failed");
		assert.equal(r.unexpectedChanges, 1);
		assert.deepEqual(r.missingDeclaredChanges, ["missing"]);
	} finally {
		await f.cleanup();
	}
});
for (const directory of [
	"../outside",
	"/absolute",
	"before/../after",
	"before\\file",
	"before:stream",
	"before//x",
	"before/.",
	"CON",
	"trailing.",
])
	it("invalid root " + directory, () => {
		assert.equal(
			ProjectReviewManifestSchema.safeParse({
				protocol: "cline-project-review/v1",
				baseline: { directory, inventory_sha256: "a".repeat(64) },
				candidate: { directory: "after", inventory_sha256: "b".repeat(64) },
				approved_changes: [],
			}).success,
			false,
		);
	});
it("overlap, duplicates, aliases and links deny", async () => {
	const f = await fixture({ a: "1" }, { a: "2" });
	try {
		await assert.rejects(
			() =>
				reviewProjectFiles(f.file, {
					...f.manifest,
					candidate: { ...f.manifest.candidate, directory: "before" },
				}),
			/disjoint/,
		);
		f.manifest.approved_changes = [
			{ path: "a", before_sha256: null, after_sha256: candidateHash("1") },
			{ path: "A", before_sha256: null, after_sha256: candidateHash("1") },
		];
		await assert.rejects(
			() => reviewProjectFiles(f.file, f.manifest),
			/ambiguous/,
		);
		f.manifest.approved_changes = [];
		await fs.symlink(join(f.root, "before/a"), join(f.root, "after/link"));
		await assert.rejects(() => reviewProjectFiles(f.file, f.manifest), /links/);
	} finally {
		await f.cleanup();
	}
});
it("hard links, over-limit files, cancellation and absent roots deny", async () => {
	const f = await fixture({ a: "1" }, { a: "2" });
	try {
		await fs.link(join(f.root, "before/a"), join(f.root, "after/alias"));
		await assert.rejects(
			() => reviewProjectFiles(f.file, f.manifest),
			/distinct/,
		);
		await fs.unlink(join(f.root, "after/alias"));
		await fs.writeFile(
			join(f.root, "after/huge"),
			Buffer.alloc(16 * 1024 * 1024 + 1),
		);
		await assert.rejects(
			() => reviewProjectFiles(f.file, f.manifest),
			/byte budget/,
		);
		const c = new AbortController();
		c.abort();
		await assert.rejects(() =>
			reviewProjectFiles(f.file, f.manifest, c.signal),
		);
		await assert.rejects(() =>
			reviewProjectFiles(f.file, {
				...f.manifest,
				candidate: { ...f.manifest.candidate, directory: "missing" },
			}),
		);
	} finally {
		await f.cleanup();
	}
});
it("empty trees pass only matching full fingerprints and no declarations", async () => {
	const f = await fixture({}, {});
	try {
		assert.equal(
			(await reviewProjectFiles(f.file, f.manifest)).status,
			"completed",
		);
		assert.notEqual(
			projectInventoryHash([
				{ path: "a", bytes: 1, sha256: candidateHash("x") },
			]),
			projectInventoryHash([
				{ path: "b", bytes: 1, sha256: candidateHash("x") },
			]),
		);
	} finally {
		await f.cleanup();
	}
});

it("rejects a same-size baseline mutation during the candidate inventory", async () => {
	const f = await fixture({ a: "1" }, { a: "3" });
	try {
		let changed = false;
		mutation.run = async (dir) => {
			if (dir === join(f.root, "after") && !changed) {
				changed = true;
				await fs.writeFile(join(f.root, "before/a"), "2");
			}
		};
		await assert.rejects(
			() => reviewProjectFiles(f.file, f.manifest),
			/mutated/,
		);
		assert.equal(changed, true);
	} finally {
		mutation.run = undefined;
		await f.cleanup();
	}
});
it("rejects depth and aggregate-byte overflow, case aliases and directory links", async () => {
	const f = await fixture({ a: "1" }, { a: "1" });
	try {
		let deep = join(f.root, "after");
		for (let i = 0; i < 17; i++) deep = join(deep, "dir");
		await fs.mkdir(deep, { recursive: true });
		await assert.rejects(
			() => reviewProjectFiles(f.file, f.manifest),
			/depth budget/,
		);
		await fs.rm(join(f.root, "after/dir"), { recursive: true });
		await fs.writeFile(
			join(f.root, "after/zero"),
			Buffer.alloc(16 * 1024 * 1024),
		);
		for (const name of ["one", "two", "three"])
			await fs.copyFile(
				join(f.root, "after/zero"),
				join(f.root, "after", name),
			);
		await assert.rejects(
			() => reviewProjectFiles(f.file, f.manifest),
			/byte budget/,
		);
		for (const name of ["zero", "one", "two", "three"])
			await fs.unlink(join(f.root, "after", name));
		if (process.platform !== "win32") {
			await fs.writeFile(join(f.root, "after/A"), "1");
			await assert.rejects(
				() => reviewProjectFiles(f.file, f.manifest),
				/ambiguous/,
			);
			await fs.unlink(join(f.root, "after/A"));
		}
		await fs.symlink(
			join(f.root, "before"),
			join(f.root, "after/alias"),
			process.platform === "win32" ? "junction" : "dir",
		);
		await assert.rejects(() => reviewProjectFiles(f.file, f.manifest), /links/);
	} finally {
		await f.cleanup();
	}
});
it("does not execute source text or expose file contents in inventory evidence", async () => {
	const text =
		"globalThis.__projectReviewExecuted=true; secret-value-must-not-be-in-evidence";
	const f = await fixture({ "owned.ts": text }, { "owned.ts": text });
	try {
		const result = await reviewProjectFiles(f.file, f.manifest);
		assert.equal(result.status, "completed");
		assert.equal(
			JSON.stringify(result).includes("secret-value-must-not-be-in-evidence"),
			false,
		);
		assert.equal(
			(globalThis as Record<string, unknown>).__projectReviewExecuted,
			undefined,
		);
	} finally {
		await f.cleanup();
	}
});
it("rejects 257 changes, authority fields and identical declared hashes", () => {
	const doc = {
		protocol: "cline-project-review/v1",
		baseline: { directory: "before", inventory_sha256: "a".repeat(64) },
		candidate: { directory: "after", inventory_sha256: "b".repeat(64) },
		approved_changes: [],
	};
	for (const extra of [
		{ shell: "run" },
		{ executionToken: "fake" },
		{ network: true },
		{ ignore: [".env"] },
	])
		assert.equal(
			ProjectReviewManifestSchema.safeParse({ ...doc, ...extra }).success,
			false,
		);
	assert.equal(
		ProjectReviewManifestSchema.safeParse({
			...doc,
			approved_changes: Array.from({ length: 257 }, (_, i) => ({
				path: String(i),
				before_sha256: null,
				after_sha256: "a".repeat(64),
			})),
		}).success,
		false,
	);
	assert.equal(
		ProjectReviewManifestSchema.safeParse({
			...doc,
			approved_changes: [
				{
					path: "a",
					before_sha256: "a".repeat(64),
					after_sha256: "a".repeat(64),
				},
			],
		}).success,
		false,
	);
});

it("inventory draft supplies exact complete hashes and changes, never approval or a write", async () => {
	const f = await fixture({ a: "1", removed: "old" }, { a: "2", added: "new" });
	try {
		const result = await reviewProjectFiles(
			f.file,
			{
				protocol: "cline-project-inventory-request/v1",
				baseline_directory: "before",
				candidate_directory: "after",
			},
			undefined,
			true,
		);
		assert.equal(result.status, "previewed-not-approved");
		assert.equal(result.published, false);
		assert.equal(result.changedFiles, 3);
		assert.ok("proposedManifest" in result && result.proposedManifest);
		if (!("proposedManifest" in result) || !result.proposedManifest)
			throw Error("Missing complete draft");
		assert.equal(
			(await reviewProjectFiles(f.file, result.proposedManifest)).status,
			"completed",
		);
		assert.equal(await fs.readFile(f.file, "utf8"), JSON.stringify(f.manifest));
	} finally {
		await f.cleanup();
	}
});
it("inventory draft never truncates a change allowlist into apparent approval", async () => {
	const before: Record<string, string> = {},
		after: Record<string, string> = {};
	for (let i = 0; i < 257; i++) after[String(i)] = "owned";
	const f = await fixture(before, after);
	try {
		const result = await reviewProjectFiles(
			f.file,
			{
				protocol: "cline-project-inventory-request/v1",
				baseline_directory: "before",
				candidate_directory: "after",
			},
			undefined,
			true,
		);
		assert.equal(result.status, "blocked");
		assert.equal(
			"proposedManifest" in result ? result.proposedManifest : undefined,
			null,
		);
		assert.equal(result.changedFiles, 257);
	} finally {
		await f.cleanup();
	}
});

it("bounds directory enumeration before accepting more than 4096 entries", async () => {
	const f = await fixture({}, {});
	try {
		for (let i = 0; i < 4097; i++)
			await fs.writeFile(join(f.root, "before", `entry-${i}`), "");
		await assert.rejects(
			reviewProjectFiles(
				f.file,
				{
					protocol: "cline-project-inventory-request/v1",
					baseline_directory: "before",
					candidate_directory: "after",
				},
				undefined,
				true,
			),
			/entry budget/,
		);
	} finally {
		await f.cleanup();
	}
}, 30000);
