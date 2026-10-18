import { afterEach, expect, it, vi } from "vitest";
import * as fs from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ReverseEngineeringInputSchema } from "../schemas";
import { createReverseEngineeringExecutor } from "./reverse-engineering";
import { compareProjectVersions } from "./project-versions";
const mutation = vi.hoisted(() => ({
	run: undefined as undefined | (() => Promise<void>),
}));
vi.mock("./source-investigation", async (importOriginal) => {
	const actual =
		await importOriginal<typeof import("./source-investigation")>();
	return {
		...actual,
		collectWorkflowSources: async (
			...args: Parameters<typeof actual.collectWorkflowSources>
		) => {
			const r = await actual.collectWorkflowSources(...args);
			await mutation.run?.();
			return r;
		},
	};
});
const dirs: string[] = [];
afterEach(async () => {
	mutation.run = undefined;
	await Promise.all(
		dirs.splice(0).map((p) => fs.rm(p, { recursive: true, force: true })),
	);
});
async function fixture(
	left: Record<string, string>,
	right: Record<string, string>,
) {
	const root = await fs.realpath(
		await fs.mkdtemp(join(tmpdir(), "owned-project-versions-")),
	);
	dirs.push(root);
	for (const [side, files] of Object.entries({ before: left, after: right })) {
		await fs.mkdir(join(root, side));
		for (const [file, value] of Object.entries(files)) {
			const p = join(root, side, file);
			await fs.mkdir(join(p, ".."), { recursive: true });
			await fs.writeFile(p, value);
		}
	}
	return {
		root,
		target: join(root, "before"),
		compare_target: join(root, "after"),
		operation: "compare_versions",
		version_comparison: { kind: "project", max_results: 100 },
	};
}
async function execute(input: unknown) {
	return JSON.parse(
		await createReverseEngineeringExecutor()(
			ReverseEngineeringInputSchema.parse(input),
			{} as never,
		),
	);
}
it("combines content-hash file categories and exact syntax API changes without executing or approving", async () => {
	const f = await fixture(
		{
			"api.ts": "export function read(x:string):string{return x}",
			"package.json": '{"version":1}',
			"assets/a": "old",
			"lib/owned.so": "old",
			".hidden": "keep",
			gone: "remove",
		},
		{
			"api.ts":
				"export function read(x:number):number{return x};globalThis.__versionMustNotRun=true;",
			"package.json": '{"version":2}',
			"assets/a": "new",
			"lib/owned.so": "new",
			".hidden": "keep",
			"new": "add",
		},
	);
	const r = await execute(f);
	expect(r).toMatchObject({
		status: "partial",
		effect: "read",
		published: false,
		observedExecution: false,
		changedFiles: 6,
		categoryCounts: {
			source: 1,
			manifest: 1,
			"resources-assets": 1,
			"native-binary": 1,
			other: 2,
		},
		coverage: { inventoryPasses: 4 },
	});
	expect(r.publicApi.changed).toEqual(["api.ts:read"]);
	expect(r.publicApi.removed).toEqual([]);
	expect(
		r.changes.find((c: { path: string }) => c.path === "assets/a")
			.before_sha256,
	).not.toBe(
		r.changes.find((c: { path: string }) => c.path === "assets/a").after_sha256,
	);
	expect(r.baselineInventorySha256).toMatch(/^[a-f0-9]{64}$/);
	expect(r.sourceArtifacts).toHaveLength(2);
	expect(r.proposedManifest).toBeUndefined();
	expect(
		(globalThis as Record<string, unknown>).__versionMustNotRun,
	).toBeUndefined();
	expect(await fs.readFile(join(f.target, "assets/a"), "utf8")).toBe("old");
});
it("keeps project API keys stable when adding a second source file and ignores body-only differences", async () => {
	const f = await fixture(
		{ "api.ts": "export function read(x:string):string{return x}" },
		{
			"api.ts": 'export function read(x:string):string{return "different"}',
			"extra.ts": "export const added:number=1",
		},
	);
	const r = await execute(f);
	expect(r.publicApi.added).toEqual(["extra.ts:added"]);
	expect(r.publicApi.removed).toEqual([]);
	expect(r.publicApi.changed).toEqual([]);
});
it("reports removal of the last JS/TS API and permits no-source binary projects", async () => {
	const f = await fixture(
		{ "api.ts": "export const old:number=1" },
		{ asset: "bytes" },
	);
	const r = await execute(f);
	expect(r.publicApi.removed).toEqual(["api.ts:old"]);
	const empty = await fixture({ "a.bin": "same" }, { "a.bin": "same" });
	const identical = await execute(empty);
	expect(identical.identicalBytes).toBe(true);
	expect(identical.publicApi.added).toEqual([]);
	expect(identical.status).toBe("partial");
});
it("includes dotfiles and ignored source directories in byte scope but marks API exclusions", async () => {
	const f = await fixture(
		{ ".config": "old", "node_modules/x.ts": "export const ignored=1" },
		{ ".config": "new", "node_modules/x.ts": "export const ignored=2" },
	);
	const r = await execute(f);
	expect(r.changedFiles).toBe(2);
	expect(r.publicApi.changed).toEqual([]);
	expect(r.sourceLimitations.join(" ")).toContain("No supported JS/TS");
});
it("blocks more than 256 changes rather than silently presenting a complete comparison", async () => {
	const f = await fixture(
		{},
		Object.fromEntries(
			Array.from({ length: 257 }, (_, i) => [`${i}.bin`, "x"]),
		),
	);
	const r = await execute(f);
	expect(r.status).toBe("blocked");
	expect(r.changedFiles).toBe(257);
	expect(r.publicApi.status).toBe("not-started");
	expect(r.changes).toBeUndefined();
});
it("enforces detail budgets, preserves counts and hashes, and never exceeds the output ceiling", async () => {
	const f = await fixture(
		{ a: "before", b: "before" },
		{ a: "after", b: "after" },
	);
	const r = await execute({
		...f,
		version_comparison: { kind: "project", max_results: 1 },
	});
	expect(r.changes).toHaveLength(1);
	expect(r.changesTruncated).toBe(true);
	expect(r.changedFiles).toBe(2);
	expect(r.changeSetSha256).toMatch(/^[a-f0-9]{64}$/);
	expect(Buffer.byteLength(JSON.stringify(r))).toBeLessThanOrEqual(262144);
});
it("rejects mutation between inventory and source parsing", async () => {
	const f = await fixture(
		{ "api.ts": "export const value:number=1" },
		{ "api.ts": "export const value:number=2" },
	);
	mutation.run = async () => {
		mutation.run = undefined;
		await fs.writeFile(join(f.target, "new"), "mutation");
	};
	await expect(execute(f)).rejects.toThrow(
		"changed during combined comparison",
	);
});
it("rejects aliases, special scopes, misplaced options, legacy overrides and invalid budgets", async () => {
	const f = await fixture({ a: "x" }, { a: "y" });
	await expect(execute({ ...f, compare_target: f.target })).rejects.toThrow(
		"distinct sibling",
	);
	await expect(
		execute({ ...f, compare_target: join(f.root, "other", "nested") }),
	).rejects.toThrow("sibling");
	await expect(execute({ ...f, operation: "inspect" })).rejects.toThrow(
		"only by compare_versions",
	);
	await expect(execute({ ...f, workflow_query: {} })).rejects.toThrow(
		"rejects legacy overrides",
	);
	expect(() =>
		ReverseEngineeringInputSchema.parse({
			...f,
			version_comparison: { kind: "project", max_results: 201 },
		}),
	).toThrow();
	await fs.link(join(f.target, "a"), join(f.target, "alias"));
	await expect(execute(f)).rejects.toThrow("distinct regular");
});
it("rejects prior cancellation without producing a report", async () => {
	const f = await fixture({ a: "x" }, { a: "y" });
	const c = new AbortController();
	c.abort();
	await expect(compareProjectVersions(f, c.signal)).rejects.toThrow();
});

it("omits oversized API detail with counts and a fingerprint, never an unbounded report", async () => {
	const source = Array.from(
		{ length: 24 },
		(_, i) => `export function f${i}(x: "${"a".repeat(4000)}"):void{}`,
	).join("\n");
	const f = await fixture({ "api.ts": source }, { "api.ts": source });
	const r = await execute(f);
	expect(r.publicApi.detailsOmitted).toBe(true);
	expect(r.publicApi.counts.leftDeclarations).toBe(24);
	expect(r.publicApi.evidenceSha256).toMatch(/^[a-f0-9]{64}$/);
	expect(Buffer.byteLength(JSON.stringify(r))).toBeLessThanOrEqual(262144);
});
