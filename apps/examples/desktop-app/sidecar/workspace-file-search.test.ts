import { mkdtemp, mkdir, writeFile, rm, symlink } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { listWorkspaceFiles } from "./workspace-file-search";
const dirs: string[] = [];
const fixture = async () => {
	const root = await mkdtemp(join(tmpdir(), "cline-file-search-"));
	dirs.push(root);
	return root;
};
afterEach(async () => {
	await Promise.all(
		dirs.splice(0).map((p) => rm(p, { recursive: true, force: true })),
	);
});
describe("bounded asynchronous workspace file discovery", () => {
	it("includes project config and excludes internal/credential directories", async () => {
		const root = await fixture();
		for (const name of [
			".github/workflows",
			".agents",
			".cline",
			".vscode",
			".git",
			".ssh",
			"node_modules",
		]) {
			await mkdir(join(root, name), { recursive: true });
			await writeFile(join(root, name, "fixture.txt"), "fixture");
		}
		const result = await listWorkspaceFiles(root, "fixture");
		expect(result.complete).toBe(true);
		expect(result.files.map((p) => p.replaceAll("\\", "/"))).toEqual([
			".agents/fixture.txt",
			".cline/fixture.txt",
			".github/workflows/fixture.txt",
			".vscode/fixture.txt",
		]);
	});
	it("bounds visited entries even when there are no matching files", async () => {
		const root = await fixture();
		for (let i = 0; i < 20; i++)
			await writeFile(join(root, `file-${i}.ts`), "fixture");
		const result = await listWorkspaceFiles(root, "no-match", {
			maxEntries: 5,
		});
		expect(result.files).toEqual([]);
		expect(result.complete).toBe(false);
		expect(result.stopReason).toBe("entry-budget");
		expect(result.visitedEntries).toBe(5);
	});
	it("reports result and directory limits independently", async () => {
		const root = await fixture();
		for (let i = 0; i < 5; i++) {
			await mkdir(join(root, `dir-${i}`));
			await writeFile(join(root, `file-${i}.ts`), "fixture");
		}
		expect(
			(await listWorkspaceFiles(root, "file", { maxResults: 2 })).stopReason,
		).toBe("result-limit");
		const result = await listWorkspaceFiles(root, "no-match", {
			maxDirectories: 1,
		});
		expect(result.complete).toBe(false);
		expect(result.stopReason).toBe("directory-budget");
	});
	it("honors cancellation without returning false completeness", async () => {
		const root = await fixture(),
			controller = new AbortController();
		controller.abort();
		const result = await listWorkspaceFiles(root, "", {
			signal: controller.signal,
		});
		expect(result.stopReason).toBe("cancelled");
		expect(result.visitedEntries).toBe(0);
	});
	it("yields to cancellation during an active directory traversal", async () => {
		const root = await fixture();
		for (let i = 0; i < 30; i++)
			await writeFile(join(root, `file-${i}.ts`), "fixture");
		const controller = new AbortController();
		const running = listWorkspaceFiles(root, "", { signal: controller.signal });
		queueMicrotask(() => controller.abort());
		const result = await running;
		expect(result.complete).toBe(false);
		expect(result.stopReason).toBe("cancelled");
	});
	it("reports an unavailable root rather than claiming a complete empty workspace", async () => {
		const root = await fixture();
		const result = await listWorkspaceFiles(join(root, "missing"), "");
		expect(result.complete).toBe(false);
		expect(result.inaccessibleDirectories).toBe(1);
	});
	it("does not follow a symlink to an outside directory", async () => {
		const root = await fixture(),
			outside = await fixture();
		await writeFile(join(outside, "outside.txt"), "fixture");
		try {
			await symlink(
				outside,
				join(root, "redirect"),
				process.platform === "win32" ? "junction" : "dir",
			);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "EPERM") return;
			throw error;
		}
		expect((await listWorkspaceFiles(root, "")).files).toEqual([]);
	});
});
