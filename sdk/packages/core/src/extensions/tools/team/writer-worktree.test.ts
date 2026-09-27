import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	createWriterWorktree,
	listWriterWorktreeChanges,
} from "./writer-worktree";

function git(cwd: string, ...args: string[]): string {
	return execFileSync("git", ["-C", cwd, ...args], { encoding: "utf8" }).trim();
}

describe("writer worktrees", () => {
	it("creates handoff-compatible metadata and reports repository-relative changes", async () => {
		const root = mkdtempSync(join(tmpdir(), "cline-writer-worktree-"));
		const repo = join(root, "repo");
		execFileSync("git", ["init", repo]);
		git(repo, "config", "user.email", "test@example.com");
		git(repo, "config", "user.name", "Cline Test");
		writeFileSync(join(repo, "README.md"), "base\n");
		git(repo, "add", "README.md");
		git(repo, "commit", "-m", "base");

		const metadata = await createWriterWorktree(
			repo,
			"writer-a",
			join(root, "worktrees"),
		);
		expect(metadata.ownerAgentId).toBe("writer-a");
		expect(metadata.generatedBranch).toMatch(/^cline\/team-/);
		expect(existsSync(metadata.path)).toBe(true);
		expect(
			JSON.parse(
				readFileSync(join(dirname(metadata.path), "worktree.json"), "utf8"),
			),
		).toMatchObject({
			version: 1,
			path: metadata.path,
			sourceRepo: repo,
			ownerAgentId: "writer-a",
		});

		writeFileSync(join(metadata.path, "README.md"), "changed\n");
		writeFileSync(join(metadata.path, "new-file.txt"), "new\n");
		await expect(listWriterWorktreeChanges(metadata.path)).resolves.toEqual([
			"README.md",
			"new-file.txt",
		]);
	});
});
