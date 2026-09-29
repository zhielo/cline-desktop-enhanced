import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import type { AgentToolContext } from "@cline/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createRepositoryExecutor } from "./repository-tool";

const execFileAsync = promisify(execFile);
let root = "";
const context = {
	agentId: "agent",
	iteration: 1,
	sessionId: "session",
} satisfies AgentToolContext;

async function git(...args: string[]) {
	await execFileAsync("git", args, { cwd: root });
}

beforeEach(async () => {
	root = await mkdtemp(join(tmpdir(), "cline-repository-tool-"));
	await git("init");
	await git("config", "user.name", "Cline Test");
	await git("config", "user.email", "cline@example.invalid");
	await writeFile(join(root, "README.md"), "one\n");
	await git("add", "README.md");
	await git("commit", "-m", "initial");
});

afterEach(async () => {
	await rm(root, { recursive: true, force: true });
});

describe("createRepositoryExecutor", () => {
	it("returns bounded structured status and read operations", async () => {
		const execute = createRepositoryExecutor(() => root);
		const status = JSON.parse(await execute({ action: "status" }, context));
		expect(status.root).toBe(root);
		expect(status.status).toContain("##");
		expect(await execute({ action: "log", limit: 5 }, context)).toContain(
			"initial",
		);
		expect(await execute({ action: "branches" }, context)).toContain("*");
	});

	it("requires explicit confirmation for local writes", async () => {
		const execute = createRepositoryExecutor(() => root);
		await expect(
			execute(
				{
					action: "create_branch",
					name: "feature/test",
					confirm_write: false as true,
				},
				context,
			),
		).rejects.toThrow("confirm_write=true");
	});

	it("creates a branch and commits only requested relative paths", async () => {
		const execute = createRepositoryExecutor(() => root);
		await execute(
			{ action: "create_branch", name: "feature/test", confirm_write: true },
			context,
		);
		await writeFile(join(root, "README.md"), "two\n");
		const result = JSON.parse(
			await execute(
				{
					action: "commit",
					message: "update readme",
					paths: ["README.md"],
					confirm_write: true,
				},
				context,
			),
		);
		expect(result.commit).toContain("update readme");
		expect(result.repository.branch).toBe("feature/test");
	});

	it("rejects path traversal and unsafe refs", async () => {
		const execute = createRepositoryExecutor(() => root);
		await expect(
			execute({ action: "diff", staged: false, path: "../secret" }, context),
		).rejects.toThrow("escape");
		await expect(
			execute(
				{ action: "switch_branch", name: "bad ref", confirm_write: true },
				context,
			),
		).rejects.toThrow("safe Git ref");
	});

	it("requires confirmation before every remote operation", async () => {
		const execute = createRepositoryExecutor(() => root);
		await expect(
			execute(
				{ action: "fetch", remote: "origin", confirm_remote: false as true },
				context,
			),
		).rejects.toThrow("confirm_remote=true");
	});
});
