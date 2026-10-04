import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EngineeringWorktreeManager } from "./engineering-worktree-manager";

const roots: string[] = [];
function repository() {
	const root = mkdtempSync(join(tmpdir(), "cline-eng-repo-"));
	roots.push(root);
	for (const args of [
		["init", "-b", "main"],
		["config", "user.email", "test@example.invalid"],
		["config", "user.name", "Test"],
	])
		execFileSync("git", ["-C", root, ...args]);
	writeFileSync(join(root, "README.md"), "base\n");
	execFileSync("git", ["-C", root, "add", "."]);
	execFileSync("git", ["-C", root, "commit", "-m", "base"]);
	return root;
}
afterEach(() => {
	for (const root of roots.splice(0))
		rmSync(root, { recursive: true, force: true });
});

describe("EngineeringWorktreeManager", () => {
	it("creates isolated writer leases and releases clean worktrees", () => {
		const root = repository();
		const managed = mkdtempSync(join(tmpdir(), "cline-eng-managed-"));
		roots.push(managed);
		const manager = new EngineeringWorktreeManager(managed);
		const lease = manager.create({
			workspaceRoot: root,
			missionId: "mission-1",
			taskId: "implement",
			agentId: "agent-1",
		});
		expect(lease.branch).toContain("cline/engineering/");
		expect(manager.inspect(lease.path)).toMatchObject({
			dirty: false,
			aheadBy: 0,
		});
		expect(manager.release(lease.path, { confirmDiscard: false }).status).toBe(
			"released",
		);
	});
	it("requires explicit confirmation before discarding changes", () => {
		const root = repository();
		const managed = mkdtempSync(join(tmpdir(), "cline-eng-managed-"));
		roots.push(managed);
		const manager = new EngineeringWorktreeManager(managed);
		const lease = manager.create({
			workspaceRoot: root,
			missionId: "mission-2",
			taskId: "implement",
			agentId: "agent-2",
		});
		writeFileSync(join(lease.path, "changed.txt"), "change\n");
		expect(() =>
			manager.release(lease.path, { confirmDiscard: false }),
		).toThrow("explicit discard confirmation");
		expect(manager.release(lease.path, { confirmDiscard: true }).status).toBe(
			"released",
		);
	});
	it("rejects paths outside the managed root", () => {
		const root = repository();
		const managed = mkdtempSync(join(tmpdir(), "cline-eng-managed-"));
		roots.push(managed);
		const manager = new EngineeringWorktreeManager(managed);
		expect(() => manager.inspect(root)).toThrow("outside the managed root");
	});
});
