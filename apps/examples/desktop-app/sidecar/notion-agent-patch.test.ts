import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	applyNotionAgentPatch,
	previewNotionAgentPatch,
	rollbackNotionAgentPatch,
} from "./notion-agent-patch";

const roots: string[] = [];
function fixture() {
	const root = mkdtempSync(join(tmpdir(), "notion-agent-patch-"));
	roots.push(root);
	execFileSync("git", ["init", "-b", "main"], { cwd: root });
	execFileSync("git", ["config", "user.email", "test@example.com"], {
		cwd: root,
	});
	execFileSync("git", ["config", "user.name", "Test"], { cwd: root });
	writeFileSync(join(root, "index.ts"), "export const ready = false;\n");
	execFileSync("git", ["add", "index.ts"], { cwd: root });
	execFileSync("git", ["commit", "-m", "fixture"], { cwd: root });
	const hash = createHash("sha256")
		.update(readFileSync(join(root, "index.ts")))
		.digest("hex");
	const patch = `diff --git a/index.ts b/index.ts\nindex 819b2de..2d8493f 100644\n--- a/index.ts\n+++ b/index.ts\n@@ -1 +1 @@\n-export const ready = false;\n+export const ready = true;\n`;
	return { root, hash, patch };
}
afterEach(() =>
	roots.splice(0).forEach((root) => {
		rmSync(root, { recursive: true, force: true });
	}),
);

describe("Notion Agent patch pipeline", () => {
	it("previews an approved patch with provenance and citations", () => {
		const { root, hash, patch } = fixture();
		const preview = previewNotionAgentPatch({
			root,
			patch,
			approvedHashes: { "index.ts": hash },
			response: `Evidence index.ts:1@sha256:${hash}`,
		});
		expect(preview.applicable).toBe(true);
		expect(preview.files[0]).toMatchObject({
			path: "index.ts",
			additions: 1,
			deletions: 1,
		});
		expect(preview.citations).toHaveLength(1);
	});

	it("rejects stale, sensitive, and unapproved targets", () => {
		const { root, patch } = fixture();
		expect(() =>
			previewNotionAgentPatch({
				root,
				patch,
				approvedHashes: { "index.ts": "stale" },
			}),
		).toThrow("changed after sharing");
		const secretPatch = patch.replaceAll("index.ts", ".env");
		expect(() =>
			previewNotionAgentPatch({ root, patch: secretPatch, approvedHashes: {} }),
		).toThrow("sensitive file");
	});

	it("applies on an isolated branch and supports guarded rollback", () => {
		const { root, hash, patch } = fixture();
		const applied = applyNotionAgentPatch({
			root,
			patch,
			approvedHashes: { "index.ts": hash },
			confirm: true,
			branchName: "review",
		});
		expect(applied.branch).toBe("notion-agent/review");
		expect(readFileSync(join(root, "index.ts"), "utf8")).toContain("true");
		const rolledBack = rollbackNotionAgentPatch({
			root,
			patch,
			branch: applied.branch,
			previousBranch: applied.previousBranch,
			appliedHashes: applied.appliedHashes,
			originalHashes: applied.originalHashes,
			confirm: true,
		});
		expect(rolledBack.currentBranch).toBe("main");
		expect(readFileSync(join(root, "index.ts"), "utf8")).toContain("false");
	});
});
