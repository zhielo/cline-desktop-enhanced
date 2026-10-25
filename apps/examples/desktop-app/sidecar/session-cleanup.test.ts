import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import {
	assertSessionCleanupId,
	removeOwnedSessionArtifacts,
} from "./session-cleanup";
let root: string;
let previous: string | undefined;
beforeEach(() => {
	previous = process.env.CLINE_SESSION_DATA_DIR;
	root = mkdtempSync(join(tmpdir(), "cline-owned-cleanup-"));
	process.env.CLINE_SESSION_DATA_DIR = root;
});
afterEach(() => {
	if (previous === undefined) delete process.env.CLINE_SESSION_DATA_DIR;
	else process.env.CLINE_SESSION_DATA_DIR = previous;
	rmSync(root, { force: true, recursive: true });
});
it.each([
	"../../outside",
	"..",
	".",
	"a/b",
	"a\\b",
	"C:outside",
	"_attachment-uploads",
	"",
])("rejects unsafe cleanup ID %s", (id) => {
	expect(() => assertSessionCleanupId(id)).toThrow();
});
it("removes only the direct owned session directory", () => {
	mkdirSync(join(root, "session-valid"));
	writeFileSync(join(root, "session-valid", "messages.json"), "{}");
	writeFileSync(join(root, "unrelated.txt"), "keep");
	expect(removeOwnedSessionArtifacts("session-valid")).toBe(true);
	expect(existsSync(join(root, "session-valid"))).toBe(false);
	expect(existsSync(join(root, "unrelated.txt"))).toBe(true);
});
it("refuses directory symlinks and Windows junctions", () => {
	const external = join(root, "external");
	mkdirSync(external);
	writeFileSync(join(external, "keep.txt"), "keep");
	symlinkSync(
		external,
		join(root, "linked-session"),
		process.platform === "win32" ? "junction" : "dir",
	);
	expect(() => removeOwnedSessionArtifacts("linked-session")).toThrow(/links/);
	expect(existsSync(join(external, "keep.txt"))).toBe(true);
});
