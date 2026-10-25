import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
vi.mock("@cline/core", () => ({
	SqliteSessionStore: class {
		get() {
			return undefined;
		}
		close() {}
	},
}));
import { discoverChatSessions } from "./discovery";
it("never deletes upload staging or unindexed artifacts while listing sessions", () => {
	const previous = process.env.CLINE_SESSION_DATA_DIR;
	const root = mkdtempSync(join(tmpdir(), "cline-discovery-readonly-"));
	try {
		process.env.CLINE_SESSION_DATA_DIR = root;
		for (const name of ["_attachment-uploads", "unindexed-session"]) {
			mkdirSync(join(root, name));
			writeFileSync(join(root, name, "keep.upload"), "in-progress");
		}
		for (let i = 0; i < 3; i++)
			discoverChatSessions({ liveSessions: new Map() });
		for (const name of ["_attachment-uploads", "unindexed-session"]) {
			expect(existsSync(join(root, name))).toBe(true);
			expect(readFileSync(join(root, name, "keep.upload"), "utf8")).toBe(
				"in-progress",
			);
		}
	} finally {
		if (previous === undefined) delete process.env.CLINE_SESSION_DATA_DIR;
		else process.env.CLINE_SESSION_DATA_DIR = previous;
		rmSync(root, { recursive: true, force: true });
	}
});
