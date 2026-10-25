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
import { expect, it } from "vitest";
import { SessionArtifacts } from "./session-artifacts";
it("confines recursive core cleanup and refuses junction aliases", () => {
	const root = mkdtempSync(join(tmpdir(), "core-owned-artifacts-"));
	const outside = mkdtempSync(join(tmpdir(), "core-external-artifacts-"));
	try {
		const a = new SessionArtifacts(() => root);
		writeFileSync(join(outside, "keep.txt"), "keep");
		a.removeDir(outside);
		a.removeDir(root);
		expect(existsSync(join(outside, "keep.txt"))).toBe(true);
		expect(existsSync(root)).toBe(true);
		symlinkSync(
			outside,
			join(root, "alias"),
			process.platform === "win32" ? "junction" : "dir",
		);
		a.removeDir(join(root, "alias"));
		a.removeOwnedFile(join(root, "alias", "keep.txt"));
		expect(existsSync(join(outside, "keep.txt"))).toBe(true);
		mkdirSync(join(root, "owned"));
		writeFileSync(join(root, "owned", "messages.json"), "owned");
		a.removeDir(join(root, "owned"));
		expect(existsSync(join(root, "owned"))).toBe(false);
	} finally {
		rmSync(root, { recursive: true, force: true });
		rmSync(outside, { recursive: true, force: true });
	}
});
