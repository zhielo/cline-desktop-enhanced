import { createHash } from "node:crypto";
import { mkdtemp, writeFile, rm, symlink } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, it, expect } from "vitest";
import { verifyRuntime } from "./bundled-analysis-runtime";
const roots: string[] = [];
afterEach(async () => {
	await Promise.all(
		roots.splice(0).map((p) => rm(p, { recursive: true, force: true })),
	);
});
async function fixture() {
	const root = await mkdtemp(join(tmpdir(), "runtime-owned-"));
	roots.push(root);
	const bytes = "owned fixture not executable";
	const digest = createHash("sha256").update(bytes).digest("hex");
	await writeFile(join(root, "python.exe"), bytes);
	await writeFile(join(root, "python313._pth"), bytes);
	const manifest = {
		schemaVersion: 1,
		runtimeId: "owned-v1",
		pythonVersion: "3.13.12",
		fixtureVersion: "v1",
		files: { "python.exe": digest, "python313._pth": digest },
	};
	await writeFile(
		join(root, "runtime-manifest.json"),
		JSON.stringify(manifest),
	);
	return { root, manifest };
}
it("validates owned file hashes, without executing an interpreter", async () => {
	const f = await fixture();
	expect((await verifyRuntime(f.root)).manifest.runtimeId).toBe("owned-v1");
});
it("rejects changed files and changed trusted manifests", async () => {
	const f = await fixture();
	const { digest } = await verifyRuntime(f.root);
	await writeFile(join(f.root, "python.exe"), "changed");
	await expect(verifyRuntime(f.root, digest)).rejects.toThrow("integrity");
	await writeFile(join(f.root, "runtime-manifest.json"), "{}");
	await expect(verifyRuntime(f.root, digest)).rejects.toThrow(
		"manifest changed",
	);
});
it("rejects path traversal even when the supplied digest is valid", async () => {
	const f = await fixture();
	f.manifest.files["../outside" as "python.exe"] = "a".repeat(64);
	await writeFile(
		join(f.root, "runtime-manifest.json"),
		JSON.stringify(f.manifest),
	);
	await expect(verifyRuntime(f.root)).rejects.toThrow("Unsafe");
});
it.skipIf(process.platform === "win32")("rejects linked roots", async () => {
	const f = await fixture();
	const link = `${f.root}-link`;
	roots.push(link);
	await symlink(f.root, link);
	await expect(verifyRuntime(link)).rejects.toThrow("non-linked");
});
it("rejects untracked imported files", async () => {
	const f = await fixture();
	await writeFile(join(f.root, "unexpected.py"), "# owned but untracked");
	await expect(verifyRuntime(f.root)).rejects.toThrow("Untracked");
});
