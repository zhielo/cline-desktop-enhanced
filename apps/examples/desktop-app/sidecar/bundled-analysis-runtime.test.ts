import { createHash } from "node:crypto";
import { mkdtemp, writeFile, rm, symlink, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, it, expect, vi } from "vitest";
import {
	verifyRuntime,
	initializeBundledAnalysisRuntime,
	repairBundledAnalysisRuntime,
} from "./bundled-analysis-runtime";
const roots: string[] = [];
afterEach(async () => {
	vi.unstubAllEnvs();
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
		runtimeId: "cpython-3.13.12-windows-x64-v1",
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
	expect((await verifyRuntime(f.root)).manifest.runtimeId).toBe(
		"cpython-3.13.12-windows-x64-v1",
	);
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

it("preserves an explicit external interpreter until the user chooses bundled repair", async () => {
	const f = await fixture();
	vi.stubEnv("CLINE_BUNDLED_ANALYSIS_ROOT", f.root);
	vi.stubEnv("CLINE_DATA_DIR", join(f.root, "../", `data-${Date.now()}`));
	roots.push(process.env.CLINE_DATA_DIR!);
	vi.stubEnv("CLINE_RE_PYTHON", "C:\\external\\python.exe");
	await initializeBundledAnalysisRuntime("win32");
	expect(process.env.CLINE_RE_PYTHON).toBe("C:\\external\\python.exe");
	const repaired = await repairBundledAnalysisRuntime();
	expect(repaired).toMatchObject({ status: "repaired", restartRequired: true });
	const selected = process.env.CLINE_RE_PYTHON;
	expect(selected).not.toBe(join(f.root, "python.exe"));
	vi.stubEnv("CLINE_RE_PYTHON", "C:\\external\\python.exe");
	await initializeBundledAnalysisRuntime("win32");
	expect(process.env.CLINE_RE_PYTHON).toBe(selected);
});
it("uses only verified installed resources when a saved repair cache is missing", async () => {
	const f = await fixture();
	const data = join(f.root, "../", `data-fallback-${Date.now()}`);
	roots.push(data);
	await mkdir(join(data, "analysis-runtime"), { recursive: true });
	await writeFile(
		join(data, "analysis-runtime", "preference.json"),
		JSON.stringify({
			schemaVersion: 1,
			preferBundled: true,
			path: "C:\\untrusted.exe",
		}),
	);
	vi.stubEnv("CLINE_BUNDLED_ANALYSIS_ROOT", f.root);
	vi.stubEnv("CLINE_DATA_DIR", data);
	vi.stubEnv("CLINE_RE_PYTHON", "C:\\external\\python.exe");
	await initializeBundledAnalysisRuntime("win32");
	expect(process.env.CLINE_RE_PYTHON).toBe(join(f.root, "python.exe"));
});
it("blocks damaged bundled analysis without throwing during coding startup", async () => {
	const f = await fixture();
	await writeFile(join(f.root, "python.exe"), "damaged");
	vi.stubEnv("CLINE_BUNDLED_ANALYSIS_ROOT", f.root);
	vi.stubEnv("CLINE_RE_PYTHON", "");
	await expect(
		initializeBundledAnalysisRuntime("win32"),
	).resolves.toBeUndefined();
	expect(process.env.CLINE_RE_PYTHON).toBe(join(f.root, "blocked-runtime.exe"));
});

it("rejects unsafe runtime identifiers even with valid owned file hashes", async () => {
	const f = await fixture();
	for (const runtimeId of [
		"../escape",
		"..",
		".",
		"a/escape",
		"a\\escape",
		"a".repeat(101),
	]) {
		await writeFile(
			join(f.root, "runtime-manifest.json"),
			JSON.stringify({ ...f.manifest, runtimeId }),
		);
		await expect(verifyRuntime(f.root)).rejects.toThrow();
	}
});
