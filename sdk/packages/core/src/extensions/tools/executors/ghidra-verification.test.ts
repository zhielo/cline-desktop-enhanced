import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import {
	createReverseEngineeringExecutor,
	shouldRefreshEngineEnvironment,
} from "./reverse-engineering";
import {
	ghidraScriptPath,
	prepareGhidraVerification,
	verifyGhidraAnalysis,
	GHIDRA_VERIFICATION_SCRIPT,
} from "./ghidra-verification";
const roots: string[] = [];
afterEach(async () => {
	vi.unstubAllEnvs();
	await Promise.all(
		roots.splice(0).map((p) => fs.rm(p, { recursive: true, force: true })),
	);
});
async function root() {
	const p = await fs.mkdtemp(path.join(tmpdir(), "ghidra-regression-"));
	roots.push(p);
	return p;
}
it("uses semicolons on every OS and rejects ambiguous script directories", () => {
	expect(ghidraScriptPath(["/one", "/two", "/one"])).toBe("/one;/two");
	expect(ghidraScriptPath(["C:\\one", "D:\\two"])).toBe("C:\\one;D:\\two");
	expect(() => ghidraScriptPath(["/one;injected"])).toThrow("semicolons");
});
it("requires a real project repository and fresh fingerprint-bound completed receipt", async () => {
	const dir = await root(),
		hash = "a".repeat(64),
		project = path.join(dir, "owned.gpr"),
		v = await prepareGhidraVerification(dir, hash);
	expect(await verifyGhidraAnalysis(project, v, hash)).toBe(false);
	// Real Ghidra .gpr files are zero-byte markers, not the project database.
	await fs.writeFile(project, "");
	await fs.mkdir(path.join(dir, "owned.rep"));
	const properties = path.join(dir, "owned.rep", "project.prp");
	await fs.writeFile(properties, "owned properties");
	const receipt = {
		schemaVersion: 1,
		attempt: v.attempt,
		inputSha256: hash,
		programName: "owned",
		analysisCompleted: true,
	};
	await fs.writeFile(v.receipt, JSON.stringify(receipt));
	expect(await verifyGhidraAnalysis(project, v, hash)).toBe(true);
	for (const override of [
		{ attempt: "stale" },
		{ inputSha256: "b".repeat(64) },
		{ analysisCompleted: false },
		{ schemaVersion: 0 },
		{ programName: "" },
	]) {
		await fs.writeFile(v.receipt, JSON.stringify({ ...receipt, ...override }));
		expect(await verifyGhidraAnalysis(project, v, hash)).toBe(false);
	}
	await fs.writeFile(v.receipt, JSON.stringify(receipt));
	await fs.writeFile(properties, "");
	expect(await verifyGhidraAnalysis(project, v, hash)).toBe(false);
	await fs.writeFile(properties, "owned properties");
	await fs.writeFile(v.receipt, "x".repeat(16385));
	expect(await verifyGhidraAnalysis(project, v, hash)).toBe(false);
	await fs.writeFile(v.receipt, JSON.stringify(receipt));
	const next = await prepareGhidraVerification(dir, hash);
	expect(next.attempt).not.toBe(v.attempt);
	expect(await verifyGhidraAnalysis(project, next, hash)).toBe(false);
	expect(GHIDRA_VERIFICATION_SCRIPT).toContain("analysisTimeoutOccurred()");
	expect(GHIDRA_VERIFICATION_SCRIPT).toContain("getExecutableSHA256()");
});
const receiptMock = `mkdir -p "$1/$2.rep"; touch "$1/$2.gpr"; printf project > "$1/$2.rep/project.prp"
( while [ "$#" -gt 0 ]; do if [ "$1" = "ClineVerifyAnalysis.java" ]; then printf '{"schemaVersion":1,"attempt":"%s","inputSha256":"%s","programName":"owned","analysisCompleted":true}' "$3" "$4" > "$2"; break; fi; shift; done )`;
async function mock(body: string) {
	const dir = await root(),
		home = path.join(dir, "ghidra");
	await fs.mkdir(path.join(home, "support"), { recursive: true });
	const launcher = path.join(home, "support", "analyzeHeadless");
	await fs.writeFile(launcher, `#!/bin/sh\nset -eu\n${body}\n`);
	await fs.chmod(launcher, 0o700);
	vi.stubEnv("GHIDRA_HOME", home);
	vi.stubEnv("CLINE_GHIDRA_SELECTED_HOME", home);
	const target = path.join(dir, "original.bin");
	await fs.writeFile(target, "owned mock fixture");
	const execute = createReverseEngineeringExecutor();
	return {
		dir,
		target,
		run: async (extra: Record<string, unknown> = {}) =>
			JSON.parse(
				await execute(
					{
						engine: "ghidra",
						operation: "analyze",
						target,
						output_directory: path.join(dir, "output"),
						...extra,
					},
					{} as never,
				),
			),
	};
}
it.skipIf(process.platform === "win32")(
	"rejects zero exit without project or receipt",
	async () => {
		const f = await mock("exit 0"),
			r = await f.run();
		expect(r.exitCode).toBe(0);
		expect(r.databaseVerified).toBe(false);
		expect(r.artifactVerified).toBe(false);
		expect(r.succeeded).toBe(false);
	},
);
it.skipIf(process.platform === "win32")(
	"reimports renamed identical input and respects disabled reuse",
	async () => {
		const f = await mock(receiptMock);
		expect((await f.run()).succeeded).toBe(true);
		expect((await f.run()).reusedAnalysis).toBe(true);
		const renamed = path.join(f.dir, "renamed.bin");
		await fs.copyFile(f.target, renamed);
		const r = await f.run({ target: renamed });
		expect(r.succeeded).toBe(true);
		expect(r.reusedAnalysis).toBe(false);
		expect(r.args).toContain("-import");
		expect(
			(await f.run({ target: renamed, reuse_analysis: false })).reusedAnalysis,
		).toBe(false);
	},
);
it.skipIf(process.platform === "win32")(
	"rejects reported script errors even with project and receipt",
	async () => {
		const f = await mock(
				receiptMock + '\nprintf "REPORT SCRIPT ERROR: owned failure\\n"',
			),
			r = await f.run();
		expect(r.databaseVerified).toBe(true);
		expect(r.succeeded).toBe(false);
	},
);
it.skipIf(process.platform === "win32")(
	"rejects reported auto-analysis timeout after zero exit",
	async () => {
		const f = await mock(
			receiptMock + '\nprintf "REPORT: Analysis timed out at 1 seconds\\n"',
		);
		expect((await f.run()).succeeded).toBe(false);
	},
);
it.skipIf(process.platform === "win32")(
	"does not fall back from explicitly selected missing installation",
	async () => {
		const f = await mock(receiptMock);
		vi.stubEnv("CLINE_GHIDRA_SELECTED_HOME", path.join(f.dir, "missing"));
		const r = await f.run().catch((e) => ({ error: String(e) }));
		expect(r.succeeded).not.toBe(true);
	},
);

it("keeps an explicit Ghidra selection pinned against registry refresh", () => {
	vi.stubEnv("CLINE_GHIDRA_SELECTED_HOME", "C:\\Owned Ghidra");
	expect(shouldRefreshEngineEnvironment("GHIDRA_HOME")).toBe(false);
	expect(shouldRefreshEngineEnvironment("GHIDRA_INSTALL_DIR")).toBe(false);
	expect(shouldRefreshEngineEnvironment("JADX_HOME")).toBe(true);
});
