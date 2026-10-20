import arm64Fixture from "../../../../scripts/fixtures/owned-arm64-elf.json";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	run: vi.fn(),
	executor: vi.fn(),
	identity: vi.fn(() => ({
		source: "bundled",
		runtimeId: "owned-full",
		manifestHash: "a".repeat(64),
		integrity: "verified",
	})),
}));
vi.mock("@cline/core", () => ({
	ADVANCED_ANALYSIS_WORKER: "owned fixture worker",
	prepareProcessEnvironment: () => ({ secretValues: [] }),
	redactSensitiveText: (value: string) => value,
	getAnalysisRuntimeIdentity: mocks.identity,
	runAdvancedAnalysis: mocks.run,
	createReverseEngineeringExecutor: () => mocks.executor,
}));
vi.mock("./trusted-update", () => ({
	privateUpdateReadiness: () => ({ enabled: false }),
}));

import {
	FULL_ENGINE_IDS,
	testGhidraIntegration,
	currentGhidraAcceptance,
	testLicensedIda,
	saveSetupPreferences,
	currentIdaAcceptance,
	hashIdaExecutable,
	fullReceiptPassed,
	getSetupCenterStatus,
	testFullCapabilityPack,
	validateSetupPreferences,
} from "./setup-center";

const roots: string[] = [];
afterEach(async () => {
	vi.unstubAllEnvs();
	mocks.run.mockReset();
	await Promise.all(
		roots.splice(0).map((p) => rm(p, { recursive: true, force: true })),
	);
});
const base = {
	schemaVersion: 1,
	idaHome: "",
	adbPath: "",
	deviceSerial: "",
	deviceKind: "physical",
	workerEndpoint: "",
	workerPublicKey: "",
};
it("requires all eleven distinct actual execution receipts, never inventory", () => {
	const checks = FULL_ENGINE_IDS.map((engine) => ({
		engine,
		status: "completed",
		executionVerified: true,
	}));
	expect(fullReceiptPassed(checks)).toBe(true);
	expect(fullReceiptPassed(checks.slice(1))).toBe(false);
	expect(fullReceiptPassed([...checks, checks[0]!])).toBe(false);
	expect(
		fullReceiptPassed(checks.map((c) => ({ ...c, executionVerified: false }))),
	).toBe(false);
	expect(fullReceiptPassed([...checks.slice(1), checks[1]!])).toBe(false);
});
it("rejects relative installations, worker credentials, half configuration and private keys", () => {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	const key = publicKey.export({ type: "spki", format: "pem" }).toString();
	expect(
		validateSetupPreferences({
			...base,
			workerEndpoint: "https://owned.example/",
			workerPublicKey: key,
		}).workerEndpoint,
	).toBe("https://owned.example/");
	for (const input of [
		{ idaHome: "relative" },
		{ ghidraHome: "relative" },
		{ adbPath: "adb.exe" },
		{ workerEndpoint: "https://owned.example/" },
		{ workerEndpoint: "http://owned.example/", workerPublicKey: key },
		{
			workerEndpoint: "https://user:pass@owned.example/",
			workerPublicKey: key,
		},
		{
			workerEndpoint: "https://owned.example/?token=secret",
			workerPublicKey: key,
		},
		{
			workerEndpoint: "https://owned.example/",
			workerPublicKey: privateKey
				.export({ type: "pkcs8", format: "pem" })
				.toString(),
		},
	])
		expect(() => validateSetupPreferences({ ...base, ...input })).toThrow();
});
it("coalesces actual full and separate angr tests and invalidates changed runtime receipts", async () => {
	const root = await mkdtemp(join(tmpdir(), "owned-setup-"));
	roots.push(root);
	vi.stubEnv("CLINE_DATA_DIR", root);
	mocks.run.mockImplementation(async ({ action }) =>
		action === "full_readiness"
			? {
					status: "completed",
					evidence: {
						checks: FULL_ENGINE_IDS.filter((id) => id !== "angr").map(
							(engine) => ({
								engine,
								status: "completed",
								executionVerified: true,
							}),
						),
					},
				}
			: {
					status: "completed",
					engineVersion: "9.2.185",
					evidence: { hostExecution: false },
				},
	);
	const [a, b] = await Promise.all([
		testFullCapabilityPack(),
		testFullCapabilityPack(),
	]);
	expect(a).toEqual(b);
	expect(mocks.run).toHaveBeenCalledTimes(2);
	expect((await getSetupCenterStatus()).fullStatus).toBe("Ready");
	vi.stubEnv("CLINE_ANGR_RUNTIME_ID", "changed-owned-runtime");
	expect((await getSetupCenterStatus()).fullStatus).toBe("Setup needed");
	expect(
		(await getSetupCenterStatus()).features.every((f) => f.state === "stale"),
	).toBe(true);
	expect((await getSetupCenterStatus()).lastCheckedAt).toBeDefined();
});
it("missing angr never produces full Ready", async () => {
	const root = await mkdtemp(join(tmpdir(), "owned-setup-missing-"));
	roots.push(root);
	vi.stubEnv("CLINE_DATA_DIR", root);
	mocks.run.mockResolvedValue({
		status: "blocked",
		evidence: { reason: "Missing required engine" },
	});
	await testFullCapabilityPack();
	expect((await getSetupCenterStatus()).fullStatus).toBe("Setup needed");
});

it("ARM64 acceptance uses a fixed owned fixture and invalidates replacement of the same IDA executable", async () => {
	const root = await mkdtemp(join(tmpdir(), "ida-setup-"));
	roots.push(root);
	vi.stubEnv("CLINE_DATA_DIR", root);
	vi.stubEnv("IDA_HOME", process.env.IDA_HOME ?? "");
	vi.stubEnv(
		"CLINE_IDA_SELECTED_HOME",
		process.env.CLINE_IDA_SELECTED_HOME ?? "",
	);
	const home = join(root, "ida");
	await mkdir(home);
	const executable = join(home, "idat.exe");
	await writeFile(executable, "owned executable identity");
	await saveSetupPreferences({ ...base, idaHome: home });
	const digest = await hashIdaExecutable(executable, home);
	mocks.executor.mockResolvedValue(
		JSON.stringify({
			succeeded: true,
			artifactVerified: true,
			sha256: arm64Fixture.sha256,
			engineExecutable: { path: executable, sha256: digest },
		}),
	);
	const receipt = await testLicensedIda("arm64");
	expect(receipt.status).toBe("passed");
	expect(receipt.architecture).toBe("arm64");
	expect(mocks.executor.mock.calls.at(-1)?.[0].function_selector.address).toBe(
		"0x1000",
	);
	const target = mocks.executor.mock.calls.at(-1)?.[0].target;
	const bytes = await import("node:fs/promises").then((fs) =>
		fs.readFile(target),
	);
	expect(bytes.readUInt16LE(18)).toBe(183);
	expect(await currentIdaAcceptance(receipt, home)).toBe(true);
	expect(await currentIdaAcceptance(receipt, home, "x86_64")).toBe(false);
	expect(
		await currentIdaAcceptance(
			{ ...receipt, fixtureSha256: "f".repeat(64) },
			home,
			"arm64",
		),
	).toBe(false);
	expect((await getSetupCenterStatus()).licensedArchitectures).toEqual([
		"arm64",
	]);
	await writeFile(executable, "replacement at same path");
	expect(await currentIdaAcceptance(receipt, home)).toBe(false);
	expect((await getSetupCenterStatus()).licensedArchitectures).toEqual([]);
	await expect(
		hashIdaExecutable(executable, join(root, "not-selected")),
	).rejects.toThrow();
});

async function ownedGhidraSetup() {
	const root = await mkdtemp(join(tmpdir(), "owned-ghidra-setup-"));
	roots.push(root);
	vi.stubEnv("CLINE_DATA_DIR", root);
	vi.stubEnv("GHIDRA_HOME", process.env.GHIDRA_HOME ?? "");
	vi.stubEnv(
		"CLINE_GHIDRA_SELECTED_HOME",
		process.env.CLINE_GHIDRA_SELECTED_HOME ?? "",
	);
	const home = join(root, "ghidra"),
		javaHome = join(root, "jdk");
	await mkdir(join(home, "support"), { recursive: true });
	await mkdir(join(home, "Ghidra"));
	await mkdir(join(javaHome, "bin"), { recursive: true });
	await writeFile(
		join(
			home,
			"support",
			process.platform === "win32" ? "analyzeHeadless.bat" : "analyzeHeadless",
		),
		"owned launcher",
	);
	await writeFile(
		join(home, "Ghidra", "application.properties"),
		"application.version=12.1.4",
	);
	await writeFile(
		join(home, "support", "launch.properties"),
		"JAVA_HOME_OVERRIDE=",
	);
	const java = join(
		javaHome,
		"bin",
		process.platform === "win32" ? "java.exe" : "java",
	);
	await writeFile(java, "owned java");
	await saveSetupPreferences({ ...base, ghidraHome: home });
	return { home, javaHome, java };
}
it("Ghidra readiness requires explicit decompilation and invalidates changed Java/configuration", async () => {
	const { home, javaHome, java } = await ownedGhidraSetup();
	const before = await getSetupCenterStatus();
	expect(before.ghidra.status).toBe("Not tested or stale");
	const fixture = await import(
		"../../../../scripts/fixtures/owned-native-elf.json"
	);
	mocks.executor.mockImplementation(async (input) => {
		await mkdir(input.output_directory, { recursive: true });
		await writeFile(
			join(input.output_directory, "ghidra-analysis-receipt.json"),
			JSON.stringify({ javaHome, javaVersion: "21-owned" }),
		);
		return JSON.stringify({
			succeeded: true,
			artifactVerified: true,
			databaseVerified: true,
			sha256: fixture.sha256,
			engineVersion: "12.1.4",
		});
	});
	const receipt = await testGhidraIntegration();
	expect(receipt.status).toBe("passed");
	expect(await currentGhidraAcceptance(receipt, home)).toBe(true);
	expect((await getSetupCenterStatus()).ghidra.status).toBe("Ready");
	await writeFile(java, "changed java");
	expect(await currentGhidraAcceptance(receipt, home)).toBe(false);
	await writeFile(java, "owned java");
	await writeFile(
		join(home, "support", "launch.properties"),
		"JAVA_HOME_OVERRIDE=changed",
	);
	expect(await currentGhidraAcceptance(receipt, home)).toBe(false);
	mocks.executor.mockReset();
});
it("persists failed Ghidra/Java acceptance without claiming Ready", async () => {
	await ownedGhidraSetup();
	mocks.executor.mockResolvedValue(
		JSON.stringify({ succeeded: false, stdout: "No compatible JDK" }),
	);
	await expect(testGhidraIntegration()).rejects.toThrow("No compatible JDK");
	const status = await getSetupCenterStatus();
	expect(status.ghidra.status).toBe("Test failed");
	expect(status.ghidra.reason).toContain("No compatible JDK");
	mocks.executor.mockReset();
});
