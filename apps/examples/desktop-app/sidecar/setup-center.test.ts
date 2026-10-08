import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	run: vi.fn(),
	identity: vi.fn(() => ({
		source: "bundled",
		runtimeId: "owned-full",
		manifestHash: "a".repeat(64),
		integrity: "verified",
	})),
}));
vi.mock("@cline/core", () => ({
	ADVANCED_ANALYSIS_WORKER: "owned fixture worker",
	getAnalysisRuntimeIdentity: mocks.identity,
	runAdvancedAnalysis: mocks.run,
	createReverseEngineeringExecutor: vi.fn(),
}));
vi.mock("./trusted-update", () => ({
	privateUpdateReadiness: () => ({ enabled: false }),
}));

import {
	FULL_ENGINE_IDS,
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
