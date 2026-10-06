import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { elf, manifest, zip } from "./__fixtures__/incident";
import { digest } from "./incident-artifacts";
import { correlateIncident, elfIdentity } from "./incident-correlation";
import { incidentReadiness, ownedFixtureRows } from "./incident-readiness";

it("keeps ambiguous mappings unresolved and refuses mismatched builds", async () => {
	const root = await mkdtemp(join(tmpdir(), "incident-mapping-"));
	try {
		const bytes = Buffer.from(
				"example.Real -> a.b:\n    void first() -> c\n    void second() -> c\n",
			),
			hash = "a".repeat(64);
		await writeFile(join(root, "mapping.txt"), bytes);
		const input = {
			kind: "java",
			apkSha256: hash,
			mapping: "mapping.txt",
			mappingSha256: digest(bytes),
			className: "a.b",
			method: "c",
		};
		const r = await correlateIncident(
			root,
			{ operation: "observe_apk", target_sha256: hash, target: "observed.apk" },
			input,
		);
		expect(r.status).toBe("unresolved");
		expect(r.candidates).toHaveLength(2);
		await expect(
			correlateIncident(
				root,
				{
					operation: "observe_apk",
					target_sha256: hash,
					target: "observed.apk",
				},
				{ ...input, apkSha256: "b".repeat(64) },
			),
		).rejects.toThrow("observed build");
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
it("checks native identity/ranges and leaves stripped functions unresolved", async () => {
	const root = await mkdtemp(join(tmpdir(), "incident-elf-"));
	try {
		const bytes = elf(),
			container = zip([
				{ name: "AndroidManifest.xml", bytes: manifest() },
				{ name: "lib/arm64-v8a/libfixture.so", bytes },
			]),
			hash = digest(container);
		await writeFile(join(root, "observed.apk"), container);
		await writeFile(join(root, "libfixture.so"), bytes);
		expect(elfIdentity(bytes).buildIds).toEqual(["78563412"]);
		const input = {
			kind: "native",
			apkSha256: hash,
			module: "libfixture.so",
			moduleSha256: digest(bytes),
			buildId: "78563412",
			abi: "arm64-v8a",
			pc: "0x1010",
		};
		const r = await correlateIncident(
			root,
			{ operation: "observe_apk", target_sha256: hash, target: "observed.apk" },
			input,
		);
		expect(r.status).toBe("unresolved");
		expect(r.fileOffset).toBe(16);
		await expect(
			correlateIncident(
				root,
				{
					operation: "observe_apk",
					target_sha256: hash,
					target: "observed.apk",
				},
				{ ...input, buildId: "00000000" },
			),
		).rejects.toThrow("mismatch");
		await expect(
			correlateIncident(
				root,
				{
					operation: "observe_apk",
					target_sha256: hash,
					target: "observed.apk",
				},
				{ ...input, pc: "0x2000" },
			),
		).rejects.toThrow("file-backed");
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
it("never promotes installed decompilers to execution-verified", () => {
	const r = incidentReadiness(
		{
			capabilities: {
				ida: { headless: "idat.exe" },
				ghidra: {},
				jadx: { cli: "jadx" },
			},
		},
		{
			version: "Android Debug Bridge version 1.0.41",
			versionExitCode: 0,
			devicesExitCode: 0,
			incomplete: false,
		},
		undefined,
	);
	expect(r.rows.find((row) => row.tool === "ida")?.state).toBe("installed");
	expect(r.rows.find((row) => row.tool === "ghidra")?.state).toBe("blocked");
	expect(r.rows.find((row) => row.tool === "adb")?.state).toBe(
		"execution-verified",
	);
	expect(r.rows.find((row) => row.tool === "Frida")?.state).toBe("unverified");
});

it("marks fixture checks verified only with scoped execution evidence", () => {
	expect(
		ownedFixtureRows({
			result: {
				result: {
					evidence: {
						checks: [
							{
								engine: "lief",
								status: "completed",
								executionVerified: true,
								scope: "owned-static-fixture-only",
							},
							{ engine: "ida", status: "completed", executionVerified: false },
						],
					},
				},
			},
		}).map((r) => r.state),
	).toEqual(["execution-verified", "blocked"]);
});
