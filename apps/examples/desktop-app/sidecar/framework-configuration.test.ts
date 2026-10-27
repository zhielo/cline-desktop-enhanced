import { generateKeyPairSync } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { emulationConfigurationStatus } from "./emulation-client";
import { analysisSandboxConfigurationStatus } from "./analysis-sandbox-client";

const key = generateKeyPairSync("ed25519")
	.publicKey.export({ type: "spki", format: "pem" })
	.toString();
afterEach(() => vi.unstubAllEnvs());
function configure(prefix: string, endpointKey = "ENDPOINT") {
	for (const suffix of [endpointKey, "PUBLIC_KEY", "TOKEN"])
		vi.stubEnv(`${prefix}_${suffix}`, "");
}
it.each([
	"qiling",
	"unidbg",
	"rnidbg",
] as const)("reports %s configuration without networking, leaking secrets or claiming readiness", (engine) => {
	const fetcher = vi.spyOn(globalThis, "fetch");
	try {
		const prefix = `CLINE_EMULATION_${engine.toUpperCase()}`;
		configure(prefix);
		expect(emulationConfigurationStatus(engine)).toBe("not-configured");
		vi.stubEnv(`${prefix}_ENDPOINT`, "https://owned.invalid");
		expect(emulationConfigurationStatus(engine)).toBe("invalid-configuration");
		vi.stubEnv(`${prefix}_PUBLIC_KEY`, key);
		vi.stubEnv(`${prefix}_TOKEN`, "private-authentication-value-123456789");
		expect(emulationConfigurationStatus(engine)).toBe("configured-not-tested");
		for (const invalid of [
			"http://owned.invalid",
			"https://owned.invalid/path",
			"https://user:secret@owned.invalid",
		]) {
			vi.stubEnv(`${prefix}_ENDPOINT`, invalid);
			expect(emulationConfigurationStatus(engine)).toBe(
				"invalid-configuration",
			);
		}
		vi.stubEnv(`${prefix}_ENDPOINT`, "https://owned.invalid");
		vi.stubEnv(`${prefix}_PUBLIC_KEY`, "invalid-secret-key-text");
		expect(emulationConfigurationStatus(engine)).toBe("invalid-configuration");
		expect(fetcher).not.toHaveBeenCalled();
	} finally {
		fetcher.mockRestore();
	}
});
it("reports Speakeasy configuration only, including partial credentials and invalid key", () => {
	const fetcher = vi.spyOn(globalThis, "fetch");
	try {
		const prefix = "CLINE_ANALYSIS_SANDBOX";
		configure(prefix, "WORKER");
		expect(analysisSandboxConfigurationStatus()).toBe("not-configured");
		vi.stubEnv(`${prefix}_TOKEN`, "private-token");
		expect(analysisSandboxConfigurationStatus()).toBe("invalid-configuration");
		vi.stubEnv(`${prefix}_WORKER`, "https://owned.invalid");
		vi.stubEnv(`${prefix}_PUBLIC_KEY`, key);
		expect(analysisSandboxConfigurationStatus()).toBe("configured-not-tested");
		vi.stubEnv(`${prefix}_PUBLIC_KEY`, "bad-key");
		expect(analysisSandboxConfigurationStatus()).toBe("invalid-configuration");
		expect(fetcher).not.toHaveBeenCalled();
	} finally {
		fetcher.mockRestore();
	}
});
