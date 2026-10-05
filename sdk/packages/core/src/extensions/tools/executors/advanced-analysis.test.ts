import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createReverseEngineeringExecutor } from "./reverse-engineering";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { describe, it, expect, vi, afterEach } from "vitest";
const mock = vi.hoisted(() => vi.fn());
vi.mock("node:child_process", () => ({ spawn: mock }));
import {
	runAdvancedAnalysis,
	advancedEvidenceBundle,
} from "./advanced-analysis";
import { ReverseEngineeringInputSchema } from "../schemas";
afterEach(() => {
	mock.mockReset();
	vi.unstubAllEnvs();
});
const evidence = {
	protocol: "cline-advanced-analysis/v1",
	status: "completed",
	engine: "builtin",
	engineVersion: "1",
	evidence: {},
	limitations: [],
};
function fake(body: string) {
	mock.mockImplementation(() => {
		const child = Object.assign(new EventEmitter(), {
			stdout: new PassThrough(),
			stderr: new PassThrough(),
			kill: vi.fn(),
			pid: undefined,
		});
		process.nextTick(() => {
			child.stdout.write(body);
			child.emit("close", 0);
		});
		return child;
	});
}
describe("advanced worker contracts", () => {
	it("blocks runtime and licensed actions without process launch", async () => {
		for (const action of [
			"trace_native_region",
			"jeb_analysis",
			"virtual_dispatch",
		] as const)
			expect((await runAdvancedAnalysis({ action })).status).toBe("blocked");
		expect(mock).not.toHaveBeenCalled();
	});
	it("cancels before launching", async () => {
		const c = new AbortController();
		c.abort();
		expect(
			(await runAdvancedAnalysis({ action: "toolchain" }, c.signal)).status,
		).toBe("cancelled");
		expect(mock).not.toHaveBeenCalled();
	});
	it("rejects relative inputs", async () => {
		await expect(
			runAdvancedAnalysis({ action: "triage", target: "x" }),
		).rejects.toThrow("Absolute");
	});
	it("requires an absolute configured interpreter", async () => {
		vi.stubEnv("CLINE_RE_PYTHON", "python-local");
		await expect(runAdvancedAnalysis({ action: "toolchain" })).rejects.toThrow(
			"absolute interpreter",
		);
	});
	it("filters inherited credentials", async () => {
		vi.stubEnv("OPENAI_API_KEY", "fixture-private-value");
		fake(JSON.stringify(evidence));
		expect((await runAdvancedAnalysis({ action: "toolchain" })).status).toBe(
			"completed",
		);
		expect(mock.mock.calls[0][2].env.OPENAI_API_KEY).toBeUndefined();
		expect(mock.mock.calls[0][1][0]).toBe("-I");
	});
	it("fails closed on malformed output", async () => {
		fake("not-json");
		expect((await runAdvancedAnalysis({ action: "toolchain" })).status).toBe(
			"failed",
		);
	});
	it("preserves blocked engine status", async () => {
		fake(JSON.stringify({ ...evidence, status: "blocked" }));
		expect((await runAdvancedAnalysis({ action: "toolchain" })).status).toBe(
			"blocked",
		);
	});
	it("bounds worker output", async () => {
		fake("x".repeat(1024 * 1024 + 1));
		expect((await runAdvancedAnalysis({ action: "toolchain" })).status).toBe(
			"failed",
		);
	});
	it("rejects arbitrary advanced options", () => {
		expect(() =>
			ReverseEngineeringInputSchema.parse({
				operation: "advanced_analysis",
				advanced_options: { script: "bad" },
			}),
		).toThrow();
	});
	it("hashes bounded evidence reproducibly", () => {
		const first = advancedEvidenceBundle("triage", evidence as never);
		expect(first.resultSha256).toBe(
			advancedEvidenceBundle("triage", evidence as never).resultSha256,
		);
		expect(first.resultSha256).not.toBe(
			advancedEvidenceBundle("suite", evidence as never).resultSha256,
		);
	});
});

const cryptoDirectories: string[] = [];
afterEach(async () => {
	await Promise.all(
		cryptoDirectories
			.splice(0)
			.map((dir) => rm(dir, { recursive: true, force: true })),
	);
});
async function cryptoFixture() {
	const dir = await mkdtemp(join(tmpdir(), "crypto-host-test-"));
	cryptoDirectories.push(dir);
	const key = join(dir, "host-private-key.raw");
	await writeFile(key, Buffer.alloc(32, 7), { mode: 0o600 });
	const target = join(dir, "owned-ciphertext.bin");
	await writeFile(target, Buffer.alloc(32, 1));
	return { key, target };
}
const decryptOptions = {
	decrypt: { algorithm: "aes-256-gcm" as const, nonce_hex: "0".repeat(24) },
};
describe("known-key host decryption boundary", () => {
	it("does not launch without explicit host enablement", async () => {
		expect(
			(await runAdvancedAnalysis({ action: "decrypt_blob" })).evidence.reason,
		).toContain("Host has not enabled");
		expect(mock).not.toHaveBeenCalled();
	});
	it("requires a trusted absolute interpreter", async () => {
		const f = await cryptoFixture();
		vi.stubEnv("CLINE_RE_ALLOW_DECRYPTION", "1");
		vi.stubEnv("CLINE_RE_PRIVATE_KEY_FILE", f.key);
		vi.stubEnv("CLINE_RE_PYTHON", "");
		expect(
			(await runAdvancedAnalysis({ action: "decrypt_blob", target: f.target }))
				.status,
		).toBe("blocked");
		expect(mock).not.toHaveBeenCalled();
	});
	it("grants only a key-file path, never key bytes in arguments", async () => {
		const f = await cryptoFixture();
		vi.stubEnv("CLINE_RE_ALLOW_DECRYPTION", "1");
		vi.stubEnv("CLINE_RE_PRIVATE_KEY_FILE", f.key);
		vi.stubEnv("CLINE_RE_PYTHON", process.execPath);
		fake(JSON.stringify(evidence));
		expect(
			(
				await runAdvancedAnalysis({
					action: "decrypt_blob",
					target: f.target,
					options: decryptOptions,
				})
			).status,
		).toBe("completed");
		const call = mock.mock.calls[0];
		expect(call[2].env.CLINE_RE_PRIVATE_KEY_FILE).toBe(f.key);
		expect(call[1].join(" ")).not.toContain(f.key);
		expect(call[1].join(" ")).not.toContain(
			Buffer.alloc(32, 7).toString("hex"),
		);
	});
	it("withholds the private-key grant from other operations", async () => {
		const f = await cryptoFixture();
		vi.stubEnv("CLINE_RE_ALLOW_DECRYPTION", "1");
		vi.stubEnv("CLINE_RE_PRIVATE_KEY_FILE", f.key);
		fake(JSON.stringify(evidence));
		await runAdvancedAnalysis({ action: "toolchain" });
		expect(mock.mock.calls[0][2].env.CLINE_RE_PRIVATE_KEY_FILE).toBeUndefined();
	});
	it("rejects short keys before launch", async () => {
		const f = await cryptoFixture();
		await writeFile(f.key, "short");
		vi.stubEnv("CLINE_RE_ALLOW_DECRYPTION", "1");
		vi.stubEnv("CLINE_RE_PRIVATE_KEY_FILE", f.key);
		vi.stubEnv("CLINE_RE_PYTHON", process.execPath);
		expect(
			(await runAdvancedAnalysis({ action: "decrypt_blob", target: f.target }))
				.status,
		).toBe("blocked");
		expect(mock).not.toHaveBeenCalled();
	});
	it("rejects key material in the public input schema", () => {
		expect(() =>
			ReverseEngineeringInputSchema.parse({
				operation: "advanced_analysis",
				advanced_action: "decrypt_blob",
				advanced_options: {
					decrypt: { ...decryptOptions.decrypt, key_hex: "secret" },
				},
			}),
		).toThrow();
		expect(() =>
			ReverseEngineeringInputSchema.parse({
				operation: "advanced_analysis",
				advanced_action: "decrypt_blob",
				advanced_options: {
					decrypt: { algorithm: "aes-256-gcm", nonce_hex: "short" },
				},
			}),
		).toThrow();
	});
	it("does not silently accept plaintext export requests", async () => {
		await expect(
			createReverseEngineeringExecutor()(
				{
					operation: "advanced_analysis",
					advanced_action: "decrypt_blob",
					output_file: "/arbitrary-plaintext.bin",
				} as never,
				{} as never,
			),
		).rejects.toThrow("Plaintext export is not enabled");
		expect(mock).not.toHaveBeenCalled();
	});
});
