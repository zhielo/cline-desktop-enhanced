import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import {
	bindRuntimeAnalysisRequest,
	submitAnalysisSandbox,
	RuntimeAnalysisInputSchema,
} from "./analysis-sandbox-client";
const keys = generateKeyPairSync("ed25519"),
	artifact = Buffer.from("MZ-owned-runtime-fixture");
function config() {
	process.env.CLINE_ANALYSIS_SANDBOX_WORKER = "https://worker.example.test";
	process.env.CLINE_ANALYSIS_SANDBOX_PUBLIC_KEY = keys.publicKey.export({
		type: "spki",
		format: "pem",
	}) as string;
	process.env.CLINE_ANALYSIS_SANDBOX_TOKEN = "owned-transport-token";
}
function signed(value: unknown, key = "receipt") {
	return {
		[key]: value,
		signature: sign(
			null,
			Buffer.from(JSON.stringify(value)),
			keys.privateKey,
		).toString("base64"),
	};
}
function manifest(runtime = "a".repeat(64)) {
	return signed(
		{
			workerId: "owned",
			version: "v1",
			protocol: "cline-analysis-worker/v1",
			isolation: "remote-vm",
			ephemeralSnapshots: true,
			networkModes: ["disabled"],
			maxArtifactBytes: 16777216,
			issuedAt: new Date().toISOString(),
			expiresAt: new Date(Date.now() + 120000).toISOString(),
			operations: ["speakeasy-windows-emulation"],
			runtimeSha256: runtime,
		},
		"manifest",
	);
}
afterEach(() => {
	for (const name of [
		"CLINE_ANALYSIS_SANDBOX_WORKER",
		"CLINE_ANALYSIS_SANDBOX_PUBLIC_KEY",
		"CLINE_ANALYSIS_SANDBOX_TOKEN",
	])
		delete process.env[name];
});
describe("separately approved Speakeasy transport", () => {
	it("binds operation, runtime, worker and uploaded bytes", async () => {
		config();
		let posts = 0;
		const transport = async (
			input: string | URL | Request,
			init?: RequestInit,
		) => {
			if (String(input).endsWith("capabilities"))
				return new Response(JSON.stringify(manifest()));
			posts++;
			expect((init?.headers as Record<string, string>).authorization).toBe(
				"Bearer owned-transport-token",
			);
			const job = JSON.parse(String(init?.body));
			expect(job.operation).toBe("emulate_windows");
			expect(job.symbol).toBeUndefined();
			return new Response(
				JSON.stringify(
					signed({
						protocol: "cline-analysis-job/v1",
						workerId: "owned",
						nonce: job.nonce,
						requestHash: job.requestHash,
						artifactSha256: createHash("sha256").update(artifact).digest("hex"),
						network: "disabled",
						status: "partial",
						engine: "speakeasy",
						runtimeSha256: "a".repeat(64),
						evidence: {},
						limitations: ["modeled behavior"],
					}),
				),
			);
		};
		const request = await bindRuntimeAnalysisRequest(
			RuntimeAnalysisInputSchema.parse({
				operation: "emulate_windows",
				target: "/owned.exe",
			}),
			transport,
		);
		expect(
			(
				await submitAnalysisSandbox(
					request,
					artifact,
					"b".repeat(64),
					undefined,
					transport,
				)
			).status,
		).toBe("partial");
		expect(posts).toBe(1);
	});
	it("rejects a changed runtime before uploading", async () => {
		config();
		let posts = 0;
		const request = await bindRuntimeAnalysisRequest(
			RuntimeAnalysisInputSchema.parse({
				operation: "emulate_windows",
				target: "/owned.exe",
			}),
			async () => new Response(JSON.stringify(manifest())),
		);
		await expect(
			submitAnalysisSandbox(
				request,
				artifact,
				"b".repeat(64),
				undefined,
				async (_i, init) => {
					if (init?.method === "POST") posts++;
					return new Response(JSON.stringify(manifest("c".repeat(64))));
				},
			),
		).rejects.toThrow(/runtime changed/);
		expect(posts).toBe(0);
	});
	it("requires authentication and rejects arbitrary scripts, network or exports", async () => {
		config();
		delete process.env.CLINE_ANALYSIS_SANDBOX_TOKEN;
		await expect(
			bindRuntimeAnalysisRequest(
				RuntimeAnalysisInputSchema.parse({
					operation: "emulate_windows",
					target: "/owned.exe",
				}),
				async () => new Response(JSON.stringify(manifest())),
			),
		).rejects.toThrow(/authenticated/);
		for (const extra of [
			{ script: "arbitrary" },
			{ network: "recorded" },
			{ symbol: "export" },
		])
			expect(
				RuntimeAnalysisInputSchema.safeParse({
					operation: "emulate_windows",
					target: "/owned.exe",
					...extra,
				}).success,
			).toBe(false);
	});
	it("never submits an already cancelled job", async () => {
		config();
		const c = new AbortController();
		c.abort();
		let n = 0;
		await expect(
			submitAnalysisSandbox(
				RuntimeAnalysisInputSchema.parse({
					operation: "emulate_windows",
					target: "/owned.exe",
				}),
				artifact,
				"b".repeat(64),
				c.signal,
				async () => {
					n++;
					return new Response();
				},
			),
		).rejects.toThrow(/Cancelled/);
		expect(n).toBe(0);
	});
});

it("rejects a signed receipt for another engine, input or nonce", async () => {
	config();
	for (const change of [
		{ engine: "qbdi" },
		{ artifactSha256: "f".repeat(64) },
		{ nonce: "f".repeat(32) },
		{ runtimeSha256: "c".repeat(64) },
	]) {
		const transport = async (
			input: string | URL | Request,
			init?: RequestInit,
		) => {
			if (String(input).endsWith("capabilities"))
				return new Response(JSON.stringify(manifest()));
			const job = JSON.parse(String(init?.body));
			return new Response(
				JSON.stringify(
					signed({
						protocol: "cline-analysis-job/v1",
						workerId: "owned",
						nonce: job.nonce,
						requestHash: job.requestHash,
						artifactSha256: createHash("sha256").update(artifact).digest("hex"),
						network: "disabled",
						status: "partial",
						engine: "speakeasy",
						runtimeSha256: "a".repeat(64),
						evidence: {},
						limitations: [],
						...change,
					}),
				),
			);
		};
		const request = await bindRuntimeAnalysisRequest(
			RuntimeAnalysisInputSchema.parse({
				operation: "emulate_windows",
				target: "/owned.exe",
			}),
			transport,
		);
		await expect(
			submitAnalysisSandbox(
				request,
				artifact,
				"b".repeat(64),
				undefined,
				transport,
			),
		).rejects.toThrow();
	}
});
