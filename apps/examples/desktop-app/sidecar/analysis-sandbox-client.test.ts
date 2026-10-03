import { generateKeyPairSync, sign } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { probeAnalysisSandbox } from "./analysis-sandbox-client";

afterEach(() => {
	delete process.env.CLINE_ANALYSIS_SANDBOX_WORKER;
	delete process.env.CLINE_ANALYSIS_SANDBOX_PUBLIC_KEY;
});

describe("analysis sandbox attestation", () => {
	it("requires HTTPS and a pinned public key", async () => {
		process.env.CLINE_ANALYSIS_SANDBOX_WORKER = "http://localhost:8080";
		expect(await probeAnalysisSandbox()).toMatchObject({
			configured: true,
			ready: false,
		});
	});

	it("accepts a signed, ephemeral, default-deny worker manifest", async () => {
		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		process.env.CLINE_ANALYSIS_SANDBOX_WORKER = "https://sandbox.example.test";
		process.env.CLINE_ANALYSIS_SANDBOX_PUBLIC_KEY = publicKey.export({
			type: "spki",
			format: "pem",
		}) as string;
		const manifest = {
			workerId: "worker-1",
			version: "1.0.0",
			protocol: "cline-analysis-worker/v1",
			isolation: "remote-vm",
			ephemeralSnapshots: true,
			networkModes: ["disabled"],
			maxArtifactBytes: 1024,
			issuedAt: new Date().toISOString(),
			expiresAt: new Date(Date.now() + 60_000).toISOString(),
		};
		const signature = sign(
			null,
			Buffer.from(JSON.stringify(manifest)),
			privateKey,
		).toString("base64");
		const health = await probeAnalysisSandbox(
			async () =>
				new Response(JSON.stringify({ manifest, signature }), {
					status: 200,
					headers: { "content-type": "application/json" },
				}),
		);
		expect(health).toMatchObject({
			configured: true,
			ready: true,
			manifest: { workerId: "worker-1" },
		});
	});
});
