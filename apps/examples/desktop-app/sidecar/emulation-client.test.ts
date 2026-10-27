import { generateKeyPairSync, sign } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { EMULATION_PROFILE_SHA256 } from "@cline/core";
import {
	bindEmulationRequest,
	submitEmulation,
	probeEmulation,
	EmulationRuntimeSchema,
} from "./emulation-client";
const owner = "11111111-1111-4111-8111-111111111111",
	runtime = "a".repeat(64);
const request = {
	operation: "emulate_profile",
	target: "/owned.elf",
	engine: "qiling",
	architecture: "x86_64",
	scenario: { kind: "entry", expectedExit: 7 },
	instruction_limit: 10000,
	timeout_ms: 1000,
	owner_session_id: owner,
	analysis_mode: "runtime",
};
afterEach(() => {
	for (const k of Object.keys(process.env))
		if (
			k.startsWith("CLINE_EMULATION_") ||
			k.startsWith("CLINE_ANALYSIS_SANDBOX_")
		)
			delete process.env[k];
});
function worker(engine = "qiling") {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519"),
		prefix = `CLINE_EMULATION_${engine.toUpperCase()}`;
	process.env[`${prefix}_ENDPOINT`] = `https://${engine}.owned.invalid`;
	process.env[`${prefix}_PUBLIC_KEY`] = publicKey.export({
		type: "spki",
		format: "pem",
	}) as string;
	process.env[`${prefix}_TOKEN`] = "t".repeat(40);
	let patch: Record<string, unknown> = {};
	let manifestPatch: Record<string, unknown> = {};
	const signed = (name: string, value: unknown) =>
		new Response(
			JSON.stringify({
				[name]: value,
				signature: sign(
					null,
					Buffer.from(JSON.stringify(value)),
					privateKey,
				).toString("base64"),
			}),
		);
	const fetcher = vi.fn(async (_url: unknown, init?: RequestInit) => {
		if (init?.method !== "POST")
			return signed("manifest", {
				workerId: "owned-" + engine,
				version: "owned-v1",
				protocol: "cline-analysis-worker/v1",
				isolation: "remote-vm",
				ephemeralSnapshots: true,
				networkModes: ["disabled"],
				maxArtifactBytes: 16777216,
				issuedAt: new Date().toISOString(),
				expiresAt: new Date(Date.now() + 60000).toISOString(),
				operations: ["emulate-profile-" + engine],
				engine,
				profileSha256: EMULATION_PROFILE_SHA256,
				architectures:
					engine === "qiling"
						? ["x86_64", "arm32", "arm64"]
						: engine === "unidbg"
							? ["arm32", "arm64"]
							: ["arm64"],
				runtimeSha256: runtime,
				isolationClaim: "operator-provisioned-not-hardware-attested",
				...manifestPatch,
			});
		const b = JSON.parse(String(init.body));
		return signed("receipt", {
			protocol: b.protocol,
			workerId: "owned-" + engine,
			nonce: b.nonce,
			requestHash: b.requestHash,
			artifactSha256: b.artifactSha256,
			network: b.network,
			status: "partial",
			engine,
			runtimeSha256: runtime,
			profileSha256: b.profileSha256,
			architecture: b.architecture,
			scenario: b.scenario,
			instructionLimit: b.instructionLimit,
			evidence: { outcome: "unverified", scenarioCheck: "passed" },
			limitations: ["Owned transport fixture, not real emulation"],
			...patch,
		});
	});
	return {
		fetcher: fetcher as unknown as typeof fetch,
		mock: fetcher,
		manifestPatch: (v: Record<string, unknown>) => {
			manifestPatch = v;
		},
		patch: (v: Record<string, unknown>) => {
			patch = v;
		},
	};
}
it("keeps engine registrations independent and never borrows Speakeasy configuration", async () => {
	process.env.CLINE_ANALYSIS_SANDBOX_WORKER = "https://old.owned.invalid";
	const w = worker();
	await bindEmulationRequest(request, w.fetcher);
	await expect(probeEmulation("unidbg", w.fetcher)).rejects.toThrow(
		"independent",
	);
	expect(process.env.CLINE_ANALYSIS_SANDBOX_WORKER).toBe(
		"https://old.owned.invalid",
	);
	process.env.CLINE_EMULATION_QILING_ENDPOINT = "http://localhost";
	await expect(probeEmulation("qiling", w.fetcher)).rejects.toThrow("HTTPS");
});
it("binds signed profile, exact scenario, artifact and runtime without certifying behavior", async () => {
	const w = worker(),
		bound = await bindEmulationRequest(request, w.fetcher);
	const r = await submitEmulation(
		bound,
		Buffer.alloc(128),
		"b".repeat(64),
		undefined,
		w.fetcher,
	);
	expect(r).toMatchObject({
		status: "partial",
		engine: "qiling",
		evidence: { outcome: "unverified" },
	});
	for (const patch of [
		{ runtimeSha256: "c".repeat(64) },
		{ engine: "rnidbg" },
		{ scenario: { kind: "entry", expectedExit: 8 } },
		{ instructionLimit: 1 },
		{ status: "completed" },
		{ evidence: { outcome: "verified" } },
	]) {
		w.patch(patch);
		await expect(
			submitEmulation(
				bound,
				Buffer.alloc(128),
				"b".repeat(64),
				undefined,
				w.fetcher,
			),
		).rejects.toThrow();
	}
});
it("rejects stale identity, missing Hybrid basis, changed ownership and cancelled submissions before upload", async () => {
	const w = worker(),
		bound = await bindEmulationRequest(request, w.fetcher);
	expect(() =>
		EmulationRuntimeSchema.parse({ ...request, analysis_mode: "hybrid" }),
	).toThrow();
	await expect(
		submitEmulation(
			{ ...bound, worker_runtime_sha256: "c".repeat(64) },
			Buffer.alloc(128),
			"b".repeat(64),
			undefined,
			w.fetcher,
		),
	).rejects.toThrow("changed");
	const cancel = new AbortController();
	cancel.abort();
	await expect(
		submitEmulation(
			bound,
			Buffer.alloc(128),
			"b".repeat(64),
			cancel.signal,
			w.fetcher,
		),
	).rejects.toThrow();
	await expect(
		submitEmulation(
			bound,
			Buffer.alloc(128),
			"b".repeat(64),
			undefined,
			w.fetcher,
			async () => {
				throw new Error("mode changed");
			},
		),
	).rejects.toThrow("mode changed");
	expect(w.mock.mock.calls.every(([, init]) => init?.method !== "POST")).toBe(
		true,
	);
});
it("requests process-group cancellation on aborted transport, without retry", async () => {
	const w = worker(),
		bound = await bindEmulationRequest(request, w.fetcher),
		abort = new AbortController(),
		methods: string[] = [];
	const f = (async (u: unknown, i?: RequestInit) => {
		methods.push(i?.method ?? "GET");
		if (i?.method === "POST") {
			abort.abort();
			throw new Error("aborted");
		}
		return w.fetcher(u as string, i);
	}) as typeof fetch;
	await expect(
		submitEmulation(bound, Buffer.alloc(128), "b".repeat(64), abort.signal, f),
	).rejects.toThrow("aborted");
	expect(methods.filter((m) => m === "POST")).toHaveLength(1);
	expect(methods).toContain("DELETE");
});

it("requires full signed profile architecture coverage and binds ARM plans without fallback", async () => {
	const w = worker();
	for (const architecture of ["x86_64", "arm32", "arm64"]) {
		expect(
			await bindEmulationRequest({ ...request, architecture }, w.fetcher),
		).toMatchObject({ engine: "qiling", architecture });
	}
	for (const architectures of [
		[],
		["x86_64"],
		["arm32", "arm64"],
		["arm64", "arm64", "x86_64"],
	]) {
		w.manifestPatch({ architectures });
		await expect(probeEmulation("qiling", w.fetcher)).rejects.toThrow(
			"incompatible",
		);
	}
	w.manifestPatch({
		profileSha256:
			"b8bb3b0fe985f4e8d74b9809c50e1da59d83f6bb3756b4b76997084473df3c71",
	});
	await expect(probeEmulation("qiling", w.fetcher)).rejects.toThrow(
		"incompatible",
	);
});
