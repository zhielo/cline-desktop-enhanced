import { z } from "zod";
import { createHash, randomBytes, verify } from "node:crypto";
import { EmulationRuntimeSchema, EMULATION_PROFILE_SHA256 } from "@cline/core";
import { boundedWorkerJson, workerPublicKey } from "./analysis-sandbox-client";
const Hash = z.string().regex(/^[a-f0-9]{64}$/),
	Id = z.string().min(1).max(128);
export { EmulationRuntimeSchema } from "@cline/core";
export type EmulationRuntimeInput = ReturnType<
	typeof EmulationRuntimeSchema.parse
>;
type FetchLike = typeof fetch;
function config(engine: string) {
	if (!["qiling", "unidbg", "rnidbg"].includes(engine))
		throw new Error("Unknown engine");
	const prefix = `CLINE_EMULATION_${engine.toUpperCase()}`,
		endpoint = process.env[`${prefix}_ENDPOINT`]?.trim(),
		key = process.env[`${prefix}_PUBLIC_KEY`]?.trim(),
		token = process.env[`${prefix}_TOKEN`];
	if (!endpoint || !key || !token || token.length < 32)
		throw new Error(
			`${engine} is unavailable: configure its independent HTTPS endpoint, Ed25519 key and authentication token; existing Unicorn/Speakeasy configuration is unchanged`,
		);
	const u = new URL(endpoint);
	if (
		u.protocol !== "https:" ||
		u.username ||
		u.password ||
		u.hash ||
		u.search ||
		u.pathname !== "/"
	)
		throw new Error("Engine worker requires an HTTPS origin");
	const publicKey = workerPublicKey(key),
		fingerprint = createHash("sha256")
			.update(publicKey.export({ type: "spki", format: "der" }))
			.digest("hex");
	return {
		endpoint,
		key: publicKey,
		fingerprint,
		headers: { authorization: `Bearer ${token}` },
	};
}
const Manifest = z
	.object({
		workerId: Id,
		version: Id,
		protocol: z.literal("cline-analysis-worker/v1"),
		isolation: z.literal("remote-vm"),
		ephemeralSnapshots: z.literal(true),
		networkModes: z.tuple([z.literal("disabled")]),
		maxArtifactBytes: z.number().int().min(64).max(16777216),
		issuedAt: z.string(),
		expiresAt: z.string(),
		operations: z.array(z.string().max(80)).max(8),
		engine: z.enum(["qiling", "unidbg", "rnidbg"]),
		profileSha256: Hash,
		architectures: z.array(z.enum(["x86_64", "arm32", "arm64"])).max(3),
		runtimeSha256: Hash,
		isolationClaim: z.literal("operator-provisioned-not-hardware-attested"),
	})
	.strict();
async function signed(
	response: Response,
	cfg: ReturnType<typeof config>,
	name: "manifest" | "receipt",
	max: number,
) {
	if (!response.ok)
		throw new Error(
			`Worker returned HTTP ${response.status}; no automatic retry`,
		);
	const raw = (await boundedWorkerJson(response, max)) as Record<
		string,
		unknown
	>;
	if (
		typeof raw.signature !== "string" ||
		raw.signature.length > 128 ||
		!raw[name] ||
		!verify(
			null,
			Buffer.from(JSON.stringify(raw[name])),
			cfg.key,
			Buffer.from(raw.signature, "base64"),
		)
	)
		throw new Error("Invalid engine worker signature");
	return raw[name];
}
export async function probeEmulation(
	engine: string,
	fetchImpl: FetchLike = fetch,
) {
	const cfg = config(engine),
		m = Manifest.parse(
			await signed(
				await fetchImpl(new URL("/v1/capabilities", cfg.endpoint), {
					method: "GET",
					redirect: "error",
					headers: cfg.headers,
					signal: AbortSignal.timeout(5000),
				}),
				cfg,
				"manifest",
				65536,
			),
		);
	const now = Date.now();
	if (
		m.engine !== engine ||
		m.profileSha256 !== EMULATION_PROFILE_SHA256 ||
		!m.operations.includes(`emulate-profile-${engine}`) ||
		!(
			Date.parse(m.issuedAt) >= now - 300000 &&
			Date.parse(m.issuedAt) <= now + 30000 &&
			Date.parse(m.expiresAt) > now &&
			Date.parse(m.expiresAt) <= now + 300000
		)
	)
		throw new Error(
			"Expired or incompatible engine profile; worker remains blocked",
		);
	return { cfg, manifest: m };
}
export async function bindEmulationRequest(
	raw: unknown,
	fetchImpl: FetchLike = fetch,
) {
	const input = EmulationRuntimeSchema.parse(raw),
		{ cfg, manifest: m } = await probeEmulation(input.engine, fetchImpl);
	if (!m.architectures.includes(input.architecture))
		throw new Error("Architecture not accepted by worker");
	return EmulationRuntimeSchema.parse({
		...input,
		worker_endpoint: cfg.endpoint,
		worker_id: m.workerId,
		worker_key_sha256: cfg.fingerprint,
		worker_runtime_sha256: m.runtimeSha256,
		worker_profile_sha256: m.profileSha256,
	});
}
const Receipt = z
	.object({
		protocol: z.literal("cline-analysis-job/v1"),
		workerId: Id,
		nonce: z.string().regex(/^[a-f0-9]{32}$/),
		requestHash: Hash,
		artifactSha256: Hash,
		network: z.literal("disabled"),
		status: z.enum(["partial", "failed"]),
		engine: z.enum(["qiling", "unidbg", "rnidbg"]),
		runtimeSha256: Hash,
		profileSha256: Hash,
		architecture: z.enum(["x86_64", "arm32", "arm64"]),
		scenario: z.unknown(),
		instructionLimit: z.number().int().min(1).max(100000),
		evidence: z.record(z.string(), z.unknown()),
		limitations: z.array(z.string().max(1000)).max(50),
	})
	.strict();
/** No fallback, host execution, auto-install, auto-retry or implied whole-app verification. */
export async function submitEmulation(
	raw: unknown,
	artifact: Uint8Array,
	requestHash: string,
	signal?: AbortSignal,
	fetchImpl: FetchLike = fetch,
	assertCurrent?: () => Promise<void>,
) {
	const input = EmulationRuntimeSchema.parse(raw);
	Hash.parse(requestHash);
	signal?.throwIfAborted();
	const { cfg, manifest: m } = await probeEmulation(input.engine, fetchImpl);
	signal?.throwIfAborted();
	if (!m.architectures.includes(input.architecture))
		throw new Error("Unsupported worker architecture");
	const bound = {
		worker_endpoint: cfg.endpoint,
		worker_id: m.workerId,
		worker_key_sha256: cfg.fingerprint,
		worker_runtime_sha256: m.runtimeSha256,
		worker_profile_sha256: m.profileSha256,
	};
	for (const key of [
		"worker_endpoint",
		"worker_id",
		"worker_key_sha256",
		"worker_runtime_sha256",
		"worker_profile_sha256",
	] as const)
		if (input[key] !== bound[key])
			throw new Error(
				"Engine identity/profile changed since approval; prepare a new plan",
			);
	if (artifact.byteLength < 64 || artifact.byteLength > 16777216)
		throw new Error("Artifact budget");
	const nonce = randomBytes(16).toString("hex"),
		artifactSha256 = createHash("sha256").update(artifact).digest("hex"),
		controller = new AbortController(),
		abort = () => controller.abort();
	signal?.addEventListener("abort", abort, { once: true });
	if (signal?.aborted) abort();
	const timer = setTimeout(abort, input.timeout_ms + 5000);
	try {
		await assertCurrent?.();
		controller.signal.throwIfAborted();
		const response = await fetchImpl(new URL("/v1/jobs", cfg.endpoint), {
			method: "POST",
			redirect: "error",
			headers: { ...cfg.headers, "content-type": "application/json" },
			signal: controller.signal,
			body: JSON.stringify({
				protocol: "cline-analysis-job/v1",
				operation: "emulate_profile",
				nonce,
				requestHash,
				artifactSha256,
				network: "disabled",
				engine: input.engine,
				architecture: input.architecture,
				scenario: input.scenario,
				instructionLimit: input.instruction_limit,
				timeoutMs: input.timeout_ms,
				maxOutputBytes: 1048576,
				profileSha256: input.worker_profile_sha256,
				runtimeSha256: input.worker_runtime_sha256,
				artifactBase64: Buffer.from(artifact).toString("base64"),
			}),
		});
		const receipt = Receipt.parse(
			await signed(response, cfg, "receipt", 1048576),
		);
		if (
			receipt.workerId !== input.worker_id ||
			receipt.nonce !== nonce ||
			receipt.requestHash !== requestHash ||
			receipt.artifactSha256 !== artifactSha256 ||
			receipt.engine !== input.engine ||
			receipt.architecture !== input.architecture ||
			receipt.runtimeSha256 !== input.worker_runtime_sha256 ||
			receipt.profileSha256 !== input.worker_profile_sha256 ||
			receipt.instructionLimit !== input.instruction_limit ||
			JSON.stringify(receipt.scenario) !== JSON.stringify(input.scenario)
		)
			throw new Error("Receipt does not bind approved emulation scenario");
		if (
			receipt.status === "partial" &&
			receipt.evidence.outcome !== "unverified"
		)
			throw new Error(
				"Modeled scenario must not certify native or whole-app behavior",
			);
		return receipt;
	} catch (e) {
		if (controller.signal.aborted) {
			try {
				await fetchImpl(new URL(`/v1/jobs/${nonce}`, cfg.endpoint), {
					method: "DELETE",
					redirect: "error",
					headers: cfg.headers,
					signal: AbortSignal.timeout(5000),
				});
			} catch {
				/* Worker independently kills its process group at deadline; cleanup is not confirmed here. */
			}
		}
		throw e;
	} finally {
		clearTimeout(timer);
		signal?.removeEventListener("abort", abort);
	}
}
