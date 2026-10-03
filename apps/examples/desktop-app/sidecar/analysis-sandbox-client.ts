import { createPublicKey, verify } from "node:crypto";

export type AnalysisSandboxManifest = {
	workerId: string;
	version: string;
	protocol: "cline-analysis-worker/v1";
	isolation: "hyper-v" | "windows-sandbox" | "remote-vm";
	ephemeralSnapshots: boolean;
	networkModes: Array<"disabled" | "recorded">;
	maxArtifactBytes: number;
	issuedAt: string;
	expiresAt: string;
};

export type AnalysisSandboxHealth = {
	configured: boolean;
	ready: boolean;
	endpoint?: string;
	error?: string;
	manifest?: AnalysisSandboxManifest;
};

type FetchLike = (
	input: string | URL | Request,
	init?: RequestInit,
) => Promise<Response>;

function configuration() {
	const endpoint = process.env.CLINE_ANALYSIS_SANDBOX_WORKER?.trim();
	const publicKey = process.env.CLINE_ANALYSIS_SANDBOX_PUBLIC_KEY?.trim();
	if (!endpoint || !publicKey) return { endpoint, publicKey, valid: false };
	try {
		return {
			endpoint,
			publicKey,
			valid: new URL(endpoint).protocol === "https:",
		};
	} catch {
		return { endpoint, publicKey, valid: false };
	}
}

function validManifest(value: unknown): value is AnalysisSandboxManifest {
	if (!value || typeof value !== "object") return false;
	const manifest = value as AnalysisSandboxManifest;
	return (
		typeof manifest.workerId === "string" &&
		typeof manifest.version === "string" &&
		manifest.protocol === "cline-analysis-worker/v1" &&
		["hyper-v", "windows-sandbox", "remote-vm"].includes(manifest.isolation) &&
		manifest.ephemeralSnapshots === true &&
		Array.isArray(manifest.networkModes) &&
		manifest.networkModes.includes("disabled") &&
		Number.isFinite(manifest.maxArtifactBytes) &&
		manifest.maxArtifactBytes > 0 &&
		Date.parse(manifest.expiresAt) > Date.now()
	);
}

export async function probeAnalysisSandbox(
	fetchImpl: FetchLike = fetch,
): Promise<AnalysisSandboxHealth> {
	const config = configuration();
	if (!config.endpoint && !config.publicKey) {
		return { configured: false, ready: false };
	}
	if (!config.endpoint || !config.publicKey || !config.valid) {
		return {
			configured: true,
			ready: false,
			error: "Sandbox requires an HTTPS endpoint and pinned public key.",
		};
	}
	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), 5_000);
	try {
		const response = await fetchImpl(
			new URL("/v1/capabilities", config.endpoint),
			{
				method: "GET",
				headers: { accept: "application/json" },
				signal: controller.signal,
			},
		);
		if (!response.ok) {
			throw new Error(`Worker health returned HTTP ${response.status}`);
		}
		const body = (await response.json()) as {
			manifest?: unknown;
			signature?: unknown;
		};
		if (!validManifest(body.manifest) || typeof body.signature !== "string") {
			throw new Error("Worker returned an invalid capability manifest");
		}
		const signatureValid = verify(
			null,
			Buffer.from(JSON.stringify(body.manifest)),
			createPublicKey(config.publicKey),
			Buffer.from(body.signature, "base64"),
		);
		if (!signatureValid)
			throw new Error("Worker attestation signature is invalid");
		return {
			configured: true,
			ready: true,
			endpoint: config.endpoint,
			manifest: body.manifest,
		};
	} catch (error) {
		return {
			configured: true,
			ready: false,
			endpoint: config.endpoint,
			error: error instanceof Error ? error.message : String(error),
		};
	} finally {
		clearTimeout(timeout);
	}
}

export type AnalysisSandboxSubmission = {
	requestHash: string;
	artifactSha256: string;
	network: "disabled" | "recorded";
	timeoutMs: number;
	maxOutputBytes: number;
};

/**
 * Dynamic execution intentionally remains unavailable until the configured
 * worker passes the signed capability probe. The host never executes a sample.
 */
export async function assertAnalysisSandboxReady(): Promise<AnalysisSandboxManifest> {
	const health = await probeAnalysisSandbox();
	if (!health.ready || !health.manifest) {
		throw new Error(
			health.error ?? "No attested isolated analysis worker is available.",
		);
	}
	return health.manifest;
}
