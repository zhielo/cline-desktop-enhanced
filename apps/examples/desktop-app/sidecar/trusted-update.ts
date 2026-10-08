import { createPublicKey, verify } from "node:crypto";
import { z } from "zod";
const Update = z
	.object({
		schemaVersion: z.literal(1),
		version: z.string().regex(/^\d+\.\d+\.\d+$/),
		platform: z.literal("windows-x64"),
		runtimeId: z.string().max(100),
		sha256: z.string().regex(/^[a-f0-9]{64}$/),
		url: z.string().url(),
		expiresAt: z.string().datetime(),
		minimumDataSchema: z.number().int().min(1),
		maximumDataSchema: z.number().int().min(1),
	})
	.strict();
export function verifyPrivateUpdate(
	payload: string,
	signature: string,
	publicKey: string,
	current: { version: string; runtimeId: string; dataSchema: number },
	now = Date.now(),
) {
	if (Buffer.byteLength(payload) > 16384 || signature.length > 256)
		throw new Error("Update manifest budget exceeded");
	const key = createPublicKey(publicKey);
	if (key.asymmetricKeyType !== "ed25519")
		throw new Error("Owner Ed25519 public key required");
	if (
		!verify(null, Buffer.from(payload), key, Buffer.from(signature, "base64"))
	)
		throw new Error("Invalid update signature");
	const manifest = Update.parse(JSON.parse(payload));
	const url = new URL(manifest.url);
	if (
		url.protocol !== "https:" ||
		url.username ||
		url.password ||
		url.hostname !== "github.com" ||
		!url.pathname.startsWith("/zhielo/cline-desktop-enhanced/")
	)
		throw new Error("App-owned HTTPS update source required");
	const tuple = (version: string) => version.split(".").map(Number);
	const left = tuple(manifest.version),
		right = tuple(current.version);
	const newer = left.some(
		(n, i) => n > right[i] && left.slice(0, i).every((v, j) => v === right[j]),
	);
	if (
		!newer ||
		Date.parse(manifest.expiresAt) <= now ||
		manifest.runtimeId !== current.runtimeId ||
		current.dataSchema < manifest.minimumDataSchema ||
		current.dataSchema > manifest.maximumDataSchema
	)
		throw new Error("Expired, downgraded, or incompatible update manifest");
	return {
		manifest,
		downloaded: false,
		activated: false,
		rollbackRequired: true,
	};
}
export function privateUpdateReadiness() {
	return {
		status: "disabled",
		reason:
			"Private unsigned artifact-only distribution preserved. Owner signing and staged rollback acceptance are required before enabling automatic updates.",
		endpointConfigured: false,
		releasePublished: false,
	};
}
