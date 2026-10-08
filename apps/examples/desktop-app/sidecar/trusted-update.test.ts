import { generateKeyPairSync, sign } from "node:crypto";
import { it, expect } from "vitest";
import { verifyPrivateUpdate, privateUpdateReadiness } from "./trusted-update";
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
const now = Date.parse("2026-10-08T00:00:00Z");
const current = {
	version: "0.3.0",
	runtimeId: "owned-runtime-v1",
	dataSchema: 1,
};
function fixture(extra: Record<string, unknown> = {}) {
	const payload = JSON.stringify({
		schemaVersion: 1,
		version: "0.3.1",
		platform: "windows-x64",
		runtimeId: current.runtimeId,
		sha256: "a".repeat(64),
		url: "https://github.com/zhielo/cline-desktop-enhanced/releases/download/owned/app.exe",
		expiresAt: "2026-10-09T00:00:00Z",
		minimumDataSchema: 1,
		maximumDataSchema: 1,
		...extra,
	});
	return {
		payload,
		signature: sign(null, Buffer.from(payload), privateKey).toString("base64"),
	};
}
it("validates owner-signed compatible metadata without downloading or activating", () => {
	const f = fixture();
	expect(
		verifyPrivateUpdate(f.payload, f.signature, pem, current, now),
	).toMatchObject({
		downloaded: false,
		activated: false,
		rollbackRequired: true,
	});
	expect(privateUpdateReadiness().status).toBe("disabled");
});
it.each([
	{ version: "0.2.9" },
	{ runtimeId: "wrong" },
	{ expiresAt: "2026-10-07T00:00:00Z" },
	{ minimumDataSchema: 2 },
	{ url: "https://github.com/other/repo/file.exe" },
])("rejects expired, foreign, downgraded, or incompatible updates: %s", (extra) => {
	const f = fixture(extra);
	expect(() =>
		verifyPrivateUpdate(f.payload, f.signature, pem, current, now),
	).toThrow();
});
it("rejects tampering", () => {
	const f = fixture();
	expect(() =>
		verifyPrivateUpdate(
			f.payload.replace("0.3.1", "9.0.0"),
			f.signature,
			pem,
			current,
			now,
		),
	).toThrow("signature");
});
