import { test, expect } from "bun:test";
import { isolationHostFailureMessage } from "../sidecar/isolation-host-failure";
const owned = {
	schemaVersion: 1,
	error: "isolation-launch-failed",
	stage: "launch",
	win32Error: 5,
	hresult: -2147024891,
	cleanupFailures: [],
};
test("retains bounded stage and native status without exception text or paths", () => {
	expect(isolationHostFailureMessage(JSON.stringify(owned))).toContain(
		"stage=launch; win32=5; hresult=0x80070005",
	);
});
test("preserves original stage when cleanup also fails", () => {
	expect(
		isolationHostFailureMessage(
			JSON.stringify({
				...owned,
				cleanupFailures: ["profile-cleanup", "staging-cleanup"],
			}),
		),
	).toContain("stage=launch");
	expect(
		isolationHostFailureMessage(
			JSON.stringify({ ...owned, cleanupFailures: ["staging-cleanup"] }),
		),
	).toContain("cleanup=staging-cleanup");
});
for (const bad of [
	{ ...owned, stage: "target-secret" },
	{ ...owned, message: "secret" },
	{ ...owned, win32Error: "5" },
	{ ...owned, hresult: 1.5 },
	{ ...owned, cleanupFailures: ["secret"] },
	{ error: "target claims success" },
	[owned],
])
	test("rejects untrusted/malformed diagnostic structure", () => {
		const m = isolationHostFailureMessage(JSON.stringify(bad));
		expect(m).toBe(
			"OS isolation failed closed before a successful receipt; no fallback",
		);
		expect(m).not.toContain("secret");
	});
test("rejects oversized and invalid output", () => {
	expect(isolationHostFailureMessage("x".repeat(4097))).not.toContain("stage=");
	expect(isolationHostFailureMessage("invalid JSON")).not.toContain("stage=");
});
