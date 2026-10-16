import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({
	verify: vi.fn(),
	test: vi.fn(),
	directory: "",
}));
vi.mock("@cline/core", () => ({
	verifyAndroidToolchain: mocks.verify,
	testAndroidToolchain: mocks.test,
}));
vi.mock("@cline/shared/storage", () => ({
	resolveClineDataDir: () => mocks.directory,
}));
import {
	androidToolchainStatus,
	testOwnedAndroidToolchain,
} from "./android-toolchain-readiness";
beforeEach(async () => {
	mocks.directory = await mkdtemp(join(tmpdir(), "android-readiness-owned-"));
	mocks.verify.mockReset().mockResolvedValue({ identity: "owned-pack-v1" });
	mocks.test
		.mockReset()
		.mockResolvedValue({ identity: "owned-pack-v1", status: "passed" });
});
afterEach(async () => {
	await rm(mocks.directory, { recursive: true, force: true });
});
it("opening readiness checks integrity without executing or claiming fixture success", async () => {
	expect((await androidToolchainStatus()).state).toBe("installed-not-tested");
	expect(mocks.test).not.toHaveBeenCalled();
});
it("coalesces explicit tests and invalidates readiness when pack identity changes", async () => {
	const first = testOwnedAndroidToolchain(),
		second = testOwnedAndroidToolchain();
	expect(first).toBe(second);
	await first;
	expect(mocks.test).toHaveBeenCalledTimes(1);
	expect((await androidToolchainStatus()).state).toBe("ready");
	mocks.verify.mockResolvedValue({ identity: "owned-pack-v2" });
	expect((await androidToolchainStatus()).state).toBe("installed-not-tested");
	expect(mocks.test).toHaveBeenCalledTimes(1);
});
it("never falls back to readiness after integrity failure", async () => {
	mocks.verify.mockRejectedValue(new Error("tampered"));
	expect((await androidToolchainStatus()).state).toBe("needs-setup");
	expect(mocks.test).not.toHaveBeenCalled();
});
it("does not persist readiness for a failed explicit fixture run", async () => {
	mocks.test.mockRejectedValue(new Error("fixture failed"));
	await expect(testOwnedAndroidToolchain()).rejects.toThrow("fixture failed");
	expect((await androidToolchainStatus()).state).toBe("installed-not-tested");
});
