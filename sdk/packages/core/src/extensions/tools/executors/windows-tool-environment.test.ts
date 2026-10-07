import { afterEach, describe, expect, it, vi } from "vitest";
import * as supervised from "./supervised-process";
import { readWindowsRegistryValue } from "./windows-tool-environment";

afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllEnvs();
});
const success = {
	exitCode: 0,
	stdout: "    Path    REG_EXPAND_SZ    %SystemRoot%\\Tools;C:\\Other\r\n",
	stderr: "",
	timedOut: false,
	cancelled: false,
};

describe("bounded Windows registry environment probes", () => {
	it("does not launch registry probes on non-Windows hosts", async () => {
		const run = vi.spyOn(supervised, "runSupervised");
		expect(
			await readWindowsRegistryValue("HKCU\\Environment", "Path", "linux"),
		).toBeUndefined();
		expect(run).not.toHaveBeenCalled();
	});
	it("uses the system executable, bounded supervised execution and expands values", async () => {
		vi.stubEnv("SystemRoot", "C:\\Windows");
		const run = vi
			.spyOn(supervised, "runSupervised")
			.mockResolvedValue(success);
		expect(
			await readWindowsRegistryValue("HKCU\\Environment", "Path", "win32"),
		).toBe("C:\\Windows\\Tools;C:\\Other");
		expect(run).toHaveBeenCalledWith(
			"C:\\Windows\\System32\\reg.exe",
			["query", "HKCU\\Environment", "/v", "Path"],
			5000,
		);
	});
	it.each([
		{ timedOut: true },
		{ cancelled: true },
		{ outputDrainTimedOut: true },
		{ truncated: true },
		{ exitCode: 1 },
	])("rejects incomplete or unsuccessful probes: %j", async (failure) => {
		vi.spyOn(supervised, "runSupervised").mockResolvedValue({
			...success,
			...failure,
		});
		expect(
			await readWindowsRegistryValue("HKCU\\Environment", "Path", "win32"),
		).toBeUndefined();
	});
	it("retains inherited values when registry access fails", async () => {
		vi.spyOn(supervised, "runSupervised").mockRejectedValue(
			new Error("access denied"),
		);
		expect(
			await readWindowsRegistryValue("HKCU\\Environment", "Path", "win32"),
		).toBeUndefined();
	});
});
