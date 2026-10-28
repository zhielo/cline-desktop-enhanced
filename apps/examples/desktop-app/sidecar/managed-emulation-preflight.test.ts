import { afterEach, expect, it, vi } from "vitest";
const execute = vi.hoisted(() => vi.fn());
vi.mock("node:child_process", () => ({
	execFile: Object.assign(() => {}, {
		[Symbol.for("nodejs.util.promisify.custom")]: execute,
	}),
}));
import {
	projectManagedEmulationPreflight,
	readManagedEmulationPreflight,
} from "./managed-emulation-preflight";
const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
afterEach(() => {
	Object.defineProperty(process, "platform", platform);
	vi.unstubAllEnvs();
	execute.mockReset();
});
function ownedObservation() {
	return {
		build: "19045",
		edition: "Professional",
		productType: 1,
		cpuArchitectures: [9],
		hypervisorPresent: true,
		hyperVEnabled: true,
		managementEnabled: true,
		managementModule: true,
		vmms: "running",
		servicingRebootPending: false,
		totalMemoryBytes: 16 * 1024 ** 3,
		freeMemoryBytes: 8 * 1024 ** 3,
		freeStorageBytes: 40 * 1024 ** 3,
	};
}
it("observed prerequisites never certify VM isolation, installation, resources or engine readiness", () => {
	const report = projectManagedEmulationPreflight(
		ownedObservation(),
		"win32",
		"x64",
	);
	expect(report).toMatchObject({
		hostPrerequisites: "observed",
		query: "observed",
		osBuild: "19045",
		managedInstallation: "not-implemented",
		containment: "not-tested",
		engineReadiness: "not-tested",
		capacity: { totalMemoryGiB: 16, freeMemoryGiB: 8, freeStorageGiB: 40 },
	});
	expect(report.checks).toHaveLength(9);
	expect(report.checks.every((c) => c.state === "observed")).toBe(true);
});
it.each([
	["server", { productType: 3 }, "x64", "unsupported"],
	["old client", { build: "18363" }, "x64", "unsupported"],
	["unreviewed edition", { edition: "Core" }, "x64", "unsupported"],
	["native ARM host", { cpuArchitectures: [12] }, "arm64", "unsupported"],
	["x64 process on ARM host", { cpuArchitectures: [12] }, "x64", "unsupported"],
	["feature disabled", { hyperVEnabled: false }, "x64", "missing"],
	["feature inaccessible", { hyperVEnabled: null }, "x64", "unknown"],
	["no module", { managementModule: false }, "x64", "missing"],
	["VM service stopped", { vmms: "stopped" }, "x64", "missing"],
	["VM service absent", { vmms: "absent" }, "x64", "missing"],
	[
		"servicing reboot marker",
		{ servicingRebootPending: true },
		"x64",
		"missing",
	],
	["unknown reboot state", { servicingRebootPending: null }, "x64", "unknown"],
] as const)("does not promote %s to usable prerequisites", (_label, patch, arch, state) => {
	expect(
		projectManagedEmulationPreflight(
			{ ...ownedObservation(), ...patch },
			"win32",
			arch,
		).hostPrerequisites,
	).toBe(state);
});
it("rejects malformed/oversized observations and never projects identities or arbitrary edition text", () => {
	for (const value of [
		null,
		{},
		{ ...ownedObservation(), totalMemoryBytes: Infinity },
		{ ...ownedObservation(), build: "../SECRET" },
	])
		expect(
			projectManagedEmulationPreflight(value, "win32", "x64"),
		).toMatchObject({ query: "unavailable", hostPrerequisites: "unknown" });
	const report = projectManagedEmulationPreflight(
		{
			...ownedObservation(),
			edition: "PRIVATE",
			hostname: "SECRET",
			token: "SECRET",
		},
		"win32",
		"x64",
	);
	expect(JSON.stringify(report)).not.toMatch(/PRIVATE|SECRET|hostname|token/);
});
it("never starts a process on unsupported hosts", async () => {
	Object.defineProperty(process, "platform", {
		value: "linux",
		configurable: true,
	});
	expect(await readManagedEmulationPreflight()).toMatchObject({
		platform: "unsupported",
		query: "not-run",
		hostPrerequisites: "unsupported",
	});
	expect(execute).not.toHaveBeenCalled();
});
it("uses one fixed bounded read-only system query, single-flight but without persistent caching", async () => {
	Object.defineProperty(process, "platform", {
		value: "win32",
		configurable: true,
	});
	vi.stubEnv("SystemRoot", "C:\\Windows");
	let finish!: (result: { stdout: string; stderr: string }) => void;
	execute.mockImplementationOnce(
		() =>
			new Promise((resolve) => {
				finish = resolve;
			}),
	);
	const first = readManagedEmulationPreflight(),
		second = readManagedEmulationPreflight();
	expect(first).toBe(second);
	expect(execute).toHaveBeenCalledTimes(1);
	const [file, args, options] = execute.mock.calls[0];
	expect(file).toBe(
		"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
	);
	expect(args.slice(0, 4)).toEqual([
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-EncodedCommand",
	]);
	const script = Buffer.from(args[4], "base64").toString("utf16le");
	expect(script).toContain("Get-CimInstance -ClassName Win32_OperatingSystem");
	expect(script).toContain(
		"$env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')",
	);
	expect(script).not.toMatch(
		/\b(New-VM|Set-VM|Start-VM|Remove-VM|Enable-WindowsOptionalFeature|Import-Module|Invoke-WebRequest|wsl\.exe)\b/i,
	);
	expect(options).toMatchObject({
		timeout: 15_000,
		maxBuffer: 16_384,
		windowsHide: true,
	});
	expect(options.shell).toBeUndefined();
	finish({
		stdout: `\uFEFF${JSON.stringify(ownedObservation())}`,
		stderr: "SECRET",
	});
	expect(await first).toMatchObject({ query: "observed" });
	execute.mockResolvedValueOnce({ stdout: "invalid SECRET", stderr: "SECRET" });
	expect(await readManagedEmulationPreflight()).toMatchObject({
		query: "unavailable",
		engineReadiness: "not-tested",
	});
	expect(execute).toHaveBeenCalledTimes(2);
});
it("query errors and invalid system roots do not echo diagnostics, elevate or fall back", async () => {
	Object.defineProperty(process, "platform", {
		value: "win32",
		configurable: true,
	});
	vi.stubEnv("SystemRoot", "\\\\server\\SECRET");
	expect(await readManagedEmulationPreflight()).toMatchObject({
		query: "unavailable",
	});
	expect(execute).not.toHaveBeenCalled();
	vi.stubEnv("SystemRoot", "C:\\Windows");
	execute.mockRejectedValueOnce(new Error("SECRET private host diagnostic"));
	expect(JSON.stringify(await readManagedEmulationPreflight())).not.toContain(
		"SECRET",
	);
	expect(execute).toHaveBeenCalledTimes(1);
});
