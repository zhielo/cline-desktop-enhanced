import { describe, expect, it } from "vitest";
import {
	processStartProbeTimeoutMs,
	getProcessStartToken,
	getProcessStartTokenAsync,
	parseLinuxProcessStartToken,
	probeProcessStartToken,
	probeProcessStartTokenAsync,
	parseWindowsProcessStartToken,
	resolveWindowsProcessStartCommand,
} from "./process-start-token";

describe("process start tokens", () => {
	it("rejects invalid process IDs without probing the operating system", async () => {
		expect(getProcessStartToken(0)).toBeUndefined();
		expect(getProcessStartToken(-1)).toBeUndefined();
		expect(getProcessStartToken(Number.MAX_SAFE_INTEGER + 1)).toBeUndefined();
		await expect(getProcessStartTokenAsync(0)).resolves.toBeUndefined();
		expect(probeProcessStartToken(0)).toEqual({ status: "missing" });
		await expect(probeProcessStartTokenAsync(0)).resolves.toEqual({
			status: "missing",
		});
	});

	it("parses Linux start ticks when the command name contains a closing parenthesis", () => {
		const fields = [
			"S",
			...Array.from({ length: 18 }, (_, index) => String(index + 1)),
			"18446744073709551615",
		];
		expect(
			parseLinuxProcessStartToken(
				`42 (command ) name) ${fields.join(" ")}`,
				"boot-id\n",
			),
		).toBe("linux:boot-id:18446744073709551615");
	});

	it.each([
		"Z",
		"X",
		"x",
	])("does not identify a Linux process in the %s state as active", (state) => {
		const fields = [state, ...Array.from({ length: 19 }, () => "1")];
		expect(
			parseLinuxProcessStartToken(`42 (zombie) ${fields.join(" ")}`, "boot-id"),
		).toBeUndefined();
	});

	it.runIf(process.platform === "linux")(
		"captures the same live-process token synchronously and asynchronously on Linux",
		async () => {
			const synchronous = getProcessStartToken(process.pid);
			expect(synchronous).toMatch(/^linux:[^:]+:\d+$/);
			await expect(getProcessStartTokenAsync(process.pid)).resolves.toBe(
				synchronous,
			);
			expect(probeProcessStartToken(process.pid)).toEqual({
				status: "found",
				token: synchronous,
			});
			await expect(probeProcessStartTokenAsync(process.pid)).resolves.toEqual({
				status: "found",
				token: synchronous,
			});
		},
	);
});

describe("Windows invariant process identity", () => {
	it("selects only available absolute system interpreter paths with invariant exact ticks", () => {
		const env = {
			ProgramFiles: "C:\\Program Files",
			SystemRoot: "C:\\Windows",
		};
		const seen: string[] = [];
		const command = resolveWindowsProcessStartCommand(1234, env, (p) => {
			seen.push(p);
			return true;
		});
		expect(command?.file).toBe("C:\\Program Files\\PowerShell\\7\\pwsh.exe");
		expect(seen).toHaveLength(1);
		expect(command?.args).toContain("-NoProfile");
		expect(command?.args.at(-1)).toContain("InvariantCulture");
		expect(command?.args.at(-1)).toContain("Get-Process -Id 1234");
		const fallback = resolveWindowsProcessStartCommand(1234, env, (p) =>
			p.endsWith("powershell.exe"),
		);
		expect(fallback?.file).toBe(
			"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
		);
		expect(
			resolveWindowsProcessStartCommand(1234, env, () => false),
		).toBeUndefined();
	});
	it("never resolves PATH/CWD or remote interpreter paths and never interpolates invalid PIDs", () => {
		const available = () => {
			throw new Error("Must not probe an untrusted path");
		};
		for (const env of [
			{},
			{ ProgramFiles: "relative", SystemRoot: "relative" },
			{ ProgramFiles: "\\\\remote\\share", SystemRoot: "\\\\remote\\Windows" },
		])
			expect(
				resolveWindowsProcessStartCommand(1234, env, available),
			).toBeUndefined();
		for (const pid of [
			0,
			-1,
			NaN,
			1.5,
			4294967296,
			Number.MAX_SAFE_INTEGER + 1,
		])
			expect(
				resolveWindowsProcessStartCommand(
					pid,
					{ SystemRoot: "C:\\Windows" },
					available,
				),
			).toBeUndefined();
	});
	it("preserves exact ticks and rejects malformed/localized/overflow birth identities", () => {
		expect(parseWindowsProcessStartToken("  639011520000000001\r\n")).toBe(
			"win32:639011520000000001",
		);
		expect(parseWindowsProcessStartToken("3155378975999999999")).toBe(
			"win32:3155378975999999999",
		);
		for (const text of [
			"",
			"0",
			"0123",
			"-1",
			"1.0",
			"6.3901152e17",
			"639,011,520,000,000,001",
			"warning\n639011520000000001",
			"3155378976000000000",
			"99999999999999999999",
			"NaN",
		])
			expect(parseWindowsProcessStartToken(text)).toBeUndefined();
	});
	it.runIf(process.platform === "win32")(
		"captures the same exact live Windows birth token synchronously and asynchronously",
		async () => {
			const token = getProcessStartToken(process.pid);
			expect(token).toMatch(/^win32:[1-9]\d{0,18}$/);
			await expect(getProcessStartTokenAsync(process.pid)).resolves.toBe(token);
			expect(probeProcessStartToken(process.pid)).toEqual({
				status: "found",
				token,
			});
			await expect(probeProcessStartTokenAsync(process.pid)).resolves.toEqual({
				status: "found",
				token,
			});
		},
	);
});

it("keeps sync probes short and grants only bounded async Windows startup time", () => {
	expect(processStartProbeTimeoutMs(false, "win32")).toBe(2000);
	expect(processStartProbeTimeoutMs(true, "win32")).toBe(5000);
	expect(processStartProbeTimeoutMs(true, "linux")).toBe(2000);
});
