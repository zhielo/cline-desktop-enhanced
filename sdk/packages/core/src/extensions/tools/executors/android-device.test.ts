import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createAndroidDeviceExecutor } from "./android-device";

const directories: string[] = [];
const originalAdbPath = process.env.ADB_PATH;

afterEach(async () => {
	if (originalAdbPath === undefined) delete process.env.ADB_PATH;
	else process.env.ADB_PATH = originalAdbPath;
	await Promise.all(
		directories
			.splice(0)
			.map((directory) => fs.rm(directory, { recursive: true, force: true })),
	);
});

async function fakeAdb() {
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), "cline-adb-test-"));
	directories.push(directory);
	const adb = path.join(directory, "adb");
	await fs.writeFile(
		adb,
		`#!/bin/sh
set -eu
if [ "\${1:-}" = "version" ]; then
  printf 'Android Debug Bridge version 1.0.41\\n'
  exit 0
fi
if [ "\${1:-}" = "devices" ]; then
  printf 'List of devices attached\\nemulator-5554 device model:Pixel\\n'
  exit 0
fi
case "$*" in
  *"shell ps -A"*) printf 'USER PID NAME\\nuid 4321 com.example.app\\nuid 4322 com.example.app:worker\\nuid 4333 com.other.app\\n' ;;
  *"shell getprop"*) printf 'fixture-device-identity\\n' ;;
  *"exec-out cat /data/app/example/base.apk"*) printf 'apk-bytes' ;;
  *"shell pidof"*) printf '4321\\n' ;;
  *"shell wm size"*) printf 'Physical size: 1080x2400\\n' ;;
  *"shell dumpsys input"*) printf 'SurfaceOrientation: 0\\n' ;;
  *"shell uiautomator dump"*) printf 'dumped\\n' ;;
  *"exec-out cat /sdcard/window_dump.xml"*) printf '<hierarchy><node text="Hello"/></hierarchy>' ;;
  *"logcat"*) printf 'E AndroidRuntime: FATAL EXCEPTION: main token=super-secret-value\\n' ;;
  *"shell pm path"*) printf 'package:/data/app/example/base.apk\\n' ;;
  *"pull"*) for last in "$@"; do :; done; printf 'apk-bytes' > "$last"; printf 'pulled\\n' ;;
  *"exec-out screencap -p"*) printf '\\211PNG\\r\\n\\032\\npayload' ;;
  *) printf '%s\\n' "$@" ;;
esac
`,
	);
	await fs.chmod(adb, 0o700);
	process.env.ADB_PATH = adb;
	return directory;
}

describe("android device executor", () => {
	it("discovers ADB and captures package-filtered logs", async () => {
		if (process.platform === "win32") return;
		await fakeAdb();
		const execute = createAndroidDeviceExecutor();
		const discovery = JSON.parse(
			await execute({ operation: "discover" }, {} as never),
		);
		const logs = JSON.parse(
			await execute(
				{
					operation: "logcat",
					device_serial: "emulator-5554",
					package: "com.example.app",
					lines: 250,
				},
				{} as never,
			),
		);
		expect(discovery.devices).toContain("emulator-5554");
		expect(logs.args).toEqual([
			"-s",
			"emulator-5554",
			"logcat",
			"-d",
			"--pid",
			"4321",
			"-t",
			"250",
		]);
		expect(logs.stdout).toContain("FATAL EXCEPTION");
		expect(logs.stdout).toContain("token=[REDACTED]");
		expect(logs.stdout).not.toContain("super-secret-value");
		await expect(
			execute(
				{
					operation: "logcat",
					device_serial: "emulator-5554",
					clear_logcat: true,
				},
				{} as never,
			),
		).rejects.toThrow("confirm_log_clear=true");
	});

	it("pulls an APK and writes a validated PNG screenshot atomically", async () => {
		if (process.platform === "win32") return;
		const directory = await fakeAdb();
		const execute = createAndroidDeviceExecutor();
		const apk = path.join(directory, "out", "base.apk");
		const screenshot = path.join(directory, "out", "screen.png");
		const pulled = JSON.parse(
			await execute(
				{
					operation: "pull_apk",
					package: "com.example.app",
					output_path: apk,
				},
				{} as never,
			),
		);
		const captured = JSON.parse(
			await execute(
				{ operation: "screenshot", output_path: screenshot },
				{} as never,
			),
		);
		expect(pulled.succeeded).toBe(true);
		expect(await fs.readFile(apk, "utf8")).toBe("apk-bytes");
		expect(captured.succeeded).toBe(true);
		expect(captured.sha256).toMatch(/^[a-f0-9]{64}$/);
		expect((await fs.readFile(screenshot)).subarray(0, 8)).toEqual(
			Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
		);
	});

	it("supports validated taps, UI hierarchy, and acknowledged shell", async () => {
		if (process.platform === "win32") return;
		await fakeAdb();
		const execute = createAndroidDeviceExecutor();
		const tap = JSON.parse(
			await execute({ operation: "tap", x: 12, y: 34 }, {} as never),
		);
		expect(tap.args).toEqual([
			"-s",
			"emulator-5554",
			"shell",
			"input",
			"tap",
			"12",
			"34",
		]);
		await expect(
			execute({ operation: "tap", x: 1080, y: 1 }, {} as never),
		).rejects.toThrow("outside");
		const hierarchy = JSON.parse(
			await execute({ operation: "ui_hierarchy" }, {} as never),
		);
		expect(hierarchy.stdout).toContain("Hello");
		await expect(
			execute({ operation: "shell", shell_args: ["id"] }, {} as never),
		).rejects.toThrow("acknowledge_risk");
		const shell = JSON.parse(
			await execute(
				{
					operation: "shell",
					shell_args: ["sh", "-c", "id"],
					acknowledge_risk: true,
				},
				{} as never,
			),
		);
		expect(shell.args.at(-1)).toBe("<redacted>");
		await expect(
			execute(
				{
					operation: "uninstall",
					package: "com.example.app",
				},
				{} as never,
			),
		).rejects.toThrow("confirm_package_change=true");
	});
});

it("validates every requested PID against the current package process name", async () => {
	if (process.platform === "win32") return;
	await fakeAdb();
	const run = createAndroidDeviceExecutor();
	const worker = JSON.parse(
		await run(
			{
				operation: "logcat",
				package: "com.example.app",
				process_id: 4322,
				device_serial: "emulator-5554",
			},
			{} as never,
		),
	);
	expect(worker.args).toContain("4322");
	await expect(
		run(
			{
				operation: "logcat",
				package: "com.example.app",
				process_id: 4333,
				device_serial: "emulator-5554",
			},
			{} as never,
		),
	).rejects.toThrow("no longer belongs");
});
it("uses a bounded base-APK read without overwriting existing evidence", async () => {
	if (process.platform === "win32") return;
	const directory = await fakeAdb(),
		run = createAndroidDeviceExecutor(),
		output = path.join(directory, "owned.apk");
	const result = JSON.parse(
		await run(
			{
				operation: "pull_apk_bounded",
				package: "com.example.app",
				device_serial: "emulator-5554",
				output_path: output,
			},
			{} as never,
		),
	);
	expect(result.coverage).toBe("base-apk-only");
	expect(result.succeeded).toBe(true);
	expect(await fs.readFile(output, "utf8")).toBe("apk-bytes");
	await expect(
		run(
			{
				operation: "pull_apk_bounded",
				package: "com.example.app",
				device_serial: "emulator-5554",
				output_path: output,
			},
			{} as never,
		),
	).rejects.toThrow();
	const device = JSON.parse(
		await run(
			{ operation: "device_info", device_serial: "emulator-5554" },
			{} as never,
		),
	);
	expect(device.root).toBe("unverified");
	expect(device.frida).toBe("unverified");
});
