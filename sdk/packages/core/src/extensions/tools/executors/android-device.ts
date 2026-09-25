import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { AndroidDeviceExecutor } from "../types";

const MAX_TEXT_BYTES = 200_000;
const MAX_SCREENSHOT_BYTES = 32 * 1024 * 1024;
const MAX_UI_BYTES = 4 * 1024 * 1024;

type ProcessResult = {
	exitCode: number | null;
	stdout: Buffer<ArrayBufferLike>;
	stderr: string;
	timedOut: boolean;
	cancelled: boolean;
};

async function commandAvailable(command: string): Promise<boolean> {
	const locator = process.platform === "win32" ? "where" : "which";
	return new Promise((resolve) => {
		const child = spawn(locator, [command], {
			stdio: "ignore",
			windowsHide: true,
		});
		child.once("error", () => resolve(false));
		child.once("exit", (code) => resolve(code === 0));
	});
}

async function discoverAdb(): Promise<string | undefined> {
	const binary = process.platform === "win32" ? "adb.exe" : "adb";
	const candidates = [
		process.env.ADB_PATH,
		process.env.ANDROID_HOME
			? path.join(process.env.ANDROID_HOME, "platform-tools", binary)
			: undefined,
		process.env.ANDROID_SDK_ROOT
			? path.join(process.env.ANDROID_SDK_ROOT, "platform-tools", binary)
			: undefined,
		binary,
	].filter((candidate): candidate is string => Boolean(candidate));
	for (const candidate of candidates) {
		if (path.isAbsolute(candidate)) {
			try {
				if ((await fs.stat(candidate)).isFile()) return candidate;
			} catch {}
		} else if (await commandAvailable(candidate)) return candidate;
	}
	return undefined;
}

async function runAdb(
	command: string,
	args: string[],
	timeoutMs: number,
	signal?: AbortSignal,
	maxStdoutBytes = MAX_TEXT_BYTES,
): Promise<ProcessResult> {
	return new Promise((resolve, reject) => {
		if (signal?.aborted) {
			resolve({
				exitCode: null,
				stdout: Buffer.alloc(0),
				stderr: "",
				timedOut: false,
				cancelled: true,
			});
			return;
		}
		const child = spawn(command, args, {
			windowsHide: true,
			stdio: ["ignore", "pipe", "pipe"],
		});
		let stdout: Buffer<ArrayBufferLike> = Buffer.alloc(0);
		let stderr = "";
		let timedOut = false;
		let cancelled = false;
		child.stdout?.on("data", (chunk: Buffer<ArrayBufferLike>) => {
			if (stdout.length < maxStdoutBytes) {
				stdout = Buffer.concat([
					stdout,
					chunk.subarray(0, maxStdoutBytes - stdout.length),
				]);
			}
		});
		child.stderr?.on("data", (chunk: Buffer) => {
			if (stderr.length < MAX_TEXT_BYTES) {
				stderr = `${stderr}${chunk.toString()}`.slice(0, MAX_TEXT_BYTES);
			}
		});
		const kill = () => {
			if (child.pid && process.platform === "win32") {
				spawn("taskkill", ["/pid", String(child.pid), "/t", "/f"], {
					stdio: "ignore",
					windowsHide: true,
				});
			} else child.kill("SIGKILL");
		};
		const timer = setTimeout(() => {
			timedOut = true;
			kill();
		}, timeoutMs);
		const abort = () => {
			cancelled = true;
			kill();
		};
		signal?.addEventListener("abort", abort, { once: true });
		child.once("error", (error) => {
			clearTimeout(timer);
			signal?.removeEventListener("abort", abort);
			reject(error);
		});
		// `close` fires after stdout/stderr are drained; resolving on `exit` can
		// lose the final output from short-lived adb commands such as `devices`.
		child.once("close", (exitCode) => {
			clearTimeout(timer);
			signal?.removeEventListener("abort", abort);
			resolve({ exitCode, stdout, stderr, timedOut, cancelled });
		});
	});
}

function requirePackage(value: string | undefined): string {
	if (!value) throw new Error("package is required for this operation");
	return value;
}

function requireAbsolute(
	value: string | undefined,
	label: "path" | "output_path",
): string {
	if (!value || !path.isAbsolute(value)) {
		throw new Error(`${label} must be an absolute local path`);
	}
	return path.resolve(value);
}

function selectedDevice(serial: string | undefined): string[] {
	return serial ? ["-s", serial] : [];
}

async function resolveDevice(
	adb: string,
	requested: string | undefined,
	signal?: AbortSignal,
): Promise<string> {
	const result = await runAdb(adb, ["devices", "-l"], 15_000, signal);
	if (result.exitCode !== 0)
		throw new Error(`Unable to enumerate Android devices: ${result.stderr}`);
	const devices = result.stdout
		.toString("utf8")
		.split(/\r?\n/)
		.slice(1)
		.map((line) => line.trim().split(/\s+/, 2))
		.filter(([serial]) => serial);
	if (requested) {
		const found = devices.find(([serial]) => serial === requested);
		if (!found) throw new Error(`Android device ${requested} is not attached`);
		if (found[1] !== "device")
			throw new Error(`Android device ${requested} is ${found[1]}`);
		return requested;
	}
	const ready = devices.filter(([, state]) => state === "device");
	if (ready.length === 0)
		throw new Error("No authorized Android device is attached");
	if (ready.length > 1)
		throw new Error(
			`Multiple authorized Android devices are attached; set device_serial (${ready.map(([serial]) => serial).join(", ")})`,
		);
	return ready[0][0];
}

type ScreenInfo = {
	width: number;
	height: number;
	rotation: number | null;
	orientation: "portrait" | "landscape" | "square";
};
async function screenInfo(
	adb: string,
	selected: string[],
	signal?: AbortSignal,
): Promise<ScreenInfo> {
	const [size, input] = await Promise.all([
		runAdb(adb, [...selected, "shell", "wm", "size"], 15_000, signal),
		runAdb(adb, [...selected, "shell", "dumpsys", "input"], 15_000, signal),
	]);
	const matches = [
		...size.stdout
			.toString("utf8")
			.matchAll(/(?:Physical|Override) size:\s*(\d+)x(\d+)/gi),
	];
	const match = matches.at(-1);
	if (!match) throw new Error("Unable to determine Android display size");
	const width = Number(match[1]);
	const height = Number(match[2]);
	const rotation = input.stdout
		.toString("utf8")
		.match(/SurfaceOrientation:\s*(\d+)/i);
	return {
		width,
		height,
		rotation: rotation ? Number(rotation[1]) : null,
		orientation:
			width === height ? "square" : width > height ? "landscape" : "portrait",
	};
}
function point(
	x: number | undefined,
	y: number | undefined,
	screen: ScreenInfo,
	label: string,
): [number, number] {
	if (x === undefined || y === undefined)
		throw new Error(`${label} coordinates are required`);
	if (x < 0 || x >= screen.width || y < 0 || y >= screen.height)
		throw new Error(
			`${label} (${x}, ${y}) is outside the ${screen.width}x${screen.height} display`,
		);
	return [x, y];
}
async function foreground(
	adb: string,
	selected: string[],
	packageName: string | undefined,
	signal?: AbortSignal,
) {
	if (!packageName) return;
	const result = await runAdb(
		adb,
		[...selected, "shell", "dumpsys", "window", "windows"],
		15_000,
		signal,
	);
	const focus = result.stdout
		.toString("utf8")
		.split(/\r?\n/)
		.find((line) => /mCurrentFocus|mFocusedApp/.test(line));
	if (!focus?.includes(packageName))
		throw new Error(
			`Refusing interaction because ${packageName} is not the foreground package`,
		);
}
async function evidence(
	adb: string,
	selected: string[],
	output: string,
	timeout: number,
	signal?: AbortSignal,
) {
	if (!path.isAbsolute(output))
		throw new Error("screenshot evidence path must be absolute");
	const result = await runAdb(
		adb,
		[...selected, "exec-out", "screencap", "-p"],
		timeout,
		signal,
		MAX_SCREENSHOT_BYTES,
	);
	const png =
		result.stdout.length >= 8 &&
		result.stdout
			.subarray(0, 8)
			.equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
	const succeeded = result.exitCode === 0 && png;
	if (succeeded) {
		await fs.mkdir(path.dirname(output), { recursive: true, mode: 0o700 });
		const temporary = `${output}.${process.pid}.tmp`;
		await fs.writeFile(temporary, result.stdout, { mode: 0o600 });
		await fs.rm(output, { force: true });
		await fs.rename(temporary, output);
	}
	return {
		outputPath: output,
		succeeded,
		bytes: result.stdout.length,
		sha256: succeeded
			? createHash("sha256").update(result.stdout).digest("hex")
			: undefined,
	};
}

function textResult(
	operation: string,
	command: string,
	args: string[],
	result: ProcessResult,
	started: number,
	extra: Record<string, unknown> = {},
) {
	return JSON.stringify(
		{
			operation,
			command,
			args,
			exitCode: result.exitCode,
			stdout: result.stdout.toString("utf8"),
			stderr: result.stderr,
			timedOut: result.timedOut,
			cancelled: result.cancelled,
			durationMs: Date.now() - started,
			...extra,
		},
		null,
		2,
	);
}

export function createAndroidDeviceExecutor(): AndroidDeviceExecutor {
	return async (input, context) => {
		const started = Date.now();
		const adb = await discoverAdb();
		if (!adb) {
			throw new Error(
				"Android Debug Bridge was not found. Install Android Platform Tools or set ADB_PATH/ANDROID_SDK_ROOT.",
			);
		}
		const timeoutMs = input.timeout_ms ?? 120_000;

		if (input.operation === "discover") {
			const [version, devices] = await Promise.all([
				runAdb(adb, ["version"], 15_000, context.signal),
				runAdb(adb, ["devices", "-l"], 15_000, context.signal),
			]);
			return JSON.stringify(
				{
					operation: input.operation,
					adb,
					version: version.stdout.toString("utf8").trim(),
					devices: devices.stdout.toString("utf8").trim(),
					stderr: `${version.stderr}\n${devices.stderr}`.trim(),
					durationMs: Date.now() - started,
				},
				null,
				2,
			);
		}

		if (input.operation === "devices") {
			const args = ["devices", "-l"];
			return textResult(
				input.operation,
				adb,
				args,
				await runAdb(adb, args, timeoutMs, context.signal),
				started,
			);
		}
		const deviceSerial = await resolveDevice(
			adb,
			input.device_serial,
			context.signal,
		);
		const selected = selectedDevice(deviceSerial);
		if (input.operation === "screen_info")
			return JSON.stringify(
				{
					operation: input.operation,
					deviceSerial,
					...(await screenInfo(adb, selected, context.signal)),
					durationMs: Date.now() - started,
				},
				null,
				2,
			);
		if (input.operation === "ui_hierarchy") {
			const dump = [
				...selected,
				"shell",
				"uiautomator",
				"dump",
				"/sdcard/window_dump.xml",
			];
			const dumped = await runAdb(adb, dump, timeoutMs, context.signal);
			if (dumped.exitCode !== 0)
				return textResult(input.operation, adb, dump, dumped, started);
			const args = [...selected, "exec-out", "cat", "/sdcard/window_dump.xml"];
			const result = await runAdb(
				adb,
				args,
				timeoutMs,
				context.signal,
				MAX_UI_BYTES,
			);
			if (input.output_path && result.exitCode === 0) {
				const output = requireAbsolute(input.output_path, "output_path");
				await fs.mkdir(path.dirname(output), { recursive: true, mode: 0o700 });
				await fs.writeFile(output, result.stdout, { mode: 0o600 });
			}
			return textResult(input.operation, adb, args, result, started, {
				deviceSerial,
				bytes: result.stdout.length,
			});
		}
		const interaction = [
			"tap",
			"long_press",
			"swipe",
			"key_event",
			"text_input",
		].includes(input.operation);
		if (interaction)
			await foreground(
				adb,
				selected,
				input.require_foreground_package,
				context.signal,
			);
		const beforeScreenshot = input.before_screenshot_path
			? await evidence(
					adb,
					selected,
					input.before_screenshot_path,
					timeoutMs,
					context.signal,
				)
			: undefined;
		let args: string[];
		let screen: ScreenInfo | undefined;
		let sensitive = false;
		switch (input.operation) {
			case "package_info":
				args = [
					...selected,
					"shell",
					"dumpsys",
					"package",
					requirePackage(input.package),
				];
				break;
			case "install": {
				const apk = requireAbsolute(input.path, "path");
				if (!(await fs.stat(apk)).isFile())
					throw new Error(`APK path is not a file: ${apk}`);
				args = [...selected, "install"];
				if (input.replace_existing !== false) args.push("-r");
				if (input.grant_permissions) args.push("-g");
				args.push(apk);
				break;
			}
			case "uninstall":
				args = [...selected, "uninstall"];
				if (input.keep_data) args.push("-k");
				args.push(requirePackage(input.package));
				break;
			case "launch": {
				const packageName = requirePackage(input.package);
				args = input.activity
					? [
							...selected,
							"shell",
							"am",
							"start",
							"-n",
							`${packageName}/${input.activity}`,
						]
					: [
							...selected,
							"shell",
							"monkey",
							"-p",
							packageName,
							"-c",
							"android.intent.category.LAUNCHER",
							"1",
						];
				break;
			}
			case "force_stop":
				args = [
					...selected,
					"shell",
					"am",
					"force-stop",
					requirePackage(input.package),
				];
				break;
			case "tap": {
				screen = await screenInfo(adb, selected, context.signal);
				const [x, y] = point(input.x, input.y, screen, "tap");
				args = [...selected, "shell", "input", "tap", String(x), String(y)];
				break;
			}
			case "long_press": {
				screen = await screenInfo(adb, selected, context.signal);
				const [x, y] = point(input.x, input.y, screen, "long_press");
				args = [
					...selected,
					"shell",
					"input",
					"swipe",
					String(x),
					String(y),
					String(x),
					String(y),
					String(input.duration_ms ?? 750),
				];
				break;
			}
			case "swipe": {
				screen = await screenInfo(adb, selected, context.signal);
				const [sx, sy] = point(
					input.start_x,
					input.start_y,
					screen,
					"swipe start",
				);
				const [ex, ey] = point(input.end_x, input.end_y, screen, "swipe end");
				args = [
					...selected,
					"shell",
					"input",
					"swipe",
					String(sx),
					String(sy),
					String(ex),
					String(ey),
					String(input.duration_ms ?? 300),
				];
				break;
			}
			case "key_event":
				if (!input.key_code) throw new Error("key_code is required");
				args = [
					...selected,
					"shell",
					"input",
					"keyevent",
					`KEYCODE_${input.key_code}`,
				];
				break;
			case "text_input":
				if (input.text === undefined) throw new Error("text is required");
				args = [
					...selected,
					"shell",
					"input",
					"text",
					input.text.replaceAll("%", "%25").replaceAll(" ", "%s"),
				];
				sensitive = true;
				break;
			case "shell":
				if (!input.acknowledge_risk)
					throw new Error(
						"acknowledge_risk must be true for unrestricted adb shell",
					);
				if (!input.shell_args?.length)
					throw new Error("shell_args is required");
				args = [...selected, "shell", ...input.shell_args];
				sensitive = true;
				break;
			case "processes":
				args = [...selected, "shell", "ps", "-A"];
				break;
			case "crash_logs":
				if (input.clear_logcat)
					await runAdb(
						adb,
						[...selected, "logcat", "-c"],
						15_000,
						context.signal,
					);
				args = [
					...selected,
					"logcat",
					"-d",
					"-b",
					"crash",
					"-t",
					String(input.lines ?? 500),
				];
				break;
			case "logcat": {
				if (input.clear_logcat)
					await runAdb(
						adb,
						[...selected, "logcat", "-c"],
						15_000,
						context.signal,
					);
				if (input.package) {
					const pidResult = await runAdb(
						adb,
						[...selected, "shell", "pidof", input.package],
						15_000,
						context.signal,
					);
					const pid = pidResult.stdout.toString("utf8").trim().split(/\s+/)[0];
					if (!pid)
						throw new Error(
							`Package ${input.package} is not running; launch it before requesting PID-filtered logcat`,
						);
					args = [
						...selected,
						"logcat",
						"-d",
						"--pid",
						pid,
						"-t",
						String(input.lines ?? 1_000),
					];
				} else {
					args = [
						...selected,
						"logcat",
						"-d",
						"-t",
						String(input.lines ?? 1_000),
					];
				}
				break;
			}
			case "pull_apk": {
				const packageName = requirePackage(input.package);
				const output = requireAbsolute(input.output_path, "output_path");
				const paths = await runAdb(
					adb,
					[...selected, "shell", "pm", "path", packageName],
					15_000,
					context.signal,
				);
				const remote = paths.stdout
					.toString("utf8")
					.split(/\r?\n/)
					.map((line) => line.trim())
					.find((line) => line.startsWith("package:"))
					?.slice("package:".length);
				if (!remote)
					throw new Error(
						`Unable to resolve the installed base APK for ${packageName}: ${paths.stderr}`,
					);
				await fs.mkdir(path.dirname(output), { recursive: true, mode: 0o700 });
				const temporary = `${output}.${process.pid}.${Date.now()}.tmp.apk`;
				const result = await runAdb(
					adb,
					[...selected, "pull", remote, temporary],
					timeoutMs,
					context.signal,
				);
				const succeeded =
					result.exitCode === 0 &&
					!result.timedOut &&
					!result.cancelled &&
					(await fs
						.stat(temporary)
						.then((stat) => stat.isFile())
						.catch(() => false));
				if (succeeded) {
					await fs.rm(output, { force: true });
					await fs.rename(temporary, output);
				} else await fs.rm(temporary, { force: true });
				return textResult(
					input.operation,
					adb,
					[...selected, "pull", remote, temporary],
					result,
					started,
					{ outputPath: output, remotePath: remote, succeeded },
				);
			}
			case "screenshot": {
				const output = requireAbsolute(input.output_path, "output_path");
				await fs.mkdir(path.dirname(output), { recursive: true, mode: 0o700 });
				const captureArgs = [...selected, "exec-out", "screencap", "-p"];
				const result = await runAdb(
					adb,
					captureArgs,
					timeoutMs,
					context.signal,
					MAX_SCREENSHOT_BYTES,
				);
				const png =
					result.stdout.length >= 8 &&
					result.stdout
						.subarray(0, 8)
						.equals(
							Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
						);
				if (result.exitCode === 0 && png) {
					const temporary = `${output}.${process.pid}.${Date.now()}.tmp`;
					await fs.writeFile(temporary, result.stdout, { mode: 0o600 });
					await fs.rm(output, { force: true });
					await fs.rename(temporary, output);
				}
				return JSON.stringify(
					{
						operation: input.operation,
						command: adb,
						args: captureArgs,
						exitCode: result.exitCode,
						stderr: result.stderr,
						timedOut: result.timedOut,
						cancelled: result.cancelled,
						outputPath: output,
						succeeded: result.exitCode === 0 && png,
						bytes: result.stdout.length,
						durationMs: Date.now() - started,
					},
					null,
					2,
				);
			}
			case "bugreport": {
				const output = requireAbsolute(input.output_path, "output_path");
				await fs.mkdir(path.dirname(output), { recursive: true, mode: 0o700 });
				args = [...selected, "bugreport", output];
				break;
			}
		}
		const result = await runAdb(adb, args, timeoutMs, context.signal);
		const afterScreenshot = input.after_screenshot_path
			? await evidence(
					adb,
					selected,
					input.after_screenshot_path,
					timeoutMs,
					context.signal,
				)
			: undefined;
		return textResult(
			input.operation,
			adb,
			sensitive ? [...selected, "shell", "<redacted>"] : args,
			result,
			started,
			{
				deviceSerial,
				screen,
				beforeScreenshot,
				afterScreenshot,
				screenChanged:
					beforeScreenshot?.sha256 && afterScreenshot?.sha256
						? beforeScreenshot.sha256 !== afterScreenshot.sha256
						: undefined,
				argumentCount: sensitive
					? args.length - selected.length - 1
					: undefined,
			},
		);
	};
}
