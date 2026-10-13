import { execFile, spawnSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { win32 } from "node:path";
import { readFile } from "node:fs/promises";

const PROCESS_PROBE_TIMEOUT_MS = 2_000;
const PROCESS_PROBE_MAX_BUFFER_BYTES = 4_096;
/** Cold Windows PowerShell startup may exceed 2s. Async probes do not block heartbeats. */
export function processStartProbeTimeoutMs(
	asynchronous: boolean,
	platform: NodeJS.Platform = process.platform,
) {
	return asynchronous && platform === "win32"
		? 5_000
		: PROCESS_PROBE_TIMEOUT_MS;
}

export type ProcessStartTokenProbeResult =
	| { status: "found"; token: string }
	| { status: "missing" }
	| { status: "unavailable" };

type ProcessExistence = "running" | "missing" | "unavailable";

type ProcessStartCommand = {
	file: string;
	args: string[];
	env?: NodeJS.ProcessEnv;
};

/** Prefer installed System-wide PowerShell 7; never resolve identity interpreters from PATH/CWD. */
export function resolveWindowsProcessStartCommand(
	pid: number,
	env: NodeJS.ProcessEnv,
	available: (file: string) => boolean,
): ProcessStartCommand | undefined {
	if (!Number.isSafeInteger(pid) || pid <= 0 || pid > 4294967295)
		return undefined;
	const local = (p: string | undefined): p is string =>
		!!p && /^[a-z]:[\\/]/i.test(p) && !p.includes("\0");
	const candidates: string[] = [];
	if (local(env.ProgramFiles))
		candidates.push(
			win32.join(env.ProgramFiles, "PowerShell", "7", "pwsh.exe"),
		);
	if (local(env.SystemRoot))
		candidates.push(
			win32.join(
				env.SystemRoot,
				"System32",
				"WindowsPowerShell",
				"v1.0",
				"powershell.exe",
			),
		);
	const file = candidates.find(available);
	if (!file) return undefined;
	return {
		file,
		args: [
			"-NoLogo",
			"-NoProfile",
			"-NonInteractive",
			"-Command",
			`[Console]::Write((Get-Process -Id ${pid} -ErrorAction Stop).StartTime.ToUniversalTime().Ticks.ToString([Globalization.CultureInfo]::InvariantCulture))`,
		],
	};
}

/** Exact DateTime ticks, not a PID-only token, a rounded timestamp or localized display value. */
export function parseWindowsProcessStartToken(
	output: string,
): string | undefined {
	const value = output.trim();
	if (
		!/^[1-9]\d{0,18}$/.test(value) ||
		BigInt(value) > BigInt("3155378975999999999")
	)
		return undefined;
	return `win32:${value}`;
}

function resolveProcessStartCommand(pid: number): ProcessStartCommand {
	if (process.platform === "win32") {
		const command = resolveWindowsProcessStartCommand(
			pid,
			process.env,
			(file) => {
				try {
					return statSync(file).isFile();
				} catch {
					return false;
				}
			},
		);
		if (!command)
			throw new Error(
				"Trusted Windows process identity interpreter unavailable",
			);
		return command;
	}
	return {
		file: "ps",
		args: ["-p", String(pid), "-o", "lstart="],
		env: { ...process.env, LC_ALL: "C", TZ: "UTC" },
	};
}

function getProcessExistence(pid: number): ProcessExistence {
	if (!Number.isSafeInteger(pid) || pid <= 0) return "missing";
	try {
		process.kill(pid, 0);
		return "running";
	} catch (error) {
		const code =
			error instanceof Error && "code" in error
				? String((error as NodeJS.ErrnoException).code)
				: undefined;
		if (code === "ESRCH") return "missing";
		if (code === "EPERM") return "running";
		return "unavailable";
	}
}

function classifyFailedProbe(pid: number): ProcessStartTokenProbeResult {
	return getProcessExistence(pid) === "missing"
		? { status: "missing" }
		: { status: "unavailable" };
}

function formatExternalProcessStartToken(
	output: string,
): ProcessStartTokenProbeResult | undefined {
	if (process.platform === "win32") {
		const token = parseWindowsProcessStartToken(output);
		return token ? { status: "found", token } : undefined;
	}
	const startTime = output.trim();
	return startTime
		? { status: "found", token: `${process.platform}:${startTime}` }
		: undefined;
}

type LinuxProcessStatResult =
	| { status: "running"; startTime: string }
	| { status: "missing" }
	| { status: "unavailable" };

function parseLinuxProcessStat(stat: string): LinuxProcessStatResult {
	const commandEnd = stat.lastIndexOf(")");
	if (commandEnd < 0) return { status: "unavailable" };

	// Fields after the command name begin at field 3 (state), so field 22
	// (starttime) is index 19. Use the final ')' because Linux permits ')' in
	// the parenthesized command name.
	const fields = stat
		.slice(commandEnd + 1)
		.trim()
		.split(/\s+/);
	if (["Z", "X", "x"].includes(fields[0] ?? "")) {
		return { status: "missing" };
	}
	const startTime = fields[19];
	return startTime && /^\d+$/.test(startTime)
		? { status: "running", startTime }
		: { status: "unavailable" };
}

export function parseLinuxProcessStartToken(
	stat: string,
	bootId: string,
): string | undefined {
	const processStat = parseLinuxProcessStat(stat);
	const normalizedBootId = bootId.trim();
	return processStat.status === "running" && normalizedBootId
		? `linux:${normalizedBootId}:${processStat.startTime}`
		: undefined;
}

function probeLinuxProcessStartToken(
	pid: number,
	read: (path: string) => string,
): ProcessStartTokenProbeResult {
	let stat: string;
	try {
		stat = read(`/proc/${pid}/stat`);
	} catch {
		return classifyFailedProbe(pid);
	}
	const processStat = parseLinuxProcessStat(stat);
	if (processStat.status !== "running") return processStat;

	let bootId: string;
	try {
		bootId = read("/proc/sys/kernel/random/boot_id").trim();
	} catch {
		return { status: "unavailable" };
	}
	return bootId
		? {
				status: "found",
				token: `linux:${bootId}:${processStat.startTime}`,
			}
		: { status: "unavailable" };
}

/** Distinguishes an absent process from an unavailable identity probe. */
export function probeProcessStartToken(
	pid: number,
): ProcessStartTokenProbeResult {
	if (!Number.isSafeInteger(pid) || pid <= 0) return { status: "missing" };

	if (process.platform === "linux") {
		return probeLinuxProcessStartToken(pid, (path) =>
			readFileSync(path, "utf8"),
		);
	}

	const existence = getProcessExistence(pid);
	if (existence !== "running") return { status: existence };
	try {
		const command = resolveProcessStartCommand(pid);
		const result = spawnSync(command.file, command.args, {
			encoding: "utf8",
			env: command.env,
			maxBuffer: PROCESS_PROBE_MAX_BUFFER_BYTES,
			stdio: ["ignore", "pipe", "ignore"],
			timeout: PROCESS_PROBE_TIMEOUT_MS,
			windowsHide: true,
		});
		if (result.status === 0 && typeof result.stdout === "string") {
			const token = formatExternalProcessStartToken(result.stdout);
			if (token) return token;
		}
		return classifyFailedProbe(pid);
	} catch {
		return classifyFailedProbe(pid);
	}
}

/**
 * Returns a token for one generation of a process ID.
 *
 * A PID alone is not an identity because the operating system can reuse it
 * after a process exits. The token is derived from the kernel-reported process
 * start time so callers can distinguish a live process from a later process
 * that inherited the same PID.
 */
export function getProcessStartToken(pid: number): string | undefined {
	const result = probeProcessStartToken(pid);
	return result.status === "found" ? result.token : undefined;
}

/** Non-blocking probe for latency-sensitive runtime paths. */
export async function probeProcessStartTokenAsync(
	pid: number,
): Promise<ProcessStartTokenProbeResult> {
	if (!Number.isSafeInteger(pid) || pid <= 0) return { status: "missing" };

	if (process.platform === "linux") {
		let stat: string;
		try {
			stat = await readFile(`/proc/${pid}/stat`, "utf8");
		} catch {
			return classifyFailedProbe(pid);
		}
		const processStat = parseLinuxProcessStat(stat);
		if (processStat.status !== "running") return processStat;

		try {
			const bootId = (
				await readFile("/proc/sys/kernel/random/boot_id", "utf8")
			).trim();
			return bootId
				? {
						status: "found",
						token: `linux:${bootId}:${processStat.startTime}`,
					}
				: { status: "unavailable" };
		} catch {
			return { status: "unavailable" };
		}
	}

	const existence = getProcessExistence(pid);
	if (existence !== "running") return { status: existence };
	try {
		const command = resolveProcessStartCommand(pid);
		return await new Promise((resolve) => {
			execFile(
				command.file,
				command.args,
				{
					encoding: "utf8",
					env: command.env,
					maxBuffer: PROCESS_PROBE_MAX_BUFFER_BYTES,
					timeout: processStartProbeTimeoutMs(true),
					windowsHide: true,
				},
				(error, stdout) => {
					const token =
						!error && typeof stdout === "string"
							? formatExternalProcessStartToken(stdout)
							: undefined;
					resolve(token ?? classifyFailedProbe(pid));
				},
			);
		});
	} catch {
		return classifyFailedProbe(pid);
	}
}

export async function getProcessStartTokenAsync(
	pid: number,
): Promise<string | undefined> {
	const result = await probeProcessStartTokenAsync(pid);
	return result.status === "found" ? result.token : undefined;
}
