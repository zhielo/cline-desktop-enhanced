import { spawn, type ChildProcess } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";

const MAX_OUTPUT_CHARS = 200_000;

function boundedAppend(current: string, chunk: Buffer | string): string {
	if (current.length >= MAX_OUTPUT_CHARS) return current;
	return (current + chunk.toString()).slice(0, MAX_OUTPUT_CHARS);
}

function windowsBatchInvocation(
	command: string,
	args: string[],
): [string, string[]] {
	return [
		process.env.ComSpec ?? "cmd.exe",
		["/d", "/s", "/c", "call", command, ...args],
	];
}

function spawnPortable(
	command: string,
	args: string[],
	gui = false,
): ChildProcess {
	const isBatch = process.platform === "win32" && /\.(bat|cmd)$/i.test(command);
	const [executable, executableArgs] = isBatch
		? windowsBatchInvocation(command, args)
		: [command, args];
	return spawn(executable, executableArgs, {
		detached: process.platform !== "win32" || gui,
		stdio: gui ? "ignore" : ["ignore", "pipe", "pipe"],
		windowsHide: !gui,
		windowsVerbatimArguments: false,
	});
}

export async function commandAvailable(command: string): Promise<boolean> {
	if (path.isAbsolute(command)) {
		try {
			const stat = await fs.stat(command);
			if (!stat.isFile()) return false;
			if (process.platform !== "win32") {
				await fs.access(command, fsConstants.X_OK);
			}
			return true;
		} catch {
			return false;
		}
	}
	const locator = process.platform === "win32" ? "where" : "which";
	return new Promise((resolve) => {
		const child = spawn(locator, [command], {
			stdio: "ignore",
			windowsHide: true,
		});
		let settled = false;
		const finish = (available: boolean) => {
			if (settled) return;
			settled = true;
			resolve(available);
		};
		child.once("error", () => finish(false));
		child.once("close", (code) => finish(code === 0));
	});
}

function killProcessTree(child: ChildProcess): void {
	if (!child.pid) return;
	if (process.platform === "win32") {
		const killer = spawn("taskkill", ["/pid", String(child.pid), "/t", "/f"], {
			stdio: "ignore",
			windowsHide: true,
		});
		killer.unref();
		return;
	}
	try {
		process.kill(-child.pid, "SIGKILL");
	} catch {
		try {
			child.kill("SIGKILL");
		} catch {
			// The process may have exited between the timeout and termination.
		}
	}
}

export async function runSupervised(
	command: string,
	args: string[],
	timeoutMs: number,
	signal?: AbortSignal,
) {
	return new Promise<{
		exitCode: number | null;
		stdout: string;
		stderr: string;
		timedOut: boolean;
		cancelled: boolean;
	}>((resolve, reject) => {
		if (signal?.aborted) {
			resolve({
				exitCode: null,
				stdout: "",
				stderr: "",
				timedOut: false,
				cancelled: true,
			});
			return;
		}
		const child = spawnPortable(command, args);
		let stdout = "";
		let stderr = "";
		let timedOut = false;
		let cancelled = false;
		let settled = false;
		child.stdout?.on("data", (chunk) => {
			stdout = boundedAppend(stdout, chunk);
		});
		child.stderr?.on("data", (chunk) => {
			stderr = boundedAppend(stderr, chunk);
		});
		const cleanup = () => {
			clearTimeout(timer);
			signal?.removeEventListener("abort", abort);
		};
		const finish = (result: { exitCode: number | null; error?: Error }) => {
			if (settled) return;
			settled = true;
			cleanup();
			if (result.error) reject(result.error);
			else
				resolve({
					exitCode: result.exitCode,
					stdout,
					stderr,
					timedOut,
					cancelled,
				});
		};
		const timer = setTimeout(() => {
			timedOut = true;
			killProcessTree(child);
		}, timeoutMs);
		const abort = () => {
			cancelled = true;
			killProcessTree(child);
		};
		signal?.addEventListener("abort", abort, { once: true });
		child.once("error", (error) => finish({ exitCode: null, error }));
		// close fires only after stdio has drained; exit can precede the final chunks.
		child.once("close", (exitCode) => finish({ exitCode }));
	});
}

export async function launchDetachedGui(
	command: string,
	args: string[],
	startupGraceMs = 750,
): Promise<{
	launched: boolean;
	status: "started" | "exited_early" | "failed";
	pid: number | null;
	exitCode?: number | null;
	error?: string;
}> {
	return new Promise((resolve) => {
		let child: ChildProcess;
		try {
			child = spawnPortable(command, args, true);
		} catch (error) {
			resolve({
				launched: false,
				status: "failed",
				pid: null,
				error: error instanceof Error ? error.message : String(error),
			});
			return;
		}
		let settled = false;
		let timer: ReturnType<typeof setTimeout> | undefined;
		const finish = (value: {
			launched: boolean;
			status: "started" | "exited_early" | "failed";
			pid: number | null;
			exitCode?: number | null;
			error?: string;
		}) => {
			if (settled) return;
			settled = true;
			if (timer) clearTimeout(timer);
			resolve(value);
		};
		child.once("error", (error) =>
			finish({
				launched: false,
				status: "failed",
				pid: child.pid ?? null,
				error: error.message,
			}),
		);
		child.once("exit", (exitCode) =>
			finish({
				launched: false,
				status: "exited_early",
				pid: child.pid ?? null,
				exitCode,
			}),
		);
		child.once("spawn", () => {
			timer = setTimeout(() => {
				child.unref();
				finish({ launched: true, status: "started", pid: child.pid ?? null });
			}, startupGraceMs);
		});
	});
}
