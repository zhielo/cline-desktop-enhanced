import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { LiveDebuggerExecutor } from "../types";
import { commandAvailable, runSupervised } from "./supervised-process";

type Backend = "gdb" | "lldb" | "cdb";

async function discoverBackend(
	requested: "auto" | Backend,
): Promise<{ backend: Backend; command: string } | undefined> {
	const suffix = process.platform === "win32" ? ".exe" : "";
	const candidates: Array<{ backend: Backend; command: string }> =
		requested === "auto"
			? [
					{ backend: "gdb", command: `gdb${suffix}` },
					{ backend: "lldb", command: `lldb${suffix}` },
					...(process.platform === "win32"
						? [{ backend: "cdb" as const, command: "cdb.exe" }]
						: []),
				]
			: [
					{
						backend: requested,
						command: requested === "cdb" ? "cdb.exe" : `${requested}${suffix}`,
					},
				];
	for (const candidate of candidates) {
		if (await commandAvailable(candidate.command)) return candidate;
	}
	return undefined;
}

async function backendVersion(command: string): Promise<string | undefined> {
	try {
		const result = await runSupervised(
			command,
			path.basename(command).toLowerCase() === "cdb.exe"
				? ["-version"]
				: ["--version"],
			10_000,
		);
		return `${result.stdout}\n${result.stderr}`
			.trim()
			.split(/\r?\n/)
			.find(Boolean)
			?.slice(0, 300);
	} catch {
		return undefined;
	}
}

async function inspectMinidump(target: string) {
	const handle = await fs.open(target, "r");
	try {
		const header = Buffer.alloc(32);
		const { bytesRead } = await handle.read(header, 0, header.length, 0);
		if (
			bytesRead < header.length ||
			header.toString("ascii", 0, 4) !== "MDMP"
		) {
			throw new Error(
				"inspect_dump requires a Windows minidump with an MDMP header",
			);
		}
		const timestamp = header.readUInt32LE(20);
		return {
			signature: "MDMP",
			version: header.readUInt32LE(4),
			streamCount: header.readUInt32LE(8),
			streamDirectoryRva: header.readUInt32LE(12),
			checksum: header.readUInt32LE(16),
			timestamp:
				timestamp > 0 ? new Date(timestamp * 1000).toISOString() : undefined,
			flags: `0x${header.readBigUInt64LE(24).toString(16)}`,
		};
	} finally {
		await handle.close();
	}
}

function validateSymbolPath(value: string | undefined): string | undefined {
	if (!value) return undefined;
	if (/[\r\n;]/.test(value)) {
		throw new Error(
			"symbol_path cannot contain control characters or semicolons",
		);
	}
	return value;
}

function gdbArgs(input: Parameters<LiveDebuggerExecutor>[0]): string[] {
	const commands = ["set pagination off", "set confirm off"];
	if (input.pid) commands.push(`attach ${input.pid}`);
	else if (input.breakpoint) commands.push(`break ${input.breakpoint}`, "run");
	else commands.push("start");
	if (input.operation === "continue") commands.push("continue");
	if (input.operation === "step") {
		for (let index = 0; index < (input.steps ?? 1); index += 1)
			commands.push("stepi");
	}
	if (
		["launch", "attach_snapshot", "backtrace", "continue", "step"].includes(
			input.operation,
		)
	)
		commands.push("thread apply all backtrace");
	if (
		["launch", "attach_snapshot", "registers", "continue", "step"].includes(
			input.operation,
		)
	)
		commands.push("info registers");
	if (input.operation === "read_memory")
		commands.push(`x/${input.length ?? 64}bx ${input.address}`);
	if (input.operation === "disassemble")
		commands.push(`disassemble ${input.address ?? input.breakpoint ?? "main"}`);
	if (input.pid) commands.push("detach");
	commands.push("quit");
	const args = ["--batch", "--nx", "--quiet"];
	for (const command of commands) args.push("-ex", command);
	if (!input.pid && input.target)
		args.push("--args", input.target, ...(input.args ?? []));
	return args;
}

function lldbArgs(input: Parameters<LiveDebuggerExecutor>[0]): string[] {
	const commands: string[] = [];
	if (input.pid) commands.push(`process attach --pid ${input.pid}`);
	else if (input.breakpoint)
		commands.push(`breakpoint set --name ${input.breakpoint}`, "run");
	else commands.push("breakpoint set --name main", "run");
	if (input.operation === "continue") commands.push("continue");
	if (input.operation === "step") {
		for (let index = 0; index < (input.steps ?? 1); index += 1)
			commands.push("thread step-inst");
	}
	if (
		["launch", "attach_snapshot", "backtrace", "continue", "step"].includes(
			input.operation,
		)
	)
		commands.push("thread backtrace all");
	if (
		["launch", "attach_snapshot", "registers", "continue", "step"].includes(
			input.operation,
		)
	)
		commands.push("register read");
	if (input.operation === "read_memory")
		commands.push(
			`memory read --count ${input.length ?? 64} --format x --size 1 ${input.address}`,
		);
	if (input.operation === "disassemble")
		commands.push(
			`disassemble --name ${input.address ?? input.breakpoint ?? "main"}`,
		);
	if (input.pid) commands.push("process detach");
	commands.push("quit");
	const args = ["--batch", "--no-lldbinit"];
	for (const command of commands) args.push("-o", command);
	if (!input.pid && input.target)
		args.push("--", input.target, ...(input.args ?? []));
	return args;
}

export function createLiveDebuggerExecutor(): LiveDebuggerExecutor {
	return async (input, context) => {
		const available = await Promise.all(
			(["gdb", "lldb", "cdb"] as const).map(async (backend) => {
				const found = await discoverBackend(backend);
				return {
					backend,
					command: found?.command,
					version: found ? await backendVersion(found.command) : undefined,
				};
			}),
		);
		if (input.operation === "discover") {
			return JSON.stringify(
				{
					platform: process.platform,
					backends: available,
					model: "one-shot supervised debugger invocations",
					persistentSession: false,
					defaultMode: "inspect-only",
					executionControlRequiresConfirmation: true,
				},
				null,
				2,
			);
		}
		if (input.operation === "inspect_dump") {
			if (!input.target || !path.isAbsolute(input.target)) {
				throw new Error("inspect_dump requires an absolute minidump target");
			}
			const target = path.resolve(input.target);
			const stat = await fs.stat(target);
			if (!stat.isFile()) throw new Error("minidump target must be a file");
			const metadata = await inspectMinidump(target);
			const symbolPath = validateSymbolPath(input.symbol_path);
			let symbolCacheDirectory: string | undefined;
			if (input.symbol_cache_directory) {
				if (!path.isAbsolute(input.symbol_cache_directory)) {
					throw new Error("symbol_cache_directory must be an absolute path");
				}
				if (/[\r\n;*]/.test(input.symbol_cache_directory)) {
					throw new Error(
						"symbol_cache_directory cannot contain control characters, semicolons, or asterisks",
					);
				}
				symbolCacheDirectory = path.resolve(input.symbol_cache_directory);
				await fs.mkdir(symbolCacheDirectory, { recursive: true, mode: 0o700 });
			}
			const cdb = await discoverBackend("cdb");
			if (!cdb) {
				return JSON.stringify(
					{
						operation: input.operation,
						target,
						size: stat.size,
						metadata,
						debuggerAvailable: false,
						symbolPathConfigured: Boolean(symbolPath),
						symbolCacheDirectory,
						hint: "Install Debugging Tools for Windows (cdb.exe) for stack and !analyze evidence.",
					},
					null,
					2,
				);
			}
			const configuredSymbolPath =
				symbolPath && symbolCacheDirectory
					? `srv*${symbolCacheDirectory}*${symbolPath}`
					: symbolPath;
			const args = [
				...(configuredSymbolPath ? ["-y", configuredSymbolPath] : []),
				"-z",
				target,
				"-c",
				"!analyze -v;~* k;q",
			];
			const result = await runSupervised(
				cdb.command,
				args,
				input.timeout_ms ?? 120_000,
				context.signal,
			);
			return JSON.stringify(
				{
					operation: input.operation,
					target,
					size: stat.size,
					metadata,
					backend: "cdb",
					command: cdb.command,
					args: configuredSymbolPath
						? [
								"-y",
								"<configured-symbol-path>",
								"-z",
								target,
								"-c",
								args.at(-1),
							]
						: args,
					symbolPathConfigured: Boolean(configuredSymbolPath),
					symbolCacheDirectory,
					succeeded:
						result.exitCode === 0 && !result.timedOut && !result.cancelled,
					...result,
				},
				null,
				2,
			);
		}
		if (input.acknowledge_risk !== true)
			throw new Error(
				"Live debugging executes or attaches to a process; set acknowledge_risk=true after confirming authorization.",
			);
		const resumesExecution = ["continue", "step"].includes(input.operation);
		if (resumesExecution && input.confirm_execution_control !== true) {
			throw new Error(
				"continue and step resume target execution; set confirm_execution_control=true after reviewing the target.",
			);
		}
		if (input.target_kind === "remote")
			throw new Error(
				"Remote debugging is not enabled; use a local authorized target or device-specific tooling.",
			);
		const attaching = input.operation !== "launch" && Boolean(input.pid);
		if (input.operation === "launch") {
			if (!input.target || !path.isAbsolute(input.target))
				throw new Error("launch requires an absolute target path");
			const stat = await fs.stat(input.target);
			if (!stat.isFile()) throw new Error("debug target must be a file");
		} else if (!attaching) {
			throw new Error(`${input.operation} requires pid`);
		}
		if (input.operation === "read_memory" && !input.address)
			throw new Error("read_memory requires address");
		const selected = await discoverBackend(input.debugger);
		if (!selected)
			throw new Error(
				`No compatible ${input.debugger === "auto" ? "GDB or LLDB" : input.debugger.toUpperCase()} executable was found`,
			);
		if (selected.backend === "cdb") {
			throw new Error("cdb is supported only for inspect_dump");
		}
		const args = selected.backend === "gdb" ? gdbArgs(input) : lldbArgs(input);
		const result = await runSupervised(
			selected.command,
			args,
			input.timeout_ms ?? 60_000,
			context.signal,
		);
		return JSON.stringify(
			{
				operation: input.operation,
				backend: selected.backend,
				command: selected.command,
				args,
				target: input.target,
				pid: input.pid,
				executionControlConfirmed: resumesExecution,
				mode: resumesExecution ? "execution-control" : "inspect-only",
				succeeded:
					result.exitCode === 0 && !result.timedOut && !result.cancelled,
				...result,
			},
			null,
			2,
		);
	};
}
