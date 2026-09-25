from pathlib import Path
import textwrap


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    source = p.read_text()
    if source.count(old) != 1:
        raise RuntimeError(f"{path}: expected exactly one occurrence, found {source.count(old)}: {old[:120]!r}")
    p.write_text(source.replace(old, new, 1))


def write(path: str, content: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(content).lstrip())


write("sdk/packages/core/src/extensions/tools/executors/supervised-process.ts", r'''
import { spawn, type ChildProcess } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";

const MAX_OUTPUT_CHARS = 200_000;

function boundedAppend(current: string, chunk: Buffer | string): string {
	if (current.length >= MAX_OUTPUT_CHARS) return current;
	return (current + chunk.toString()).slice(0, MAX_OUTPUT_CHARS);
}

function windowsBatchInvocation(command: string, args: string[]): [string, string[]] {
	return [
		process.env.ComSpec ?? "cmd.exe",
		["/d", "/s", "/c", "call", command, ...args],
	];
}

function spawnPortable(command: string, args: string[], gui = false): ChildProcess {
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
		const killer = spawn(
			"taskkill",
			["/pid", String(child.pid), "/t", "/f"],
			{ stdio: "ignore", windowsHide: true },
		);
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
			resolve({ exitCode: null, stdout: "", stderr: "", timedOut: false, cancelled: true });
			return;
		}
		const child = spawnPortable(command, args);
		let stdout = "";
		let stderr = "";
		let timedOut = false;
		let cancelled = false;
		let settled = false;
		child.stdout?.on("data", (chunk) => { stdout = boundedAppend(stdout, chunk); });
		child.stderr?.on("data", (chunk) => { stderr = boundedAppend(stderr, chunk); });
		const cleanup = () => {
			clearTimeout(timer);
			signal?.removeEventListener("abort", abort);
		};
		const finish = (result: { exitCode: number | null; error?: Error }) => {
			if (settled) return;
			settled = true;
			cleanup();
			if (result.error) reject(result.error);
			else resolve({ exitCode: result.exitCode, stdout, stderr, timedOut, cancelled });
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
			resolve({ launched: false, status: "failed", pid: null, error: error instanceof Error ? error.message : String(error) });
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
		child.once("error", (error) => finish({ launched: false, status: "failed", pid: child.pid ?? null, error: error.message }));
		child.once("exit", (exitCode) => finish({ launched: false, status: "exited_early", pid: child.pid ?? null, exitCode }));
		child.once("spawn", () => {
			timer = setTimeout(() => {
				child.unref();
				finish({ launched: true, status: "started", pid: child.pid ?? null });
			}, startupGraceMs);
		});
	});
}
''')

write("sdk/packages/core/src/extensions/tools/executors/live-debugger.ts", r'''
import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { LiveDebuggerExecutor } from "../types";
import { commandAvailable, runSupervised } from "./supervised-process";

type Backend = "gdb" | "lldb";

async function discoverBackend(requested: "auto" | Backend): Promise<{ backend: Backend; command: string } | undefined> {
	const suffix = process.platform === "win32" ? ".exe" : "";
	const candidates: Array<{ backend: Backend; command: string }> = requested === "auto"
		? [{ backend: "gdb", command: `gdb${suffix}` }, { backend: "lldb", command: `lldb${suffix}` }]
		: [{ backend: requested, command: `${requested}${suffix}` }];
	for (const candidate of candidates) {
		if (await commandAvailable(candidate.command)) return candidate;
	}
	return undefined;
}

async function backendVersion(command: string): Promise<string | undefined> {
	try {
		const result = await runSupervised(command, ["--version"], 10_000);
		return `${result.stdout}\n${result.stderr}`.trim().split(/\r?\n/).find(Boolean)?.slice(0, 300);
	} catch {
		return undefined;
	}
}

function gdbArgs(input: Parameters<LiveDebuggerExecutor>[0]): string[] {
	const commands = ["set pagination off", "set confirm off"];
	if (input.pid) commands.push(`attach ${input.pid}`);
	else if (input.breakpoint) commands.push(`break ${input.breakpoint}`, "run");
	else commands.push("start");
	if (input.operation === "continue") commands.push("continue");
	if (input.operation === "step") {
		for (let index = 0; index < (input.steps ?? 1); index += 1) commands.push("stepi");
	}
	if (["launch", "attach_snapshot", "backtrace", "continue", "step"].includes(input.operation)) commands.push("thread apply all backtrace");
	if (["launch", "attach_snapshot", "registers", "continue", "step"].includes(input.operation)) commands.push("info registers");
	if (input.operation === "read_memory") commands.push(`x/${input.length ?? 64}bx ${input.address}`);
	if (input.operation === "disassemble") commands.push(`disassemble ${input.address ?? input.breakpoint ?? "main"}`);
	if (input.pid) commands.push("detach");
	commands.push("quit");
	const args = ["--batch", "--nx", "--quiet"];
	for (const command of commands) args.push("-ex", command);
	if (!input.pid && input.target) args.push("--args", input.target, ...(input.args ?? []));
	return args;
}

function lldbArgs(input: Parameters<LiveDebuggerExecutor>[0]): string[] {
	const commands: string[] = [];
	if (input.pid) commands.push(`process attach --pid ${input.pid}`);
	else if (input.breakpoint) commands.push(`breakpoint set --name ${input.breakpoint}`, "run");
	else commands.push("breakpoint set --name main", "run");
	if (input.operation === "continue") commands.push("continue");
	if (input.operation === "step") {
		for (let index = 0; index < (input.steps ?? 1); index += 1) commands.push("thread step-inst");
	}
	if (["launch", "attach_snapshot", "backtrace", "continue", "step"].includes(input.operation)) commands.push("thread backtrace all");
	if (["launch", "attach_snapshot", "registers", "continue", "step"].includes(input.operation)) commands.push("register read");
	if (input.operation === "read_memory") commands.push(`memory read --count ${input.length ?? 64} --format x --size 1 ${input.address}`);
	if (input.operation === "disassemble") commands.push(`disassemble --name ${input.address ?? input.breakpoint ?? "main"}`);
	if (input.pid) commands.push("process detach");
	commands.push("quit");
	const args = ["--batch", "--no-lldbinit"];
	for (const command of commands) args.push("-o", command);
	if (!input.pid && input.target) args.push("--", input.target, ...(input.args ?? []));
	return args;
}

export function createLiveDebuggerExecutor(): LiveDebuggerExecutor {
	return async (input, context) => {
		const available = await Promise.all((["gdb", "lldb"] as const).map(async (backend) => {
			const found = await discoverBackend(backend);
			return { backend, command: found?.command, version: found ? await backendVersion(found.command) : undefined };
		}));
		if (input.operation === "discover") {
			return JSON.stringify({ platform: process.platform, backends: available, model: "one-shot supervised debugger invocations", persistentSession: false }, null, 2);
		}
		if (input.acknowledge_risk !== true) throw new Error("Live debugging executes or attaches to a process; set acknowledge_risk=true after confirming authorization.");
		if (input.target_kind === "remote") throw new Error("Remote debugging is not enabled; use a local authorized target or device-specific tooling.");
		const attaching = input.operation !== "launch" && Boolean(input.pid);
		if (input.operation === "launch") {
			if (!input.target || !path.isAbsolute(input.target)) throw new Error("launch requires an absolute target path");
			const stat = await fs.stat(input.target);
			if (!stat.isFile()) throw new Error("debug target must be a file");
		} else if (!attaching) {
			throw new Error(`${input.operation} requires pid`);
		}
		if (input.operation === "read_memory" && !input.address) throw new Error("read_memory requires address");
		const selected = await discoverBackend(input.debugger);
		if (!selected) throw new Error(`No compatible ${input.debugger === "auto" ? "GDB or LLDB" : input.debugger.toUpperCase()} executable was found`);
		const args = selected.backend === "gdb" ? gdbArgs(input) : lldbArgs(input);
		const result = await runSupervised(selected.command, args, input.timeout_ms ?? 60_000, context.signal);
		return JSON.stringify({
			operation: input.operation,
			backend: selected.backend,
			command: selected.command,
			args,
			target: input.target,
			pid: input.pid,
			succeeded: result.exitCode === 0 && !result.timedOut && !result.cancelled,
			...result,
		}, null, 2);
	};
}
''')

write("sdk/packages/core/src/extensions/tools/executors/supervised-process.test.ts", r'''
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { commandAvailable, launchDetachedGui, runSupervised } from "./supervised-process";

async function script(body: string) {
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), "cline-supervisor space-"));
	const target = path.join(directory, "tool with spaces");
	await fs.writeFile(target, `#!/bin/sh\n${body}\n`, { mode: 0o700 });
	return { directory, target };
}

describe("supervised process lifecycle", () => {
	it("accepts executable paths with spaces and drains final output", async () => {
		const fixture = await script('printf "first\\n"; printf "final\\n"');
		try {
			expect(await commandAvailable(fixture.target)).toBe(true);
			const result = await runSupervised(fixture.target, [], 5_000);
			expect(result.exitCode).toBe(0);
			expect(result.stdout).toBe("first\nfinal\n");
		} finally { await fs.rm(fixture.directory, { recursive: true, force: true }); }
	});

	it("reports an immediately failing GUI instead of optimistic success", async () => {
		const fixture = await script("exit 7");
		try {
			const result = await launchDetachedGui(fixture.target, [], 300);
			expect(result).toMatchObject({ launched: false, status: "exited_early", exitCode: 7 });
		} finally { await fs.rm(fixture.directory, { recursive: true, force: true }); }
	});

	it("marks timed-out process groups", async () => {
		const fixture = await script("sleep 30");
		try {
			const result = await runSupervised(fixture.target, [], 50);
			expect(result.timedOut).toBe(true);
		} finally { await fs.rm(fixture.directory, { recursive: true, force: true }); }
	});
});
''')

write("sdk/packages/core/src/extensions/tools/executors/live-debugger.test.ts", r'''
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createLiveDebuggerExecutor } from "./live-debugger";

const originalPath = process.env.PATH;
const directories: string[] = [];
afterEach(async () => {
	process.env.PATH = originalPath;
	await Promise.all(directories.splice(0).map((entry) => fs.rm(entry, { recursive: true, force: true })));
});

it("discovers and invokes a supervised one-shot debugger", async () => {
	if (process.platform === "win32") return;
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), "cline-debugger-"));
	directories.push(directory);
	const gdb = path.join(directory, "gdb");
	await fs.writeFile(gdb, '#!/bin/sh\nprintf "%s\\n" "$@"\n', { mode: 0o700 });
	process.env.PATH = `${directory}${path.delimiter}${originalPath ?? ""}`;
	const target = path.join(directory, "sample program");
	await fs.writeFile(target, "sample", { mode: 0o700 });
	const execute = createLiveDebuggerExecutor();
	const discovery = JSON.parse(await execute({ operation: "discover", debugger: "auto", target_kind: "local" }, {} as never));
	expect(discovery.backends.find((entry: { backend: string }) => entry.backend === "gdb").command).toBe("gdb");
	const result = JSON.parse(await execute({ operation: "launch", debugger: "gdb", target_kind: "local", target, acknowledge_risk: true }, {} as never));
	expect(result.exitCode).toBe(0);
	expect(result.args).toEqual(expect.arrayContaining(["--args", target]));
});

it("requires explicit risk acknowledgement", async () => {
	await expect(createLiveDebuggerExecutor()({ operation: "backtrace", debugger: "auto", target_kind: "local", pid: 123 }, {} as never)).rejects.toThrow("acknowledge_risk=true");
});
''')

write("docs/LIVE_DEBUGGING.md", r'''
# Supervised live debugging

Cline Enhanced exposes live debugging separately from static reverse engineering. The `live_debugger` tool uses an installed GDB or LLDB executable for bounded, one-shot local debugger invocations.

## Safety contract

- Every operation except `discover` requires `acknowledge_risk: true`.
- The caller must own or be explicitly authorized to inspect the process or executable.
- Targets launched under the debugger must be absolute local file paths.
- Attach operations require an explicit positive PID.
- Remote debugging is rejected; use device-specific tooling for authorized devices.
- There is no hidden persistent debugger connection. Each request launches one supervised debugger process, gathers bounded output, detaches when applicable, and exits.
- Timeouts and cancellation terminate the debugger process tree.

## Operations

- `discover`: report available GDB/LLDB commands and versions.
- `launch`: start an authorized executable under a debugger, stop at a named breakpoint or program entry, and collect a backtrace and registers.
- `attach_snapshot`: attach, collect a backtrace and registers, detach, and exit.
- `backtrace`, `registers`, `read_memory`, and `disassemble`: bounded one-shot inspection of an attached process.
- `continue` and `step`: perform bounded execution from the initial stopped state, collect evidence, detach, and exit.

This interface deliberately does not accept arbitrary debugger command strings, silently elevate privileges, bypass operating-system protections, or maintain a background session.
''')

# Refactor reverse engineering onto the shared supervisor.
replace_once("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts",
'import type { ReverseEngineeringExecutor } from "../types";\n',
'import type { ReverseEngineeringExecutor } from "../types";\nimport { commandAvailable, launchDetachedGui, runSupervised } from "./supervised-process";\n')
start = Path("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts").read_text()
block_start = start.index("async function commandAvailable(command: string): Promise<boolean> {")
block_end = start.index("\nasync function discover(", block_start)
Path("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts").write_text(start[:block_start] + start[block_end + 1:])
start = Path("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts").read_text()
block_start = start.index("function spawnPortable(command: string, args: string[]) {")
block_end = start.index("\nasync function toolVersion(", block_start)
Path("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts").write_text(start[:block_start] + start[block_end + 1:])
start = Path("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts").read_text()
block_start = start.index("function launchGui(command: string, args: string[]) {")
block_end = start.index("\nexport function createReverseEngineeringExecutor", block_start)
Path("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts").write_text(start[:block_start] + start[block_end + 1:])
replace_once("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts", "\t\t\t\t\t\t...launchGui(command, args),", "\t\t\t\t\t\t...(await launchDetachedGui(command, args)),")

# Cross-platform roots and broader IDA names.
replace_once("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts", "async function windowsInstallRoots(engine: Engine): Promise<string[]> {\n\tif (process.platform !== \"win32\") return [];", "async function platformInstallRoots(engine: Engine): Promise<string[]> {\n\tif (process.platform !== \"win32\") {\n\t\tconst parents = process.platform === \"darwin\"\n\t\t\t? [\"/Applications\", path.join(os.homedir(), \"Applications\"), \"/opt\", \"/usr/local\", os.homedir()]\n\t\t\t: [\"/opt\", \"/usr/local\", os.homedir()];\n\t\tconst prefixes = engine === \"ghidra\" ? [\"ghidra\", \"Ghidra\"] : engine === \"ida\" ? [\"IDA Professional\", \"IDA Pro\", \"ida\", \"idapro\"] : [\"jadx\"];\n\t\tconst roots: string[] = [];\n\t\tfor (const parent of parents) roots.push(...(await listMatchingDirectories(parent, prefixes)));\n\t\treturn [...new Set(roots)];\n\t}")
replace_once("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts", "\tconst discoveredRoots = await windowsInstallRoots(engine);", "\tconst discoveredRoots = await platformInstallRoots(engine);")
replace_once("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts", 'const names = win\n\t\t\t? ["idat64.exe", "ida64.exe", "idat.exe", "ida.exe"]\n\t\t\t: ["idat64", "ida64", "idat", "ida"];', 'const names = win\n\t\t\t? ["idat64.exe", "ida64.exe", "idat.exe", "ida.exe"]\n\t\t\t: ["idat64", "ida64", "idat", "ida", "idat32", "ida32"];')
replace_once("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts", "\t\treturn [\n\t\t\t...roots.flatMap((root) => names.map((name) => path.join(root, name))),\n\t\t\t...names,\n\t\t];\n\t}\n\tconst home = process.env.JADX_HOME;", "\t\treturn [\n\t\t\t...roots.flatMap((root) => names.flatMap((name) => [\n\t\t\t\tpath.join(root, name),\n\t\t\t\tpath.join(root, \"Contents\", \"MacOS\", name),\n\t\t\t])),\n\t\t\t...names,\n\t\t];\n\t}\n\tconst home = process.env.JADX_HOME;")
replace_once("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts", "\t\t\t...roots.flatMap((root) => [\n\t\t\t\tpath.join(\n\t\t\t\t\troot,", "\t\t\t...roots.flatMap((root) => [\n\t\t\t\tpath.join(\n\t\t\t\t\troot,")
# Add macOS Ghidra bundle candidates without disturbing existing paths.
replace_once("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts", "\t\t\t\tpath.join(root, win ? \"ghidraRun.bat\" : \"ghidraRun\"),\n\t\t\t]),", "\t\t\t\tpath.join(root, win ? \"ghidraRun.bat\" : \"ghidraRun\"),\n\t\t\t\tpath.join(root, \"Contents\", \"Resources\", \"ghidra\", \"support\", \"analyzeHeadless\"),\n\t\t\t\tpath.join(root, \"Contents\", \"Resources\", \"ghidra\", \"ghidraRun\"),\n\t\t\t]),")

# Version/capability identity and cache compatibility.
replace_once("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts", 'const ANALYSIS_MANIFEST = "cline-analysis.json";', 'const ANALYSIS_MANIFEST = "cline-analysis.json";\nconst ANALYSIS_SCHEMA_VERSION = 2;\nconst GHIDRA_SCRIPT_VERSION = 2;')
replace_once("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts", "async function toolVersion(\n\tengine: Engine,\n\tcommand: string | undefined,\n): Promise<string | undefined> {\n\tif (!command) return undefined;\n\tif (engine === \"ghidra\" || engine === \"ida\") {\n\t\tconst root = installationRoot(command, engine);\n\t\treturn root ? path.basename(root) : undefined;\n\t}\n\ttry {\n\t\tconst result = await runSupervised(command, [\"--version\"], 10_000);\n\t\tconst version = `${result.stdout}\\n${result.stderr}`\n\t\t\t.trim()\n\t\t\t.split(/\\r?\\n/)\n\t\t\t.find(Boolean);\n\t\treturn version?.slice(0, 300);\n\t} catch {\n\t\treturn undefined;\n\t}\n}", r'''async function toolIdentity(engine: Engine, command: string | undefined) {
	if (!command) return { version: undefined, versionSource: undefined, executable: undefined };
	const root = installationRoot(command, engine);
	if (engine === "ghidra" && root) {
		for (const propertiesPath of [path.join(root, "Ghidra", "application.properties"), path.join(root, "application.properties")]) {
			const source = await fs.readFile(propertiesPath, "utf8").catch(() => "");
			const version = /^application\.version\s*=\s*(.+)$/m.exec(source)?.[1]?.trim();
			if (version) return { version, versionSource: propertiesPath, executable: command, installDirectory: root };
		}
	}
	if (engine === "ida" && root) {
		for (const versionPath of [path.join(root, "version.txt"), path.join(root, "ida.version")]) {
			const version = (await fs.readFile(versionPath, "utf8").catch(() => "")).trim().split(/\r?\n/).find(Boolean);
			if (version) return { version: version.slice(0, 300), versionSource: versionPath, executable: command, installDirectory: root };
		}
	}
	if (engine === "jadx") {
		try {
			const result = await runSupervised(command, ["--version"], 10_000);
			const version = `${result.stdout}\n${result.stderr}`.trim().split(/\r?\n/).find(Boolean)?.slice(0, 300);
			return { version, versionSource: "--version", executable: command, installDirectory: root };
		} catch { /* discovery remains best effort */ }
	}
	return { version: root ? path.basename(root) : path.basename(command), versionSource: root ? "directory-name" : "executable-name", executable: command, installDirectory: root };
}

async function toolVersion(engine: Engine, command: string | undefined): Promise<string | undefined> {
	return (await toolIdentity(engine, command)).version;
}''')
replace_once("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts", "async function installationCapabilities(\n\tavailable: ToolInventory,", r'''async function detectHexRays(command: string | undefined): Promise<boolean | undefined> {
	const root = installationRoot(command, "ida");
	if (!root) return undefined;
	for (const directory of [root, path.join(root, "plugins")]) {
		const entries = await fs.readdir(directory).catch(() => []);
		if (entries.some((entry) => /(?:hexrays|hexx64|hexarm|hexarm64|hexmips|hexppc)/i.test(entry))) return true;
	}
	return false;
}

function analysisOptionsHash(engine: Engine, input: Record<string, unknown>): string {
	const relevant = engine === "ghidra"
		? { operation: input.operation, max_cpu: input.max_cpu ?? null, script_path: input.script_path ?? null, script_args: input.script_args ?? [] , ghidraScriptVersion: GHIDRA_SCRIPT_VERSION }
		: engine === "ida"
			? { operation: input.operation, script_path: input.script_path ?? null, script_args: input.script_args ?? [] }
			: { operation: input.operation, jadx_mode: input.jadx_mode ?? "auto", jadx_threads: input.jadx_threads ?? null, jadx_output_format: input.jadx_output_format ?? "java", jadx_deobfuscate: input.jadx_deobfuscate ?? false, jadx_no_resources: input.jadx_no_resources ?? false, jadx_no_sources: input.jadx_no_sources ?? false };
	return createHash("sha256").update(JSON.stringify(relevant)).digest("hex");
}

async function installationCapabilities(
	available: ToolInventory,''')
replace_once("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts", "\tconst bundledPyGhidra = ghidraHome", "\tconst [ghidraIdentity, idaIdentity, jadxIdentity, hexRays] = await Promise.all([\n\t\ttoolIdentity(\"ghidra\", ghidraCommand),\n\t\ttoolIdentity(\"ida\", idaCommand),\n\t\ttoolIdentity(\"jadx\", available.jadx),\n\t\tdetectHexRays(idaCommand),\n\t]);\n\tconst bundledPyGhidra = ghidraHome")
replace_once("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts", "\t\t\tversion: await toolVersion(\"ghidra\", ghidraCommand),", "\t\t\tversion: ghidraIdentity.version,\n\t\t\tversionSource: ghidraIdentity.versionSource,\n\t\t\texecutableVerified: Boolean(ghidraCommand),")
replace_once("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts", "\t\t\tversion: await toolVersion(\"ida\", idaCommand),", "\t\t\tversion: idaIdentity.version,\n\t\t\tversionSource: idaIdentity.versionSource,\n\t\t\thexRays: { detected: hexRays, requiredForDecompile: true },\n\t\t\texecutableVerified: Boolean(idaCommand),")
replace_once("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts", "\t\t\tversion: await toolVersion(\"jadx\", available.jadx),", "\t\t\tversion: jadxIdentity.version,\n\t\t\tversionSource: jadxIdentity.versionSource,")
replace_once("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts", "\t\tconst timeoutMs = input.timeout_ms ?? 900_000;", "\t\tconst timeoutMs = input.timeout_ms ?? 900_000;\n\t\tconst engineIdentity = await toolIdentity(engine, available[engine]);\n\t\tconst optionsHash = analysisOptionsHash(engine, input);\n\t\tif (engine === \"ida\" && input.operation === \"decompile\" && (await detectHexRays(command)) === false) {\n\t\t\tthrow new Error(\"IDA decompile requires an installed Hex-Rays decompiler; no compatible plugin was detected.\");\n\t\t}")
replace_once("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts", "\t\t\tconst sameArtifact =\n\t\t\t\texistingManifest?.sha256 === hash &&\n\t\t\t\texistingManifest?.engine === engine;", "\t\t\tconst sameArtifact =\n\t\t\t\texistingManifest?.schemaVersion === ANALYSIS_SCHEMA_VERSION &&\n\t\t\t\texistingManifest?.sha256 === hash &&\n\t\t\t\texistingManifest?.engine === engine &&\n\t\t\t\texistingManifest?.engineVersion === engineIdentity.version &&\n\t\t\t\texistingManifest?.analysisOptionsHash === optionsHash;")
replace_once("sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts", "\t\t\t\t\tschemaVersion: 1,\n\t\t\t\t\tsha256: hash,\n\t\t\t\t\ttarget,\n\t\t\t\t\tengine,\n\t\t\t\t\tengineVersion: await toolVersion(engine, available[engine]),", "\t\t\t\t\tschemaVersion: ANALYSIS_SCHEMA_VERSION,\n\t\t\t\t\tsha256: hash,\n\t\t\t\t\ttarget,\n\t\t\t\t\tengine,\n\t\t\t\t\tengineVersion: engineIdentity.version,\n\t\t\t\t\tengineVersionSource: engineIdentity.versionSource,\n\t\t\t\t\tanalysisOptionsHash: optionsHash,")

# Schema and types for the separate live debugger.
replace_once("sdk/packages/core/src/extensions/tools/schemas.ts", "/** Structured Android automation with explicitly acknowledged unrestricted shell access. */", r'''/** Supervised one-shot live debugging for explicitly authorized local targets. */
export const LiveDebuggerInputSchema = z.object({
	operation: z.enum(["discover", "launch", "attach_snapshot", "backtrace", "registers", "read_memory", "disassemble", "continue", "step"]),
	debugger: z.enum(["auto", "gdb", "lldb"]).default("auto"),
	target_kind: z.enum(["local", "remote"]).default("local"),
	target: z.string().min(1).optional(),
	args: z.array(z.string().max(32_768)).max(256).optional(),
	pid: z.number().int().positive().optional(),
	breakpoint: z.string().min(1).max(1_024).optional(),
	address: z.string().regex(/^(?:0x[0-9a-fA-F]+|[A-Za-z_.$][\w.$:+-]*)$/).optional(),
	length: z.number().int().min(1).max(4_096).optional(),
	steps: z.number().int().min(1).max(100).optional(),
	timeout_ms: z.number().int().positive().max(120_000).optional(),
	acknowledge_risk: z.boolean().optional(),
});

/** Structured Android automation with explicitly acknowledged unrestricted shell access. */''')
replace_once("sdk/packages/core/src/extensions/tools/schemas.ts", "export type AndroidDeviceInput = z.infer<typeof AndroidDeviceInputSchema>;", "export type LiveDebuggerInput = z.infer<typeof LiveDebuggerInputSchema>;\nexport type AndroidDeviceInput = z.infer<typeof AndroidDeviceInputSchema>;")
replace_once("sdk/packages/core/src/extensions/tools/types.ts", "\tEditFileInput,\n\tReadFileRequest,", "\tEditFileInput,\n\tLiveDebuggerInput,\n\tReadFileRequest,")
replace_once("sdk/packages/core/src/extensions/tools/types.ts", "export type AndroidDeviceExecutor = (", "export type LiveDebuggerExecutor = (\n\tinput: LiveDebuggerInput,\n\tcontext: AgentToolContext,\n) => Promise<string>;\n\nexport type AndroidDeviceExecutor = (")
replace_once("sdk/packages/core/src/extensions/tools/types.ts", "\treverseEngineering?: ReverseEngineeringExecutor;", "\treverseEngineering?: ReverseEngineeringExecutor;\n\t/** Explicitly authorized one-shot GDB/LLDB workflows */\n\tliveDebugger?: LiveDebuggerExecutor;")
replace_once("sdk/packages/core/src/extensions/tools/types.ts", '\t| "reverse_engineer"\n\t| "android_device"', '\t| "reverse_engineer"\n\t| "live_debugger"\n\t| "android_device"')
replace_once("sdk/packages/core/src/extensions/tools/types.ts", "\t/** Enable the android_device tool. @default true */", "\t/** Enable the live_debugger tool. @default false */\n\tenableLiveDebugger?: boolean;\n\n\t/** Enable the android_device tool. @default true */")

# Definitions and factory wiring.
replace_once("sdk/packages/core/src/extensions/tools/definitions.ts", "\ttype FetchWebContentInput,\n\tFetchWebContentInputSchema,", "\ttype FetchWebContentInput,\n\tFetchWebContentInputSchema,\n\ttype LiveDebuggerInput,\n\tLiveDebuggerInputSchema,")
replace_once("sdk/packages/core/src/extensions/tools/definitions.ts", "\tFileReadExecutor,\n\tReverseEngineeringExecutor,", "\tFileReadExecutor,\n\tLiveDebuggerExecutor,\n\tReverseEngineeringExecutor,")
replace_once("sdk/packages/core/src/extensions/tools/definitions.ts", "export function createAndroidDeviceTool(", r'''export function createLiveDebuggerTool(
	executor: LiveDebuggerExecutor,
): AgentTool<LiveDebuggerInput, string> {
	return createTool<LiveDebuggerInput, string>({
		name: "live_debugger",
		description: "Use an installed GDB or LLDB for explicitly authorized local live debugging. This is separate from static reverse_engineer analysis. Start with discover. Every operation that launches or attaches requires acknowledge_risk=true. Invocations are one-shot and supervised: launch or attach, collect bounded backtrace/register/memory/disassembly evidence, detach when applicable, and exit. Remote debugging, arbitrary command strings, privilege escalation, and hidden persistent sessions are not supported.",
		inputSchema: zodToJsonSchema(LiveDebuggerInputSchema),
		timeoutMs: 120_000,
		retryable: false,
		execute: executor,
	});
}

export function createAndroidDeviceTool(''')
replace_once("sdk/packages/core/src/extensions/tools/definitions.ts", "\t\tenableReverseEngineering = true,\n\t\tenableAndroidDevice = true,", "\t\tenableReverseEngineering = true,\n\t\tenableLiveDebugger = false,\n\t\tenableAndroidDevice = true,")
replace_once("sdk/packages/core/src/extensions/tools/definitions.ts", "\tif (enableAndroidDevice && executors.androidDevice) {", "\tif (enableLiveDebugger && executors.liveDebugger) {\n\t\ttools.push(createLiveDebuggerTool(executors.liveDebugger));\n\t}\n\tif (enableAndroidDevice && executors.androidDevice) {")

# Executor exports and public API.
replace_once("sdk/packages/core/src/extensions/tools/executors/index.ts", 'import { createReverseEngineeringExecutor } from "./reverse-engineering";', 'import { createReverseEngineeringExecutor } from "./reverse-engineering";\nimport { createLiveDebuggerExecutor } from "./live-debugger";')
replace_once("sdk/packages/core/src/extensions/tools/executors/index.ts", 'export { createReverseEngineeringExecutor } from "./reverse-engineering";', 'export { createReverseEngineeringExecutor } from "./reverse-engineering";\nexport { createLiveDebuggerExecutor } from "./live-debugger";')
replace_once("sdk/packages/core/src/extensions/tools/executors/index.ts", "\t\treverseEngineering: createReverseEngineeringExecutor(),", "\t\treverseEngineering: createReverseEngineeringExecutor(),\n\t\tliveDebugger: createLiveDebuggerExecutor(),")
replace_once("sdk/packages/core/src/extensions/tools/index.ts", "\tcreateReadFilesTool,\n\tcreateReverseEngineeringTool,", "\tcreateReadFilesTool,\n\tcreateLiveDebuggerTool,\n\tcreateReverseEngineeringTool,")
replace_once("sdk/packages/core/src/extensions/tools/index.ts", "\tcreateFileReadExecutor,\n\tcreateReverseEngineeringExecutor,", "\tcreateFileReadExecutor,\n\tcreateLiveDebuggerExecutor,\n\tcreateReverseEngineeringExecutor,")
replace_once("sdk/packages/core/src/extensions/tools/index.ts", "\ttype FetchWebContentInput,\n\tFetchWebContentInputSchema,", "\ttype FetchWebContentInput,\n\tFetchWebContentInputSchema,\n\ttype LiveDebuggerInput,\n\tLiveDebuggerInputSchema,")
replace_once("sdk/packages/core/src/extensions/tools/index.ts", "\tFileReadExecutor,\n\tReverseEngineeringExecutor,", "\tFileReadExecutor,\n\tLiveDebuggerExecutor,\n\tReverseEngineeringExecutor,")

# Catalog, constants, and presets. Live debugging is opt-in in every preset.
replace_once("sdk/packages/core/src/extensions/tools/constants.ts", '\tREVERSE_ENGINEER: "reverse_engineer",', '\tREVERSE_ENGINEER: "reverse_engineer",\n\tLIVE_DEBUGGER: "live_debugger",')
replace_once("sdk/packages/core/src/extensions/tools/constants.ts", "\tDefaultToolNames.REVERSE_ENGINEER,", "\tDefaultToolNames.REVERSE_ENGINEER,\n\tDefaultToolNames.LIVE_DEBUGGER,")
for marker in ["act: {", "plan: {", "search: {", "minimal: {", "yolo: {"]:
    replace_once("sdk/packages/core/src/extensions/tools/presets.ts", marker + "\n\t\tenableReadFiles:", marker + "\n\t\tenableLiveDebugger: false,\n\t\tenableReadFiles:")
replace_once("sdk/packages/core/src/extensions/tools/runtime.ts", "\t{\n\t\tid: \"android_device\",", "\t{\n\t\tid: \"live_debugger\",\n\t\tdescription: \"Run explicitly authorized, supervised one-shot GDB or LLDB workflows.\",\n\t\theadlessToolNames: [\"live_debugger\"],\n\t},\n\t{\n\t\tid: \"android_device\",")
replace_once("sdk/packages/core/src/extensions/tools/runtime.ts", '\t\t\t| "enableReverseEngineering"\n\t\t\t| "enableAndroidDevice"', '\t\t\t| "enableReverseEngineering"\n\t\t\t| "enableLiveDebugger"\n\t\t\t| "enableAndroidDevice"')
replace_once("sdk/packages/core/src/extensions/tools/runtime.ts", '\treverse_engineer: "enableReverseEngineering",', '\treverse_engineer: "enableReverseEngineering",\n\tlive_debugger: "enableLiveDebugger",')
replace_once("sdk/packages/core/src/extensions/tools/runtime.ts", '\t| "enableReverseEngineering"\n\t| "enableAndroidDevice"', '\t| "enableReverseEngineering"\n\t| "enableLiveDebugger"\n\t| "enableAndroidDevice"')

# Customization ledger and verifier.
replace_once("CUSTOMIZATIONS.md", "- Reverse-engineering and Smali workflows.\n- APK comparison improvements.", "- Reverse-engineering and Smali workflows, with cross-platform IDA/Ghidra discovery, executable/version/capability reporting, version-and-option-aware cache reuse, complete output draining, process-tree cancellation, and verified GUI startup.\n- A separate opt-in `live_debugger` tool provides explicitly acknowledged, bounded, one-shot GDB/LLDB launch and attach workflows; see `docs/LIVE_DEBUGGING.md`.\n- APK comparison improvements.")
replace_once("CUSTOMIZATIONS.md", "### Specialized tools\n", "### Specialized tools\n")
replace_once("CUSTOMIZATIONS.md", "- Codex-compatible tool calls and binary attachment handling.\n", "- Codex-compatible tool calls and binary attachment handling.\n\nPrimary files:\n\n- `sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts`\n- `sdk/packages/core/src/extensions/tools/executors/supervised-process.ts`\n- `sdk/packages/core/src/extensions/tools/executors/live-debugger.ts`\n- `docs/LIVE_DEBUGGING.md`\n")
replace_once("scripts/verify-custom-fork.ts", "\t{\n\t\tpath: \"docs/ANDROID_DEVICE_AUTOMATION.md\",", "\t{\n\t\tpath: \"sdk/packages/core/src/extensions/tools/executors/supervised-process.ts\",\n\t\tmarkers: [\"child.once(\\\"close\\\"\", \"process.kill(-child.pid\", \"exited_early\"],\n\t},\n\t{\n\t\tpath: \"sdk/packages/core/src/extensions/tools/executors/live-debugger.ts\",\n\t\tmarkers: [\"acknowledge_risk=true\", \"persistentSession\", \"process detach\"],\n\t},\n\t{\n\t\tpath: \"docs/LIVE_DEBUGGING.md\",\n\t\tmarkers: [\"one-shot\", \"acknowledge_risk: true\", \"Remote debugging is rejected\"],\n\t},\n\t{\n\t\tpath: \"docs/ANDROID_DEVICE_AUTOMATION.md\",")

print("Applied reverse-engineering hardening and live-debugger changes")
