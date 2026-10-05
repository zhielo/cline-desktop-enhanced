#!/usr/bin/env python3
"""Fresh issue #98 source integration. No archived patches or installer reuse."""
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BRANCH = "work/full-tool-platform-upgrade"
branch = os.environ.get("GITHUB_REF_NAME") or subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip()
if branch != BRANCH:
    raise SystemExit("Source staging is restricted to the full-upgrade branch")
changes = {}

def read(path):
    return changes.get(path, (ROOT / path).read_text())

def put(path, text):
    changes[path] = text

def replace(path, old, new):
    text = read(path)
    if text.count(new) == 1:
        return
    if text.count(old) != 1:
        raise SystemExit(f"Refusing ambiguous source integration: {path}")
    put(path, text.replace(old, new, 1))

BASE = "sdk/packages/core/src/extensions/tools/"
replace(BASE + "types.ts", 'export type DefaultToolName =\n', 'export type DefaultToolName =\n\t| "tool_registry"\n')
replace(BASE + "types.ts", 'export interface DefaultToolsConfig {\n', 'export interface DefaultToolsConfig {\n\t/** Registry metadata only; standard presets opt in. @default false */\n\tenableToolRegistry?: boolean;\n\t/** Host-selected independent-command parallelism, integer 1..4. @default 1 */\n\tcommandConcurrency?: number;\n')
types = read(BASE + "types.ts")
if "cleanupUnverified?: boolean;" not in types:
    pattern = r'(export (?:interface|type) ToolOperationResult\s*(?:=\s*)?\{)'
    types, count = re.subn(pattern, r'\1\n\t/** Cancellation was requested; physical process cleanup was not verified. */\n\tcleanupUnverified?: boolean;', types)
    if count != 1:
        raise SystemExit("Cannot locate ToolOperationResult safely")
    put(BASE + "types.ts", types)
replace(BASE + "constants.ts", '\tREAD_FILES: "read_files",', '\tTOOL_REGISTRY: "tool_registry",\n\tREAD_FILES: "read_files",')
replace(BASE + "constants.ts", '\tDefaultToolNames.READ_FILES,', '\tDefaultToolNames.TOOL_REGISTRY,\n\tDefaultToolNames.READ_FILES,')
replace(BASE + "permission-profile.ts", 'const READ_ONLY_TOOLS = new Set([\n', 'const READ_ONLY_TOOLS = new Set([\n\t"tool_registry",\n')
replace(BASE + "index.ts", '// Zod Utilities\n', 'export { createToolRegistryTool } from "./capability-registry";\nexport type { ToolRegistryEntry, ToolRegistryInput, ToolRegistryResult } from "./capability-registry";\n\n// Zod Utilities\n')
core_index = "sdk/packages/core/src/index.ts"
text = read(core_index)
export = '\nexport { createToolRegistryTool } from "./extensions/tools/capability-registry";\n'
if export.strip() not in text:
    put(core_index, text + export)

presets = read(BASE + "presets.ts")
if "enableToolRegistry:" not in presets:
    presets, count = re.subn(r'(?m)^(\t\t)enableLiveDebugger:', r'\1enableToolRegistry: true,\n\1enableLiveDebugger:', presets)
    if count < 3:
        raise SystemExit("Cannot safely identify standard presets")
    put(BASE + "presets.ts", presets)

runtime = BASE + "runtime.ts"
replace(runtime, 'const BASE_TOOL_CATALOG: readonly RuntimeToolCatalogEntry[] = [\n', 'const BASE_TOOL_CATALOG: readonly RuntimeToolCatalogEntry[] = [\n\t{ id: "tool_registry", description: "Inspect bounded registered SDK tool metadata without granting permissions or claiming engine readiness.", headlessToolNames: ["tool_registry"] },\n')
replace(runtime, '\tread_files: "enableReadFiles",', '\ttool_registry: "enableToolRegistry",\n\tread_files: "enableReadFiles",')
text = read(runtime)
if '| "enableToolRegistry"' not in text:
    text = text.replace('| "enableReadFiles"', '| "enableToolRegistry"\n\t| "enableReadFiles"')
    put(runtime, text)

helpers = BASE + "helpers.ts"
old = '''return Promise.race([
		promise,
		new Promise<never>((_, reject) => {
			setTimeout(() => reject(new TimeoutError(message, ms)), ms);
		}),
	]);'''
new = '''return new Promise<T>((resolve, reject) => {
		const timer = setTimeout(() => reject(new TimeoutError(message, ms)), ms);
		Promise.resolve(promise).then(
			(value) => { clearTimeout(timer); resolve(value); },
			(error: unknown) => { clearTimeout(timer); reject(error); },
		);
	});'''
replace(helpers, old, new)

definitions = BASE + "definitions.ts"
replace(definitions, 'import { isAbsolute, join, resolve } from "node:path";', 'import { isAbsolute, join, resolve } from "node:path";\nimport { createToolRegistryTool } from "./capability-registry";\nimport { type CommandBatchContext, runCommandBatch, waitForCommandResult } from "./command-batch";')
replace(definitions, '\t\tenableReadFiles = true,', '\t\tenableToolRegistry = false,\n\t\tenableReadFiles = true,')
replace(definitions, '\treturn tools as unknown as AgentTool[];', '\tif (enableToolRegistry) {\n\t\ttools.push(createToolRegistryTool(() => tools as unknown as AgentTool[]));\n\t}\n\treturn tools as unknown as AgentTool[];')
replace(definitions, '"cwd" | "bashTimeoutMs" | "telemetry">', '"cwd" | "bashTimeoutMs" | "telemetry" | "commandConcurrency">')
replace(definitions, '\t\t\t\ttelemetry: config.telemetry,', '\t\t\t\ttelemetry: config.telemetry,\n\t\t\t\tconcurrency: config.commandConcurrency,')
text = read(definitions)
start = text.index('async function executeShellCommands(')
end = text.index('\n// =============================================================================\n// AgentTool Factory Functions', start)
block = text[start:end]
if "runCommandBatch(commands, runCommand" not in block:
    body_start = block.index('\t\t\t\tconst startedAt = Date.now();')
    body_end = block.rfind('\n\t\t\t},\n\t\t),\n\t);')
    if body_end <= body_start:
        raise SystemExit("Cannot safely isolate command executor")
    body = block[body_start:body_end]
    body = '\n'.join(line[2:] if line.startswith('\t\t') else line for line in body.split('\n'))
    body = body.replace('const startedAt = Date.now();', 'const startedAt = Date.now();\n\t\tlet launchAttempted = false;', 1)
    body, count = re.subn(r'(?m)^(\t+)\.\.\.context,$', r'\1...context,\n\1signal: batch.signal,', body)
    if count != 1:
        raise SystemExit("Cannot safely link executor cancellation")
    if body.count(': context;') != 1:
        raise SystemExit("Cannot safely link non-streaming cancellation")
    body = body.replace(': context;', ': { ...context, signal: batch.signal };', 1)
    pattern = r'const output = await withTimeout\(\s*executor\(command, cwd, commandContext\),\s*timeoutMs,\s*`Command timed out after \$\{timeoutMs\}ms`,\s*\);'
    replacement = 'batch.ensureActive();\n\t\t\tlaunchAttempted = true;\n\t\t\tconst output = await waitForCommandResult(executor(command, cwd, commandContext), batch.signal);\n\t\t\tbatch.ensureActive();'
    body, count = re.subn(pattern, replacement, body)
    if count != 1:
        raise SystemExit("Cannot safely replace per-command timeout")
    body = body.replace('if (error instanceof TimeoutError) {', 'if (error instanceof TimeoutError) {\n\t\t\t\tbatch.cancel(error);', 1)
    body = re.sub(r'(?m)^(\t+)success: false,$', r'\1success: false,\n\1...(launchAttempted && batch.signal.aborted ? { cleanupUnverified: true } : {}),', body)
    header = block[:block.index('\n\treturn Promise.all(')]
    header = header.replace('\t\ttelemetry?: ITelemetryService;', '\t\ttelemetry?: ITelemetryService;\n\t\tconcurrency?: number;')
    replacement = header + '''
	const runCommand = async (
		command: string | StructuredCommandInput,
		commandIndex: number,
		batch: CommandBatchContext,
	): Promise<ToolOperationResult> => {
''' + body + '''
	};
	return runCommandBatch(commands, runCommand, {
		timeoutMs,
		concurrency: options.concurrency,
		signal: context.signal,
		onSkipped: runCommand,
	});
}
'''
    text = text[:start] + replacement + text[end:]
    put(definitions, text)

ledger = "CUSTOMIZATIONS.md"
section = '''
### Fresh tool platform foundation (issue #98)

- `tool_registry` reports bounded registered SDK metadata, not the final permission-filtered tool roster. Installation, licensing, health and effective permission remain unverified. It does not invoke tools, descriptor getters, external discovery or MCP, and never exposes schema defaults.
- Normal tool presets enable registry introspection; the SDK factory also supports an explicit host opt-in/out. Existing permission and Plan-mode guards remain authoritative.
- `run_commands` executes in input order by default, with host-only independent-command concurrency bounded to 1..4. One monotonic batch deadline covers queued commands; cancellation or expiry prevents later launches and is forwarded to the executor.
- Timed-out launched commands report `cleanupUnverified`; cancellation requests and caller timeouts are not proof that descendants terminated. This checkpoint does not introduce Windows Job Objects, verified hostile-code isolation, or a global multi-agent execution limit.
- Shared timeout wrappers clear their timers when work settles.
- This is a fresh core foundation, NOT completion of the tool catalogue in issue #98 and NOT an installer release. Optional runtime workers remain subject to the existing fail-closed prerequisites.
'''
if "### Fresh tool platform foundation (issue #98)" not in read(ledger):
    put(ledger, read(ledger) + section)
verifier = "scripts/verify-custom-fork.ts"
replace(verifier, '}> = [\n', '''}> = [
	{ path: "CUSTOMIZATIONS.md", markers: ["Fresh tool platform foundation (issue #98)", "cleanupUnverified"] },
	{ path: "sdk/packages/core/src/extensions/tools/capability-registry.ts", markers: ["createToolRegistryTool", "not_probed", "not_evaluated"] },
	{ path: "sdk/packages/core/src/extensions/tools/command-batch.ts", markers: ["runCommandBatch", "ensureActive", "clearTimeout(timer)"] },
	{ path: "sdk/packages/core/src/extensions/tools/definitions.ts", markers: ["runCommandBatch(commands, runCommand", "createToolRegistryTool", "cleanupUnverified"] },
''')
# Validate ALL anchors before touching any existing source.
for path, updated in changes.items():
    original = (ROOT / path).read_text()
    if updated != original:
        (ROOT / path).write_text(updated)
        print(f"Integrated: {path}")
print("Fresh source integration finished; validation is a separate required gate.")
