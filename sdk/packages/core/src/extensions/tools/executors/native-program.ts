import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { mkdtemp, open, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { z } from "zod";
import type { AdvancedResult } from "./advanced-analysis";
import { analyzeProgramCfg } from "./analysis-program-evidence";
import { GHIDRA_NATIVE_PROGRAM_SCRIPT } from "./native-program-script";
import { prepareProcessEnvironment } from "./process-environment-policy";

export const NativeRecoveryOptionsSchema = z.object({
 functionName: z.string().min(1).max(512).optional(),
 maxFunctions: z.number().int().min(1).max(64).default(16),
 maxPcodeOps: z.number().int().min(1).max(4096).default(2048),
}).strict();
const Id = z.string().min(1).max(256);
const Varnode = z.object({ id: Id, space: z.string().min(1).max(128), offsetHex: z.string().regex(/^[a-f0-9]{1,16}$/), bytes: z.number().int().min(1).max(64), constant: z.boolean() }).strict();
export const NativeProgramSchema = z.object({
 schemaVersion: z.literal(1), producer: z.literal("ghidra-high-pcode"), engineVersion: z.string().min(1).max(128), language: z.string().min(1).max(128),
 functions: z.array(z.object({
  name: z.string().max(512), entry: Id, status: z.enum(["recovered", "partial", "failed"]), error: z.string().max(512).optional(), pseudocode: z.string().max(8192), pseudocodeTruncated: z.boolean(),
  blocks: z.array(z.object({ id: z.string().regex(/^b[0-9]+$/), start: Id, stop: Id, successors: z.array(z.string().regex(/^b[0-9]+$/)).max(32) }).strict()).max(256),
  pcode: z.array(z.object({ id: Id, address: Id, block: Id, opcode: z.string().regex(/^[A-Z0-9_]+$/).max(64), output: Varnode.nullable(), inputs: z.array(Varnode).max(64) }).strict()).max(4096),
 }).strict()).max(64),
 coverage: z.object({ consideredFunctions: z.number().int().min(0).max(1000000), failedFunctions: z.number().int().min(0).max(64), pcodeOperations: z.number().int().min(0).max(4096), truncated: z.boolean(), externalAndThunkFunctionsExcluded: z.literal(true) }).strict(),
}).strict().superRefine((document, ctx) => {
 const fail = (message: string) => ctx.addIssue({ code: "custom", message });
 const entries = new Set<string>(); let count = 0, failures = 0;
 for (const fn of document.functions) {
  if (entries.has(fn.entry)) fail("Duplicate function entry"); entries.add(fn.entry);
  if (fn.status === "failed") failures++;
  const blocks = new Set(fn.blocks.map(b => b.id));
  if (blocks.size !== fn.blocks.length) fail("Duplicate CFG block");
  for (const block of fn.blocks) {
   if (new Set(block.successors).size !== block.successors.length) fail("Duplicate CFG successor");
   for (const edge of block.successors) if (!blocks.has(edge)) fail("Dangling CFG edge");
  }
  const operations = new Set<string>(), definitions = new Set<string>(), values = new Map<string, string>();
  for (const op of fn.pcode) {
   if (operations.has(op.id)) fail("Duplicate p-code operation"); operations.add(op.id);
   if (op.block !== "unassigned" && !blocks.has(op.block)) fail("Dangling p-code block");
   if (op.output) { if (definitions.has(op.output.id)) fail("Duplicate SSA definition"); definitions.add(op.output.id); }
   for (const value of [...op.inputs, ...(op.output ? [op.output] : [])]) {
    const signature = JSON.stringify(value); if (values.has(value.id) && values.get(value.id) !== signature) fail("Conflicting varnode identity"); values.set(value.id, signature);
   }
  }
  count += fn.pcode.length;
 }
 if (count !== document.coverage.pcodeOperations || count > 4096) fail("P-code coverage count mismatch");
 if (failures !== document.coverage.failedFunctions) fail("Failure coverage count mismatch");
});
export type NativeProgram = z.infer<typeof NativeProgramSchema>;
export function validateNativeProgram(value: unknown): NativeProgram {
 if (Buffer.byteLength(JSON.stringify(value), "utf8") > 1048576) throw new Error("Program evidence byte budget exceeded");
 return NativeProgramSchema.parse(value);
}
export function nativeProgramFindings(program: NativeProgram) {
 return program.functions.filter(fn => fn.blocks.length > 0).map(fn => ({ entry: fn.entry, name: fn.name,
  cfg: (() => {
   if (fn.blocks.reduce((n, b) => n + b.successors.length, 0) > 2048) return { omitted: "CFG edge budget exceeded", equivalence: "not-proven" };
   const cfg = analyzeProgramCfg({ schemaVersion: 1, entry: fn.blocks[0].id, blocks: fn.blocks.map(block => ({ id: block.id, successors: block.successors })) });
   return { reachable: cfg.reachable, unreachable: cfg.unreachable, stronglyConnectedComponents: cfg.stronglyConnectedComponents, naturalLoops: cfg.naturalLoops, irreducibleRegions: cfg.irreducibleRegions, dispatcherCandidates: cfg.dispatcherCandidates, equivalence: cfg.equivalence };
  })(), coverage: fn.status,
 }));
}
export function nativeEngineEnvironment() {
 const environment = { ...prepareProcessEnvironment({}).environment };
 for (const key of Object.keys(environment)) if (/^(JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS|CLASSPATH)$/i.test(key)) delete environment[key];
 return environment;
}
function terminate(child: ChildProcess) {
 if (!child.pid) return;
 if (process.platform === "win32") { const killer = spawn("taskkill", ["/pid", String(child.pid), "/t", "/f"], { stdio: "ignore", windowsHide: true }); killer.on("error", () => { child.kill(); }); killer.unref(); }
 else { try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); } }
}
export function nativeProgramInvocation(command: string, args: string[], platform = process.platform) {
 if (!isAbsolute(command)) throw new Error("Trusted absolute Ghidra headless path required");
 if (platform === "win32" && /\.(bat|cmd)$/i.test(command)) {
  if ([command, ...args].some(value => /[%!&|<>^"\r\n]/.test(value))) throw new Error("Unsafe Windows batch path");
  return { command: process.env.ComSpec ?? "cmd.exe", args: ["/d", "/s", "/c", "call", command, ...args] };
 }
 return { command, args };
}
async function execute(command: string, args: string[], cwd: string, timeoutMs: number, signal?: AbortSignal) {
 if (signal?.aborted) return "cancelled" as const;
 const invocation = nativeProgramInvocation(command, args);
 return new Promise<"ok" | "failed" | "cancelled">((resolve) => {
  const child = spawn(invocation.command, invocation.args, { cwd, env: nativeEngineEnvironment(), detached: process.platform !== "win32", windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  child.stdout?.on("data", () => {}); child.stderr?.on("data", () => {});
  let interrupted: "failed" | "cancelled" | undefined;
  const abort = () => { interrupted = "cancelled"; terminate(child); };
  const timer = setTimeout(() => { interrupted = "failed"; terminate(child); }, timeoutMs);
  signal?.addEventListener("abort", abort, { once: true }); if (signal?.aborted) abort();
  let settled = false;
  const finish = (code: number | null) => { if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener("abort", abort); resolve(interrupted ?? (code === 0 ? "ok" : "failed")); };
  child.once("error", () => finish(null)); child.once("close", finish);
 });
}
export async function recoverNativeProgram(command: string | undefined, target: string, options: unknown = {}, timeoutMs = 120000, signal?: AbortSignal): Promise<AdvancedResult> {
 const result = (status: AdvancedResult["status"], reason: string): AdvancedResult => ({ protocol: "cline-advanced-analysis/v1", status, engine: "ghidra", engineVersion: null, evidence: { reason }, limitations: ["Static parser/decompiler processing, not target execution or OS containment."] });
 if (!command) return result("blocked", "Install and configure a reviewed Ghidra headless toolchain");
 const policy = NativeRecoveryOptionsSchema.parse(options);
 if (!isAbsolute(target) || !Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 300000) throw new Error("Absolute target and bounded timeout required");
 if (signal?.aborted) return result("cancelled", "Cancelled before static recovery");
 const directory = await mkdtemp(join(tmpdir(), "cline-native-"));
 try {
  const canonical = await realpath(target);
  const source = await open(canonical, constants.O_RDONLY | (process.platform === "win32" ? 0 : constants.O_NOFOLLOW));
  let bytes = 0; const hash = createHash("sha256");
  try {
   const staged = await open(join(directory, "artifact.bin"), "wx", 0o600);
   try {
    const before = await source.stat();
    if (!before.isFile() || before.size < 1 || before.size > 128 * 1024 * 1024) throw new Error("Native input must be a regular file <=128 MiB");
    const buffer = Buffer.alloc(65536);
    for (;;) {
     if (signal?.aborted) return result("cancelled", "Cancelled while snapshotting input");
     const chunk = await source.read(buffer, 0, buffer.length, null); if (!chunk.bytesRead) break; bytes += chunk.bytesRead;
     if (bytes > 128 * 1024 * 1024) throw new Error("Input grew beyond byte budget");
     const data = buffer.subarray(0, chunk.bytesRead); hash.update(data);
     let offset = 0; while (offset < data.length) { const written = await staged.write(data, offset, data.length - offset); if (!written.bytesWritten) throw new Error("Snapshot write failed"); offset += written.bytesWritten; }
    }
    const after = await source.stat(); if (after.size !== before.size || after.mtimeMs !== before.mtimeMs || bytes !== before.size) throw new Error("Input changed while snapshotting"); await staged.sync();
   } finally { await staged.close(); }
  } finally { await source.close(); }
  await writeFile(join(directory, "ClineNativeProgram.java"), GHIDRA_NATIVE_PROGRAM_SCRIPT, { flag: "wx", mode: 0o600 });
  await writeFile(join(directory, "policy.json"), JSON.stringify(policy), { flag: "wx", mode: 0o600 });
  const output = join(directory, "program.json");
  const outcome = await execute(command, [directory, "program", "-import", join(directory, "artifact.bin"), "-analysisTimeoutPerFile", String(Math.max(1, Math.floor(timeoutMs / 1000) - 10)), "-max-cpu", "2", "-scriptPath", directory, "-postScript", "ClineNativeProgram.java", output, join(directory, "policy.json"), "-deleteProject"], directory, timeoutMs, signal);
  if (outcome !== "ok") return result(outcome, "Static native engine failed, timed out, or was cancelled");
  const report = await open(output, constants.O_RDONLY | (process.platform === "win32" ? 0 : constants.O_NOFOLLOW));
  let program: NativeProgram;
  try {
   const metadata = await report.stat(); if (!metadata.isFile() || metadata.size > 1048576) throw new Error("Program evidence byte budget exceeded");
   const buffer = Buffer.alloc(1048577); let total = 0;
   while (total < buffer.length) { const chunk = await report.read(buffer, total, buffer.length - total, null); if (!chunk.bytesRead) break; total += chunk.bytesRead; }
   if (total > 1048576) throw new Error("Program evidence byte budget exceeded");
   program = validateNativeProgram(JSON.parse(buffer.subarray(0, total).toString("utf8")));
  } finally { await report.close(); }
  if (!program.functions.some(fn => fn.blocks.length > 0)) return result("failed", "No selected native function was recovered");
  const evidence = { program, findings: nativeProgramFindings(program) };
  if (Buffer.byteLength(JSON.stringify(evidence), "utf8") > 1048576) return result("failed", "Combined native evidence byte budget exceeded");
  return { protocol: "cline-advanced-analysis/v1", status: program.coverage.truncated || program.coverage.failedFunctions ? "partial" : "completed", engine: "ghidra", engineVersion: program.engineVersion, input: { sha256: hash.digest("hex"), bytes, format: program.language }, evidence,
   limitations: ["Recovered CFG and high p-code are decompiler interpretations, not verified source or native equivalence.", "Function, CFG, p-code, pseudocode and output budgets are explicit; external/thunk functions are excluded.", "Static analysis only. No target execution, trace acquisition, binary patching or OS containment."] };
 } finally { await rm(directory, { recursive: true, force: true }); }
}
