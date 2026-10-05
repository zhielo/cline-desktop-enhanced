import { spawn, execFileSync } from "node:child_process";
import { createWriteStream } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export function parseParallel(value = "2") {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 4) throw new Error("Parallelism must be an integer from 1 to 4");
  return n;
}

export async function runJobs(jobs, parallel, run) {
  parseParallel(parallel);
  const results = new Array(jobs.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(parallel, jobs.length) }, async () => {
    for (;;) {
      const index = next++;
      if (index >= jobs.length) return;
      try { results[index] = await run(jobs[index]); }
      catch { results[index] = { name: jobs[index].name, status: "failed", reason: "Runner rejected the check" }; }
    }
  }));
  return results;
}

export async function runValidation(prerequisites, checks, parallel, run) {
  const results = [];
  for (const step of prerequisites) {
    const result = await run(step);
    results.push(result);
    if (result.status !== "passed") return {
      status: "failed", results: [...results, ...checks.map(x => ({ name: x.name, status: "blocked", reason: "Prerequisite failed" }))],
    };
  }
  results.push(...await runJobs(checks, parallel, run));
  return { status: results.every(x => x.status === "passed") ? "passed" : "failed", results };
}

async function main() {
  const flags = process.argv.slice(2).filter(x => x !== "--");
  if (flags.some(x => !["--engines"].includes(x))) throw new Error("Only --engines is supported");
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const output = path.join(root, ".cline-validation", `${Date.now()}-${process.pid}`);
  await mkdir(output, { recursive: true });
  const parallel = parseParallel(process.env.CLINE_VALIDATION_PARALLEL ?? "2");
  const desktop = path.join(root, "apps/examples/desktop-app");
  const pkg = JSON.parse(await readFile(path.join(desktop, "package.json"), "utf8"));
  const job = (name, args, cwd = root) => ({ name, args, cwd, timeoutMs: 20 * 60 * 1000 });
  const prerequisites = [
    job("Verify custom fork preservation", ["run", "scripts/verify-custom-fork.ts"]),
    job("Build SDK packages", ["run", "build:sdk"]),
  ];
  const checks = [
    job("Test consolidated runner", ["test", "scripts/validate-advanced-build.test.mjs"]),
    job("Type-check desktop", ["x", "tsc", "-p", "apps/examples/desktop-app/tsconfig.dev.json", "--noEmit"]),
    job("Type-check core", ["x", "tsc", "-p", "sdk/packages/core/tsconfig.build.json", "--noEmit"]),
    job("Run required desktop sidecar regression suite", ["-F", "@cline/code", "test:sidecar"]),
    job("Test Windows installer configuration", ["-F", "@cline/code", "test:windows-installer"]),
    job("Test AI task report", ["x", "vitest", "run", "webview/lib/task-report.test.ts", "--config", "vitest.config.mts"], desktop),
    job("Test desktop chat UI", ["x", ...pkg.scripts["test:chat-ui"].split(/\s+/)], desktop),
    job("Run desktop customization tests", ["x", "vitest", "run",
      "apps/examples/desktop-app/sidecar/analysis-sandbox-client.test.ts",
      "apps/examples/desktop-app/sidecar/analysis-document-store.test.ts",
      "apps/examples/desktop-app/sidecar/analysis-task-orchestrator.test.ts",
      "apps/examples/desktop-app/sidecar/engineering-control-plane.test.ts",
      "apps/examples/desktop-app/sidecar/engineering-git-review.test.ts",
      "apps/examples/desktop-app/sidecar/engineering-worktree-manager.test.ts",
      "apps/examples/desktop-app/sidecar/browser-manager.test.ts",
      "apps/examples/desktop-app/sidecar/commands-workbench.test.ts",
      "apps/examples/desktop-app/sidecar/repository-tool.test.ts",
      "apps/examples/desktop-app/sidecar/notion-agent-bridge.test.ts",
      "apps/examples/desktop-app/sidecar/notion-agent-patch.test.ts",
      "apps/examples/desktop-app/webview/components/views/settings/functions-view.test.tsx",
      "apps/examples/desktop-app/webview/components/views/engineering/engineering-workspace.test.tsx",
      "--config", "apps/examples/desktop-app/vitest.config.mts"]),
    job("Run focused SDK safety tests", ["x", "vitest", "run",
      "sdk/packages/core/src/extensions/tools/permission-profile.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/process-session-manager.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/reverse-engineering.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/advanced-analysis.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/analysis-evidence-graph.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/analysis-notebook.test.ts",
 "sdk/packages/core/src/extensions/tools/executors/analysis-program-evidence.test.ts",
      "sdk/packages/core/src/runtime/orchestration/notion-provenance.test.ts",
      "sdk/packages/core/src/runtime/orchestration/runtime-builder.test.ts",
      "--config", "vitest.config.mts", "--testTimeout=60000"]),
  ];
  if (flags.includes("--engines")) {
    const python = process.env.CLINE_RE_PYTHON;
    if (!python || !path.isAbsolute(python)) throw new Error("--engines requires an absolute trusted CLINE_RE_PYTHON");
    for (const corpus of ["advanced-analysis-worker.test.py", "advanced-ir.test.py", "advanced-crypto.test.py"])
      checks.push({ ...job(`Engine corpus: ${corpus}`, [path.join(root, "sdk/packages/core/scripts", corpus)]), executable: python });
  }
  const active = new Set();
  let cancelled = false;
  function terminate(child) {
    if (!child.pid) return;
    if (process.platform === "win32") {
      try { execFileSync(path.join(process.env.SystemRoot ?? "C:\\Windows", "System32", "taskkill.exe"), ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore", timeout: 10000 }); } catch {}
    } else { try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); } }
  }
  const abort = () => { cancelled = true; for (const child of active) terminate(child); };
  process.on("SIGINT", abort); process.on("SIGTERM", abort);
  const run = async (step) => {
    if (cancelled) return { name: step.name, status: "cancelled" };
    const start = Date.now();
    const logName = step.name.toLowerCase().replace(/[^a-z0-9]+/g, "-") + ".log";
    const stream = createWriteStream(path.join(output, logName));
    console.log(`[START] ${step.name}`);
    return await new Promise(resolve => {
      let settled = false, timedOut = false, timer;
      const child = spawn(step.executable ?? process.execPath, step.args, {
        cwd: step.cwd, env: process.env, shell: false, detached: process.platform !== "win32", windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
      });
      active.add(child);
      child.stdout?.pipe(stream, { end: false }); child.stderr?.pipe(stream, { end: false });
      const finish = (code) => {
        if (settled) return; settled = true; clearTimeout(timer); active.delete(child); stream.end();
        const status = cancelled ? "cancelled" : timedOut ? "timed-out" : code === 0 ? "passed" : "failed";
        console.log(`[${status.toUpperCase()}] ${step.name}`);
        resolve({ name: step.name, status, exitCode: code, durationMs: Date.now() - start, log: logName });
      };
      child.once("error", () => finish(null)); child.once("close", code => finish(code));
      timer = setTimeout(() => { timedOut = true; terminate(child); finish(null); }, step.timeoutMs);
    });
  };
  let sourceCommit = "unavailable";
  try { sourceCommit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(); } catch {}
  const started = new Date().toISOString();
  const report = await runValidation(prerequisites, checks, parallel, run);
  process.removeListener("SIGINT", abort); process.removeListener("SIGTERM", abort);
  await writeFile(path.join(output, "summary.json"), JSON.stringify({
    schemaVersion: 1, started, finished: new Date().toISOString(), sourceCommit, parallel,
    engineValidation: flags.includes("--engines") ? "requested-see-corpus-results" : "not-requested",
    windowsInstallerBuilt: false, ...report,
  }, null, 2) + "\n");
  console.log(`Validation ${report.status}: ${path.relative(root, output)}/summary.json`);
  process.exitCode = report.status === "passed" ? 0 : 1;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
