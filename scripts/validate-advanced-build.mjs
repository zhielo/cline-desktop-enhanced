import { spawn, execFileSync } from "node:child_process";
import { appendFileSync, createWriteStream } from "node:fs";
import { mkdir, readFile, realpath, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export function parseParallel(value = "2") {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 4) throw new Error("Parallelism must be an integer from 1 to 4");
  return n;
}

export function engineCorpusArgs(corpus, root, platform = process.platform) {
  const args = [path.join(root, "sdk/packages/core/scripts", corpus)];
  if (corpus === "advanced-analysis-worker.test.py")
    args.push("--engine-profile", platform === "win32" ? "windows-portable" : "full");
  return args;
}

export function validationScope(env = process.env) {
  return { runId: env.GITHUB_RUN_ID ?? null, runAttempt: env.GITHUB_RUN_ATTEMPT ?? null, job: env.GITHUB_JOB ?? null };
}

export function coreValidationReceiptPath(root, value) {
  if (typeof value !== "string" || !/^\.cline-validation\/[0-9]+-[0-9]+\/summary\.json$/.test(value))
    throw new Error("Reuse requires an exact local consolidated validation receipt");
  return path.join(root, value);
}

export function assertReusableCoreValidation(report, sourceCommit, expectedGates, scope) {
  if (!/^[a-f0-9]{40}$/.test(sourceCommit) || report?.schemaVersion !== 1 ||
      report.status !== "passed" || report.sourceCommit !== sourceCommit ||
      report.engineValidation !== "not-requested" ||
      ["runId", "runAttempt", "job"].some(key => report.executionScope?.[key] !== scope[key]))
    throw new Error("Consolidated receipt is failed, stale or from another execution scope");
  const names = new Set(expectedGates);
  const results = report.results;
  if (names.size !== expectedGates.length || !Array.isArray(results) || results.length !== names.size ||
      results.some(result => result.status !== "passed" || !names.delete(result.name)) || names.size !== 0)
    throw new Error("Consolidated receipt does not prove every required core gate");
}

export function formatValidationHeartbeat(active, now = Date.now()) {
  return `[PROGRESS] ${Array.from(active.values(), step =>
    `${step.name}: ${Math.max(0, Math.floor((now - step.start) / 1000))}s`
  ).join("; ") || "no active checks"}`;
}

export function formatValidationNotice(message) {
  // Only fixed gate names/timings are passed here, never child output or env.
  // Escape workflow-command data and bound server-side annotation storage.
  const data = String(message).slice(0, 1000).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "")
    .replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
  return `::notice title=Custom validation progress::${data}`;
}

export function formatValidationFailureNotice(message) {
  return formatValidationNotice(message).replace("::notice title=Custom validation progress::", "::error title=Required validation gate::");
}

export function formatValidationSummary(report, sourceCommit) {
  // Only fixed gate names/statuses/timings. Never child log contents, requests or environment.
  const cell = value => String(value ?? "").replace(/[|`<>\r\n\x00-\x1f\x7f]/g, " ").slice(0, 180);
  const commit = /^[a-f0-9]{40}$/.test(sourceCommit) ? sourceCommit : "unavailable";
  const status = ["passed", "failed"].includes(report.status) ? report.status : "unknown";
  const rows = report.results.map(r => `| ${cell(r.name)} | ${cell(r.status)} | ${Number.isFinite(r.durationMs) ? Math.max(0, Math.round(r.durationMs / 1000)) : "—"} |`);
  return `## Required desktop validation: ${status}\n\nSource commit: ${commit}\n\n| Gate | Status | Seconds |\n| --- | --- | ---: |\n${rows.join("\n")}\n\nDetailed logs and the machine-readable summary are in the regression artifact. A passing validation suite does not certify behavioral superiority or complete unimplemented capabilities.\n`;
}

export function recordValidationProgress(file, event) {
  // Open/write/close each record: evidence survives a child crash without
  // depending on the final summary or a buffered persistent stream.
  appendFileSync(file, JSON.stringify({ timestamp: new Date().toISOString(), ...event }) + "\n", "utf8");
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
  if (flags.some(x => !["--engines", "--reuse-core"].includes(x)) ||
      (flags.includes("--reuse-core") && !flags.includes("--engines")))
    throw new Error("Only --engines and its receipt-verified --reuse-core option are supported");
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const output = path.join(root, ".cline-validation", `${Date.now()}-${process.pid}`);
  await mkdir(output, { recursive: true });
  const parallel = parseParallel(process.env.CLINE_VALIDATION_PARALLEL ?? "2");
  const desktop = path.join(root, "apps/examples/desktop-app");
  const pkg = JSON.parse(await readFile(path.join(desktop, "package.json"), "utf8"));
  let sourceCommit = "unavailable";
  try { sourceCommit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(); } catch {}
  const executionScope = validationScope();
  const job = (name, args, cwd = root) => ({ name, args, cwd, timeoutMs: 20 * 60 * 1000 });
  const prerequisites = [
    job("Check owned ARM64 fixture", ["scripts/generate-owned-arm64-fixture.mjs", "--check"]),
    job("Check Android worker embed", ["scripts/generate-android-investigation.mjs", "--check"]),
    job("Verify custom fork preservation", ["run", "scripts/verify-custom-fork.ts"]),
    job("Build SDK packages", ["run", "build:sdk"]),
    job("Build CLI workspace quality prerequisite", ["run", "-F", "@cline/cli", "build"]),
  ];
  const checks = [
    job("Type-check complete workspace including tests and smoke declarations", ["run", "types"]),
    job("Lint complete workspace", ["run", "lint"]),
    job("Test first-party static parser, evidence and supervised workers", ["x", "vitest", "run", "src/analysis/analysis.test.ts", "src/analysis/semantic.test.ts", "src/analysis/recovery.test.ts", "src/analysis/module-context.test.ts", "src/analysis/dotnet.test.ts", "src/analysis/il.test.ts", "src/analysis/managed-signature.test.ts", "src/analysis/scenario.test.ts", "src/analysis/managed-stack.test.ts", "src/analysis/electron-boundaries.test.ts", "src/analysis/managed-exceptions.test.ts", "src/analysis/unified-evidence.test.ts", "src/analysis/inspector.test.ts", "src/analysis/inspector-console.test.ts", "src/runtime/process-start-token.test.ts", "--config", "vitest.config.ts"], path.join(root,"sdk/packages/core")),
    job("Test real Hub singleton crash recovery", ["x", "vitest", "run", "src/hub/daemon/singleton.e2e.test.ts", "--config", "vitest.e2e.config.ts"], path.join(root, "sdk/packages/core")),
    { ...job("Test native Node installed process harness", ["--experimental-strip-types", "--test", "scripts/installed-node-process.test.mjs", "scripts/e2e-dependency-install.test.mjs", "scripts/wheelhouse-manifest.test.mjs"]), executable: "node" },
    job("Test native Bun SQLite memory startup", ["test", "sdk/packages/shared/scripts/sqlite-memory.bun.test.mjs"]),
    job("Test SQLite database path boundaries", ["x", "vitest", "run", "sdk/packages/shared/src/db/sqlite-db-paths.test.ts", "--config", "vitest.config.mts"]),
    job("Test measured performance budget policy", ["test", "scripts/performance-budget.test.mjs", "scripts/benchmark-command-execution.test.mjs"]),
    job("Test bounded acceptance diagnostics", ["test", "scripts/report-installed-acceptance.test.mjs"]),
    { ...job("Measure fixed owned command workload", ["scripts/benchmark-command-execution.mjs", "--out", path.join(output, "command-performance.json")]), executable: "node" },
    job("Test Windows workflow hardening", ["test", "scripts/windows-hardening.test.mjs"]),
    job("Test consolidated runner", ["test", "scripts/validate-advanced-build.test.mjs"]),
    job("Type-check desktop", ["x", "tsc", "-p", "apps/examples/desktop-app/tsconfig.dev.json", "--noEmit"]),
    job("Type-check core", ["x", "tsc", "-p", "sdk/packages/core/tsconfig.build.json", "--noEmit"]),
    job("Run required desktop sidecar regression suite", ["-F", "@cline/code", "test:sidecar"]),
    job("Test real Windows AppContainer execution boundary", ["test", "scripts/isolation-host-failure.test.ts", "scripts/javascript-isolation.test.ts"], desktop),
    job("Test Windows installer configuration", ["-F", "@cline/code", "test:windows-installer"]),
    job("Test AI task report", ["x", "vitest", "run", "webview/lib/task-report.test.ts", "--config", "vitest.config.mts"], desktop),
    job("Test desktop authentication boundary", ["x", "vitest", "run",
      "sidecar/server.test.ts", "sidecar/server-auth.test.ts", "sidecar/transport-auth.test.ts",
      "--config", "vitest.config.mts"], desktop),
    job("Test desktop transport recovery", ["x", "vitest", "run",
      "webview/lib/desktop-client.test.ts",
      "webview/lib/run-error.test.ts",
      "--config", "vitest.config.mts"], desktop),
    job("Test Hub lifecycle deadlines", ["x", "vitest", "run",
      "sdk/packages/shared/src/hub.test.ts", "--config", "vitest.config.mts"]),
    job("Test desktop chat UI", ["x", ...pkg.scripts["test:chat-ui"].split(/\s+/)], desktop),
    job("Run desktop customization tests", ["x", "vitest", "run",
      "apps/examples/desktop-app/webview/components/views/settings/analysis-environment-view.test.tsx",
      "apps/examples/desktop-app/webview/lib/native-tool-progress.test.ts",
      "apps/examples/desktop-app/webview/components/views/settings/setup-center-view.test.tsx",
      "apps/examples/desktop-app/webview/components/views/settings/optimization-panel.test.tsx",
      "apps/examples/desktop-app/sidecar/bundled-analysis-runtime.test.ts",
      "apps/examples/desktop-app/sidecar/setup-center.test.ts",
      "apps/examples/desktop-app/sidecar/setup-jobs.test.ts",
      "apps/examples/desktop-app/sidecar/trusted-update.test.ts",
      "apps/examples/desktop-app/sidecar/analysis-environment.test.ts",
      "apps/examples/desktop-app/sidecar/analysis-sandbox-client.test.ts",
      "apps/examples/desktop-app/sidecar/android-runtime-client.test.ts",
      "apps/examples/desktop-app/sidecar/analysis-investigation-store.test.ts",
      "apps/examples/desktop-app/webview/components/views/chat/investigation-workspace.test.tsx",
      "apps/examples/desktop-app/sidecar/analysis-document-store.test.ts",
      "apps/examples/desktop-app/sidecar/analysis-task-orchestrator.test.ts",
      "apps/examples/desktop-app/sidecar/apk-incident-service.test.ts",
      "apps/examples/desktop-app/sidecar/incident-artifacts.test.ts",
      "apps/examples/desktop-app/sidecar/incident-correlation.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/android-device.test.ts",
 "sdk/packages/core/src/extensions/tools/executors/android-debug-reports.test.ts",
      "apps/examples/desktop-app/sidecar/engineering-control-plane.test.ts",
      "apps/examples/desktop-app/sidecar/engineering-git-review.test.ts",
      "apps/examples/desktop-app/sidecar/engineering-worktree-manager.test.ts",
      "apps/examples/desktop-app/sidecar/browser-manager.test.ts",
      "apps/examples/desktop-app/sidecar/commands-workbench.test.ts",
      "apps/examples/desktop-app/sidecar/project-output.test.ts",
      "apps/examples/desktop-app/webview/components/views/chat/project-output-bar.test.tsx",
      "apps/examples/desktop-app/sidecar/repository-tool.test.ts",
      "apps/examples/desktop-app/sidecar/notion-agent-bridge.test.ts",
      "apps/examples/desktop-app/sidecar/notion-agent-patch.test.ts",
      "apps/examples/desktop-app/webview/components/views/settings/functions-view.test.tsx",
      "apps/examples/desktop-app/webview/components/views/engineering/engineering-workspace.test.tsx",
      "--config", "apps/examples/desktop-app/vitest.config.mts"]),
    job("Test real Hub shutdown runtime identity", ["x", "vitest", "run", "src/hub/daemon/shutdown.e2e.test.ts", "--config", "vitest.e2e.config.ts"], path.join(root, "sdk/packages/core")),
    job("Run focused SDK safety tests", ["x", "vitest", "run",
      "sdk/packages/core/src/extensions/tools/investigation.test.ts",
      "sdk/packages/core/src/hub/server/hub-capability-tool-executors.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/command-evidence.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/bash.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/bash.powershell.test.ts",
      "sdk/packages/core/src/extensions/tools/definitions.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/resource-governor.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/analysis-notebook.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/analysis-evidence-graph.test.ts",
      "sdk/packages/core/src/hub/client/index.test.ts",
      "sdk/packages/core/src/session/search/session-history-search.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/advanced-analysis.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/analysis-environment.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/ida-job-diagnostics.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/targeted-native-evidence.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/ida-analysis-workspace.test.ts",
      "sdk/packages/core/src/hub/discovery/startup-lock.test.ts",
      "sdk/packages/core/src/hub/daemon/index.test.ts",
      "sdk/packages/core/src/extensions/tools/permission-profile.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/process-session-manager.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/smali-search.test.ts",
 "sdk/packages/core/src/extensions/tools/executors/supervised-process.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/supervised-process-cancellation.test.ts",
 "sdk/packages/core/src/extensions/tools/executors/analysis-project-lease.test.ts",
 "sdk/packages/core/src/extensions/tools/executors/managed-engine-pool.test.ts",
 "sdk/packages/core/src/extensions/tools/executors/native-project-candidates.test.ts",
 "sdk/packages/core/src/extensions/tools/executors/live-debugger.test.ts",
 "sdk/packages/core/src/extensions/tools/team/writer-worktree.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/reverse-engineering.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/windows-tool-environment.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/advanced-analysis.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/android-investigation.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/targeted-decompiler-scripts.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/android-investigation-index.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/analysis-evidence-graph.test.ts",
      "sdk/packages/core/src/extensions/tools/executors/analysis-notebook.test.ts",
 "sdk/packages/core/src/extensions/tools/executors/analysis-program-evidence.test.ts",
      "sdk/packages/core/src/runtime/orchestration/notion-provenance.test.ts",
      "sdk/packages/core/src/runtime/orchestration/runtime-builder.test.ts",
      "sdk/packages/core/src/runtime/orchestration/session-runtime-orchestrator.test.ts",
      "--config", "vitest.config.mts", "--testTimeout=60000"]),
  ];
  const coreGateNames = [...prerequisites, ...checks].map(step => step.name);
  const engineChecks = [];
  if (flags.includes("--engines")) {
    const python = process.env.CLINE_RE_PYTHON;
    if (!python || !path.isAbsolute(python)) throw new Error("--engines requires an absolute trusted CLINE_RE_PYTHON");
    for (const corpus of ["server.test.py", "capture_support.test.py", "setup-controller.test.py"])
      engineChecks.push({ ...job(`Android controller corpus: ${corpus}`, [path.join(root, "workers/android-capture", corpus)]), executable: python });
    for (const corpus of ["advanced-analysis-worker.test.py", "advanced-ir.test.py", "advanced-crypto.test.py"]) {
      const args = engineCorpusArgs(corpus, root);
      engineChecks.push({ ...job(`Engine corpus: ${corpus}`, args), executable: python });
    }
  }
  checks.push(...engineChecks);
  let coreValidationReceipt = null;
  if (flags.includes("--reuse-core")) {
    coreValidationReceipt = process.env.CLINE_VALIDATION_CORE_RECEIPT;
    const receipt = coreValidationReceiptPath(root, coreValidationReceipt);
    const resolvedRoot = await realpath(path.join(root, ".cline-validation"));
    const resolvedReceipt = await realpath(receipt);
    if (!resolvedReceipt.startsWith(resolvedRoot + path.sep) || (await stat(resolvedReceipt)).size > 131072)
      throw new Error("Consolidated receipt must be bounded and inside local validation evidence");
    const report = JSON.parse(await readFile(resolvedReceipt, "utf8"));
    assertReusableCoreValidation(report, sourceCommit, coreGateNames, executionScope);
    console.log("[VERIFIED] Every core gate already passed for this commit, job and run attempt");
  }
  const active = new Map();
  const progressFile = path.join(output, "progress.jsonl");
  recordValidationProgress(progressFile, { event: "validation-start", parallel });
  let heartbeatCount = 0;
  const heartbeat = setInterval(() => {
    const message = formatValidationHeartbeat(active);
    console.log(message);
    if (process.env.GITHUB_ACTIONS === "true" && ++heartbeatCount % 10 === 0)
      console.log(formatValidationNotice(message));
    recordValidationProgress(progressFile, { event: "heartbeat", message });
  }, 30_000);
  let cancelled = false;
  function terminate(child) {
    if (!child.pid) return;
    if (process.platform === "win32") {
      try { execFileSync(path.join(process.env.SystemRoot ?? "C:\\Windows", "System32", "taskkill.exe"), ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore", timeout: 10000 }); } catch {}
    } else { try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); } }
  }
  const abort = () => { cancelled = true; for (const child of active.keys()) terminate(child); };
  process.on("SIGINT", abort); process.on("SIGTERM", abort);
  const run = async (step) => {
    if (cancelled) return { name: step.name, status: "cancelled" };
    const start = Date.now();
    const logName = step.name.toLowerCase().replace(/[^a-z0-9]+/g, "-") + ".log";
    const stream = createWriteStream(path.join(output, logName));
    console.log(`[START] ${step.name}`);
    if (process.env.GITHUB_ACTIONS === "true") console.log(formatValidationNotice(`[START] ${step.name}`));
    recordValidationProgress(progressFile, { event: "check-start", name: step.name, log: logName });
    return await new Promise(resolve => {
      let settled = false, timedOut = false, timer;
      const child = spawn(step.executable ?? process.execPath, step.args, {
        cwd: step.cwd, env: process.env, shell: false, detached: process.platform !== "win32", windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
      });
      active.set(child, { name: step.name, start });
      child.stdout?.pipe(stream, { end: false }); child.stderr?.pipe(stream, { end: false });
      const finish = (code) => {
        if (settled) return; settled = true; clearTimeout(timer); active.delete(child); stream.end();
        const status = cancelled ? "cancelled" : timedOut ? "timed-out" : code === 0 ? "passed" : "failed";
        console.log(`[${status.toUpperCase()}] ${step.name}`);
        if (process.env.GITHUB_ACTIONS === "true" && status !== "passed") console.log(formatValidationFailureNotice(`[${status.toUpperCase()}] ${step.name}`));
        recordValidationProgress(progressFile, { event: "check-finish", name: step.name, status, exitCode: code, durationMs: Date.now() - start });
        resolve({ name: step.name, status, exitCode: code, durationMs: Date.now() - start, log: logName });
      };
      child.once("error", () => finish(null)); child.once("close", code => finish(code));
      timer = setTimeout(() => { timedOut = true; terminate(child); finish(null); }, step.timeoutMs);
    });
  };
  const started = new Date().toISOString();
  let report;
  try { report = await runValidation(coreValidationReceipt ? [] : prerequisites, coreValidationReceipt ? engineChecks : checks, parallel, run); }
  finally {
    clearInterval(heartbeat);
    process.removeListener("SIGINT", abort); process.removeListener("SIGTERM", abort);
  }
  await writeFile(path.join(output, "summary.json"), JSON.stringify({
    schemaVersion: 1, started, finished: new Date().toISOString(), sourceCommit, parallel, executionScope,
    coreValidationReceipt,
    engineValidation: flags.includes("--engines") ? "requested-see-corpus-results" : "not-requested",
    engineProfile: flags.includes("--engines") ? (process.platform === "win32" ? "windows-portable" : "full") : "not-requested",
    windowsInstallerBuilt: false, ...report,
  }, null, 2) + "\n");
  if (process.env.GITHUB_OUTPUT && report.status === "passed" && !flags.includes("--engines")) {
    const receipt = path.relative(root, path.join(output, "summary.json")).split(path.sep).join("/");
    coreValidationReceiptPath(root, receipt);
    await writeFile(process.env.GITHUB_OUTPUT, `validation_receipt=${receipt}\n`, { flag: "a" });
  }
  if (process.env.GITHUB_STEP_SUMMARY) {
    try { await writeFile(process.env.GITHUB_STEP_SUMMARY, formatValidationSummary(report, sourceCommit), {flag:"a"}); }
    catch { console.warn("CI display summary unavailable; use the retained regression artifact. No check was replayed."); }
  }
  console.log(`Validation ${report.status}: ${path.relative(root, output)}/summary.json`);
  process.exitCode = report.status === "passed" ? 0 : 1;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
