import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { assertReusableCoreValidation, coreValidationReceiptPath, validationScope, engineCorpusArgs, formatValidationHeartbeat, formatValidationNotice, formatValidationFailureNotice, formatValidationSummary, recordValidationProgress, parseParallel, runJobs, runValidation } from "./validate-advanced-build.mjs";
const jobs = [1, 2, 3, 4, 5].map(n => ({ name: String(n) }));
test("core reuse requires every gate and the exact commit, job and run attempt", () => {
  const source = "a".repeat(40);
  const scope = { runId: "123", runAttempt: "2", job: "build" };
  const gates = ["build", "types", "isolation", "installer"];
  const receipt = { schemaVersion: 1, sourceCommit: source, status: "passed",
    engineValidation: "not-requested", executionScope: scope,
    results: gates.map(name => ({ name, status: "passed" })) };
  assert.doesNotThrow(() => assertReusableCoreValidation(receipt, source, gates, scope));
  for (const patch of [
    { status: "failed" }, { sourceCommit: "b".repeat(40) }, { schemaVersion: 0 },
    { engineValidation: "requested-see-corpus-results" }, { executionScope: { ...scope, runAttempt: "1" } },
    { executionScope: { ...scope, runId: "other" } }, { executionScope: { ...scope, job: "other" } },
    { results: receipt.results.slice(1) }, { results: [...receipt.results, { name: "extra", status: "passed" }] },
    { results: receipt.results.map((r, i) => i ? r : { ...r, status: "blocked" }) },
    { results: receipt.results.map((r, i) => i ? r : { ...r, status: "skipped" }) },
    { results: receipt.results.map((r, i) => i ? r : { ...r, status: "failed" }) },
    { results: receipt.results.map((r, i) => i ? r : { ...r, name: "types" }) },
    { results: receipt.results.map((r, i) => i ? r : { ...r, name: "unknown" }) },
  ]) assert.throws(() => assertReusableCoreValidation({ ...receipt, ...patch }, source, gates, scope));
  assert.throws(() => assertReusableCoreValidation(receipt, "unavailable", gates, scope));
  assert.throws(() => assertReusableCoreValidation(receipt, source, [...gates, "types"], scope));
});
test("core receipt path cannot select external, traversal or arbitrary JSON files", () => {
  assert.equal(coreValidationReceiptPath("/owned", ".cline-validation/123-456/summary.json"),
    path.join("/owned", ".cline-validation/123-456/summary.json"));
  for (const value of [undefined, "", "/tmp/summary.json", "../summary.json",
    ".cline-validation/../../summary.json", ".cline-validation/123-456/summary.json\n",
    ".cline-validation/123-456/other.json"])
    assert.throws(() => coreValidationReceiptPath("/owned", value));
  assert.deepEqual(validationScope({}), { runId: null, runAttempt: null, job: null });
});
test("receipt-verified engine phase retains all actual corpora and blocks unproved reuse", () => {
  const workflow = readFileSync(new URL("../.github/workflows/build-custom-windows-installer.yml", import.meta.url), "utf8");
  assert.ok(workflow.includes("CLINE_VALIDATION_CORE_RECEIPT: ${{ steps.consolidated.outputs.validation_receipt }}"));
  assert.ok(workflow.includes("bun run validate:advanced --engines --reuse-core"));
  assert.ok(workflow.includes("advanced-windows-engine-smoke.test.ts"));
  const runner = readFileSync(new URL("./validate-advanced-build.mjs", import.meta.url), "utf8");
  assert.ok(runner.includes("assertReusableCoreValidation(report, sourceCommit, coreGateNames, executionScope)"));
  assert.ok(runner.includes('realpath(receipt)'));
  assert.ok(runner.includes('size > 131072'));
  assert.ok(runner.includes('coreValidationReceipt ? engineChecks : checks'));
  assert.ok(runner.includes('!flags.includes("--engines")'));
  for (const file of ["server.test.py", "capture_support.test.py", "setup-controller.test.py",
    "advanced-analysis-worker.test.py", "advanced-ir.test.py", "advanced-crypto.test.py"])
    assert.ok(runner.includes(file));
});
test("engine corpus explicitly selects the shipped Windows profile without weakening full-engine execution", () => {
  const corpus = "advanced-analysis-worker.test.py";
  assert.deepEqual(engineCorpusArgs(corpus, "/owned", "win32").slice(1), ["--engine-profile", "windows-portable"]);
  assert.deepEqual(engineCorpusArgs(corpus, "/owned", "linux").slice(1), ["--engine-profile", "full"]);
  assert.equal(engineCorpusArgs("advanced-ir.test.py", "/owned", "win32").length, 1);
  assert.equal(engineCorpusArgs("advanced-crypto.test.py", "/owned", "win32").length, 1);
  const python = readFileSync(new URL("../sdk/packages/core/scripts/advanced-analysis-worker.test.py", import.meta.url), "utf8");
  assert.ok(python.includes("Missing optional engine: triton"));
  assert.ok(python.includes("Missing optional engine: qbindiff"));
  assert.ok(python.includes("owned-native-elf.json"));
  assert.ok(!python.includes("unittest.skip"));
});
test("heartbeats identify every active gate without exposing commands or environment", () => {
  const active = new Map([[{}, { name: "sidecar", start: 1000, args: ["secret"] }], [{}, { name: "installer", start: 3000 }]]);
  assert.equal(formatValidationHeartbeat(active, 5000), "[PROGRESS] sidecar: 4s; installer: 2s");
  assert.equal(formatValidationHeartbeat(new Map(), 5000), "[PROGRESS] no active checks");
});
test("public progress annotations are bounded and cannot inject workflow commands", () => {
  const annotation = formatValidationNotice("gate%\r\n::error::injected\u0000");
  assert.equal(annotation, "::notice title=Custom validation progress::gate%25%0D%0A::error::injected");
  assert.ok(!annotation.includes("\n"));
  assert.equal(formatValidationNotice("x".repeat(2000)).split("::").at(-1).length, 1000);
  const runner = readFileSync(new URL("./validate-advanced-build.mjs", import.meta.url), "utf8");
  assert.ok(runner.includes('process.env.GITHUB_ACTIONS === "true"'));
  assert.ok(runner.includes("++heartbeatCount % 10 === 0"));
});
test("progress records are independently readable before a final summary exists", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "cline-validation-progress-"));
  try {
    const file = path.join(dir, "progress.jsonl");
    recordValidationProgress(file, { event: "check-start", name: "sidecar" });
    assert.equal(JSON.parse(readFileSync(file, "utf8")).event, "check-start");
    recordValidationProgress(file, { event: "check-finish", name: "sidecar", status: "failed" });
    const records = readFileSync(file, "utf8").trim().split("\n").map(line => JSON.parse(line));
    assert.equal(records.length, 2);
    assert.equal(records[1].status, "failed");
    assert.ok(records.every(record => !Number.isNaN(Date.parse(record.timestamp))));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("Windows validation has an external deadline and bounded workers without dropping suites", () => {
  const workflow = readFileSync(new URL("../.github/workflows/build-custom-windows-installer.yml", import.meta.url), "utf8");
  assert.match(workflow, /name: Run consolidated custom fork validation[\s\S]*?timeout-minutes: 35[\s\S]*?CLINE_VALIDATION_PARALLEL: "1"[\s\S]*?run: bun run validate:advanced/);
  const config = readFileSync(new URL("../apps/examples/desktop-app/vitest.config.mts", import.meta.url), "utf8");
  assert.ok(config.includes('maxWorkers: process.platform === "win32" && process.env.CI ? 2 : undefined'));
  const runner = readFileSync(new URL("./validate-advanced-build.mjs", import.meta.url), "utf8");
  assert.ok(runner.includes('job("Run required desktop sidecar regression suite"'));
  assert.ok(runner.includes('job("Test Windows installer configuration"'));
  assert.ok(runner.includes("clearInterval(heartbeat)"));
});
test("parallelism is bounded and rejects malformed values", () => {
  assert.equal(parseParallel(), 2); assert.equal(parseParallel("4"), 4);
  for (const value of [0, -1, 5, 1.5, NaN, "bad"]) assert.throws(() => parseParallel(value));
});
test("independent checks run within the concurrency cap and preserve report order", async () => {
  let active = 0, max = 0;
  const result = await runJobs(jobs, 2, async x => { active++; max = Math.max(max, active); await new Promise(r => setTimeout(r, 8)); active--; return { name: x.name, status: "passed" }; });
  assert.equal(max, 2); assert.deepEqual(result.map(x => x.name), jobs.map(x => x.name));
});
test("a failed check does not hide remaining failures", async () => {
  const result = await runJobs(jobs, 2, async x => ({ name: x.name, status: x.name === "1" ? "failed" : "passed" }));
  assert.equal(result.length, 5); assert.equal(result[0].status, "failed"); assert.equal(result[4].status, "passed");
});
test("rejected checks produce an explicit failed outcome", async () => {
  const result = await runJobs(jobs, 1, async () => { throw new Error("private detail"); });
  assert.equal(result[0].status, "failed"); assert.ok(!JSON.stringify(result).includes("private detail"));
});
test("prerequisites complete before any independent check", async () => {
  const seen = []; await runValidation([{ name: "build" }], jobs, 2, async x => { seen.push(x.name); return { name: x.name, status: "passed" }; }); assert.equal(seen[0], "build");
});
test("a failed prerequisite blocks dependent checks instead of false passing", async () => {
  const seen = []; const result = await runValidation([{ name: "build" }], jobs, 2, async x => { seen.push(x.name); return { name: x.name, status: "failed" }; });
  assert.deepEqual(seen, ["build"]); assert.equal(result.status, "failed"); assert.equal(result.results.filter(x => x.status === "blocked").length, 5);
});
test("the aggregate status fails if any required check fails", async () => {
  const result = await runValidation([], jobs, 2, async x => ({ name: x.name, status: x.name === "3" ? "failed" : "passed" })); assert.equal(result.status, "failed");
});

test("installed Hub smoke never expires before the SDK startup contract", () => {
  const sdk = readFileSync(new URL("../sdk/packages/core/src/hub/daemon/index.ts", import.meta.url), "utf8");
  const smoke = readFileSync(new URL("../apps/examples/desktop-app/scripts/desktop-startup.test.ts", import.meta.url), "utf8");
  const value = (text, name) => { const m = text.match(new RegExp("const " + name + " = ([0-9_]+);")); assert.ok(m, `Missing ${name}`); return Number(m[1].replaceAll("_", "")); };
  assert.ok(value(smoke, "HUB_BOOTSTRAP_TIMEOUT_MS") >= value(sdk, "HUB_STARTUP_TIMEOUT_MS") + 5000);
  assert.ok(smoke.includes("timeout: HUB_BOOTSTRAP_TIMEOUT_MS"));
  assert.ok(smoke.includes("expect(health.ok).toBe(true)"));
  assert.ok(smoke.includes("expect(restartedHealth.ok).toBe(true)"));
});

test("workspace quality retains complete typecheck scope and Bun smoke declarations",()=>{
 const pkg=JSON.parse(readFileSync(new URL("../package.json",import.meta.url),"utf8"));
 assert.equal(pkg.scripts.types,"bun --sequential -F '*' typecheck");
 const smoke=JSON.parse(readFileSync(new URL("../sdk/packages/core/tsconfig.smoke.json",import.meta.url),"utf8"));
 assert.deepEqual(smoke.include,["scripts/**/*","src/**/*"]);
 assert.deepEqual(smoke.exclude,["scripts/advanced-windows-engine-smoke.test.ts"]);
 const bunSmoke=JSON.parse(readFileSync(new URL("../sdk/packages/core/tsconfig.bun-smoke.json",import.meta.url),"utf8"));
 assert.deepEqual(bunSmoke.compilerOptions.types,["node","bun"]);assert.deepEqual(bunSmoke.include,smoke.exclude);assert.deepEqual(bunSmoke.exclude,[]);
 const core=JSON.parse(readFileSync(new URL("../sdk/packages/core/package.json",import.meta.url),"utf8"));
 assert.equal(core.scripts["typecheck:smoke"],"bun tsc -p tsconfig.smoke.json --noEmit && bun tsc -p tsconfig.bun-smoke.json --noEmit");
 const workflow=readFileSync(new URL("../.github/workflows/sdk-test.yml",import.meta.url),"utf8");
 assert.equal((workflow.match(/bun-version: \$\{\{ steps\.toolchain\.outputs\.version \}\}/g)||[]).length,2);assert.ok(workflow.includes("bun run types"));assert.ok(workflow.includes("run: bun run lint"));assert.ok(workflow.includes("needs: quality-checks"));
});

test("advanced integration retains worker fixture and compilation gates without implying device validation",()=>{
 const runner=readFileSync(new URL("./validate-advanced-build.mjs",import.meta.url),"utf8");for(const file of ["android-runtime-client.test.ts","analysis-investigation-store.test.ts","investigation-workspace.test.tsx"])assert.ok(runner.includes(file));
 const workflow=readFileSync(new URL("../.github/workflows/build-custom-windows-installer.yml",import.meta.url),"utf8");assert.ok(workflow.includes("workers/android-capture/server.test.py"));assert.ok(workflow.includes("Build pinned Android instrumentation bundle"));assert.ok(workflow.includes("not live-device validation"));assert.ok(workflow.includes("Run process-session terminal smoke test"));
});

test("confirmed CI repairs preserve DB close/rollback and exact launched Bun identity",()=>{
 const worker=readFileSync(new URL("../workers/android-capture/server.py",import.meta.url),"utf8");assert.ok(worker.includes("with connection:yield connection"));assert.ok(worker.includes("finally:connection.close()"));
 const shutdown=readFileSync(new URL("../sdk/packages/core/src/hub/daemon/shutdown.e2e.test.ts",import.meta.url),"utf8");assert.ok(shutdown.includes("probeBunRuntimeVersion(executable)"));assert.equal((shutdown.match(/runtime: bun \$\{daemon.runtimeVersion\}/g)||[]).length,2);assert.ok(!shutdown.includes("runtime: bun 1.3.13"));assert.ok(shutdown.includes("toBeLessThan(5_000)"));assert.ok(shutdown.includes("forced exit:"));
 const runner=readFileSync(new URL("./validate-advanced-build.mjs",import.meta.url),"utf8");assert.ok(runner.includes("Test real Hub shutdown runtime identity"));
});


test("full-quality gates include test/smoke typing and lint with the CLI prerequisite",()=>{
 const runner=readFileSync(new URL("./validate-advanced-build.mjs",import.meta.url),"utf8");
 assert.ok(runner.includes('job("Build CLI workspace quality prerequisite", ["run", "-F", "@cline/cli", "build"])'));
 assert.ok(runner.includes('job("Type-check complete workspace including tests and smoke declarations", ["run", "types"])'));
 assert.ok(runner.includes('job("Lint complete workspace", ["run", "lint"])'));
 assert.ok(runner.includes('formatValidationFailureNotice(`[${status.toUpperCase()}] ${step.name}`)'));
 assert.ok(runner.includes("GITHUB_STEP_SUMMARY"));
});
test("failed gates expose safe actionable CI annotations without raw child output",()=>{
 const text=formatValidationFailureNotice("[FAILED] gate%\r\n::warning::injected\u0000");
 assert.equal(text,"::error title=Required validation gate::[FAILED] gate%25%0D%0A::warning::injected");
 assert.ok(!text.includes("\n"));
});
test("CI summaries retain failed/blocked statuses without leaking log contents or private fields",()=>{
 const report={status:"failed",results:[{name:"gate|<>`\n",status:"failed",durationMs:1100,stderr:"SECRET",request:{key:"SECRET"}},{name:"later",status:"blocked"}]};
 const text=formatValidationSummary(report,"a".repeat(40));
 assert.ok(text.includes("validation: failed"));assert.ok(text.includes("| failed | 1 |"));assert.ok(text.includes("| later | blocked | — |"));assert.ok(!text.includes("SECRET"));assert.ok(!text.includes("<>"));
 assert.ok(formatValidationSummary(report,"not-a-commit\nSECRET").includes("Source commit: unavailable"));
});


test("shipped investigation skills are a blocking core and installed gate before Hub startup",()=>{
 const runner=readFileSync(new URL("./validate-advanced-build.mjs",import.meta.url),"utf8");
 assert.ok(runner.includes('job("Test bundled investigation skills"'));
 assert.ok(runner.includes('"sidecar/commands-skills.test.ts"'));
 const sidecar=readFileSync(new URL("../apps/examples/desktop-app/sidecar/index.ts",import.meta.url),"utf8");
 assert.ok(sidecar.indexOf('process.argv.includes("--cline-investigation-skills-selfcheck")')<sidecar.indexOf("configureFirstPartyAnalysisHost({"));
 const acceptance=readFileSync(new URL("../apps/vscode/scripts/desktop-installed-acceptance.ts",import.meta.url),"utf8");
 const selfcheck=acceptance.indexOf('startAcceptanceProcess(sidecar, ["--cline-investigation-skills-selfcheck"]');
 const bootstrap=acceptance.indexOf('"--remote-hub-ensure"');
 assert.ok(selfcheck>=0 && bootstrap>=0 && selfcheck<bootstrap);
 for(const stage of ["installed-bundled-investigation-skills-instruction-only-namespace-disable-passed","installed-bundled-investigation-skills-disable-persisted-restart-passed"])
  assert.ok(acceptance.includes(stage));
 assert.ok(acceptance.includes('verifyInstalledInvestigationCatalog(await readSkills(), false, installedSkillRoot)'));
});
