import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { QUICK_CHECKS, runQuick } from "./verify-quick.mjs";
import { actionTimings, validationTimings, formatTimings } from "./summarize-verification.mjs";
const load = p => readFileSync(new URL(`../${p}`,import.meta.url),"utf8");
test("quick feedback fails closed and never runs a shell or release operation",()=>{
  let calls=0;
  assert.equal(runQuick((exe,args,options)=>{calls++;assert.equal(options.shell,false);assert.equal(options.timeout,120000);return {status:calls===2?1:0};}),1);
  assert.equal(calls,2);
  for(const result of [{error:new Error("missing")},{status:null},{status:0,signal:"SIGTERM"}]) assert.equal(runQuick(()=>result),1);
  assert.equal(runQuick(()=>({status:0})),0);
  assert.ok(QUICK_CHECKS.every(([,args])=>!args.some(a=>/tauri|--reuse-core|--engines/.test(a))));
});
test("early quick tier precedes compiler/download setup but does not replace full acceptance",()=>{
  const w=load(".github/workflows/build-custom-windows-installer.yml");
  assert.ok(w.indexOf("name: Fast verification preflight")<w.indexOf("name: Seed Bun cache"));
  for(const name of ["Run consolidated custom fork validation","Validate portable Windows analysis engines","Build NSIS installer","Smoke-test installer and installed binaries","Installed WebView acceptance journey","Upload verified setup.exe"]) assert.ok(w.includes(`name: ${name}`));
  assert.ok(w.includes("run: bun run validate:advanced"));
  assert.ok(w.includes("steps.ui_acceptance.outcome == 'success'"));
  assert.ok(!w.includes("continue-on-error"));
  const regression=load(".github/workflows/custom-desktop-validation.yml");
  assert.ok(regression.indexOf("name: Fast verification preflight")<regression.indexOf("name: Setup validation tools"));
  assert.ok(regression.includes("run: bun run validate:advanced"));
});
test("compiler caches are precisely scoped and never substitute cached acceptance outputs",()=>{
  const w=load(".github/workflows/build-custom-windows-installer.yml");
  assert.ok(w.includes("windows-cargo-v2-${{ runner.arch }}-${{ env.RUST_TOOLCHAIN }}"));
  assert.ok(w.includes("src-tauri/src/**/*.rs"));assert.ok(w.includes("src-tauri/build.rs"));assert.ok(w.includes("src-tauri/tauri*.json"));
  assert.ok(w.includes("path: apps/examples/desktop-app/webview/.next/cache"));
  assert.ok(w.includes("!apps/examples/desktop-app/src-tauri/target/release/bundle/**"));
  assert.ok(!w.includes("if: steps.cache.outputs.cache-hit"));
  assert.ok(w.includes("hashFiles('bun.lock', 'workers/android-capture/bun.lock')"));
  assert.ok(w.includes("bun install --frozen-lockfile"));
  assert.ok(w.includes("Remove-Item 'src-tauri/target/release/bundle/nsis'"));
  assert.ok(w.includes("Expected exactly one fresh installer"));
});
test("timing rows require exact source and execution scope",()=>{
  const scope={sha:"a".repeat(40),runId:"1",runAttempt:"2",job:"build"};
  const r={sourceCommit:scope.sha,executionScope:{runId:"1",runAttempt:"2",job:"build"},results:[{name:"gate",status:"passed",durationMs:50,secret:"NEVER"}]};
  assert.deepEqual(validationTimings(r,scope),[{name:"gate",status:"passed",durationMs:50}]);
  for(const s of [{...scope,sha:"b".repeat(40)},{...scope,runAttempt:"3"},{...scope,job:"other"}])assert.deepEqual(validationTimings(r,s),[]);
  assert.ok(!formatTimings(validationTimings(r,scope),[]).includes("NEVER"));
});
test("journal timings pair exact sequences/phases and include failures without replay",()=>{
  const row=(sequence,phase,status,at)=>JSON.stringify({sequence,phase,status,at});
  const s=[row(1,"launch","running","2026-10-19T12:00:00Z"),row(1,"wrong","completed","2026-10-19T12:00:01Z"),row(1,"launch","failed","2026-10-19T12:00:02Z"),row(2,"bad\n::error::","running","2026-10-19T12:00:00Z"),"invalid"].join("\n");
  assert.deepEqual(actionTimings(s),[{name:"launch",status:"failed",durationMs:2000}]);
  assert.throws(()=>actionTimings("x".repeat(2*1024*1024+1)));
  const report=formatTimings([{name:"x|<>`\n",status:"failed",durationMs:1000}],[]);assert.ok(!report.includes("x|<>"));assert.ok(report.includes("diagnostic only"));assert.ok(report.includes("not additive wall time"));
});
test("diagnostic reader omits stale, malformed and missing receipts",async()=>{
  const {mkdtemp,mkdir,writeFile,rm}=await import("node:fs/promises");
  const {tmpdir}=await import("node:os");const path=await import("node:path");
  const {summarize}=await import("./summarize-verification.mjs");
  const root=await mkdtemp(path.join(tmpdir(),"cline-timing-"));
  try {
    const dir=path.join(root,".cline-validation","123-456");await mkdir(dir,{recursive:true});
    await writeFile(path.join(dir,"summary.json"),JSON.stringify({sourceCommit:"b".repeat(40),executionScope:{runId:"1",runAttempt:"1",job:"build"},results:[{name:"STALE_NEVER_COPY",status:"passed",durationMs:10}]}));
    const report=await summarize(root,{GITHUB_SHA:"a".repeat(40),GITHUB_RUN_ID:"1",GITHUB_RUN_ATTEMPT:"1",GITHUB_JOB:"build"});
    assert.ok(!report.includes("STALE_NEVER_COPY"));assert.ok(report.includes("diagnostic only"));
    await writeFile(path.join(dir,"summary.json"),"not json");assert.ok((await summarize(root,{})).includes("diagnostic only"));
  }finally{await rm(root,{recursive:true,force:true});}
});
