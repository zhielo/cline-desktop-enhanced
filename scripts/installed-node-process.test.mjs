import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ANALYSIS_PROFILE } from "../sdk/packages/core/src/analysis/contracts.ts";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
	withInstalledActionDeadline,
 INSTALLED_ACTION_LIMIT,
 assertInstalledActionSequence,
	ownedDescendantMetadata,
	startAcceptanceProcess,
	stopOwnedApplication,
 stopOwnedWindowsTree,
 verifyOwnedTreeStopReceipt,
 OWNED_WINDOWS_TREE_STOP,
	verifyRestartInstructions,
	verifyRecoveredHubSession,
	waitForInstalledBackendEndpoint,
	verifyInstalledAnalysisProfile,
 openInstalledSavedSession,
} from "../apps/vscode/scripts/desktop-installed-acceptance.ts";

test("owned native tree is stopped before CDP can tear down its WebView children", async () => {
  const order = [];
  let rootAlive = true;
  await stopOwnedApplication(async () => {
    assert.equal(rootAlive, true);
    order.push("terminate-tree");
    rootAlive = false;
  }, async () => {
    assert.equal(rootAlive, false);
    order.push("disconnect-cdp");
  });
  assert.deepEqual(order, ["terminate-tree", "disconnect-cdp"]);
});

test("owned stop failures remain failures and disconnect still runs without replay", async () => {
  const stopError = new Error("owned tree termination unconfirmed");
  const disconnectError = new Error("owned disconnect failed");
  let kills = 0, disconnects = 0;
  await assert.rejects(stopOwnedApplication(async () => {
    kills++; throw stopError;
  }, async () => { disconnects++; }), error => error === stopError);
  assert.equal(kills, 1);
  assert.equal(disconnects, 1);
  await assert.rejects(stopOwnedApplication(async () => {
    kills++; throw stopError;
  }, async () => { disconnects++; throw disconnectError; }), error => {
    assert.ok(error instanceof AggregateError);
    assert.deepEqual(error.errors, [stopError, disconnectError]);
    return true;
  });
  assert.equal(kills, 2);
  assert.equal(disconnects, 2);
  await assert.rejects(stopOwnedApplication(async () => { kills++; },
    async () => { disconnects++; throw disconnectError; }),
    error => error === disconnectError);
  assert.equal(kills, 3);
  assert.equal(disconnects, 3);
});

test("Hub crash acceptance reattaches before local discovery without replay or hiding errors", async () => {
  const calls = [];
  await verifyRecoveredHubSession(async () => { calls.push("attach"); }, async () => {
    assert.deepEqual(calls, ["attach"]);
    calls.push("list"); return [{sessionId:"owned"}];
  }, "owned");
  assert.deepEqual(calls, ["attach", "list"]);
  let reads = 0;
  await assert.rejects(verifyRecoveredHubSession(async () => {}, async () => {
    reads++; throw new Error("disk I/O error");
  }, "owned"), /disk I\/O error/);
  assert.equal(reads, 1);
  await assert.rejects(verifyRecoveredHubSession(async () => { throw new Error("recovery failed"); },
    async () => { reads++; return []; }, "owned"), /recovery failed/);
  assert.equal(reads, 1);
  await assert.rejects(verifyRecoveredHubSession(async () => {}, async () => [], "owned"),
    /Saved session missing/);
});

test("installed backend discovery tolerates only bounded native not-ready responses", async () => {
	let attempts = 0;
	const endpoint = "ws://127.0.0.1:12345/transport?approval_token=owned";
	const result = await waitForInstalledBackendEndpoint(async () => {
		if (++attempts < 3) throw new Error("page.evaluate: desktop backend endpoint not ready");
		return endpoint;
	}, {pollMs:0});
	assert.equal(result, endpoint);
	assert.equal(attempts, 3);
	await assert.rejects(waitForInstalledBackendEndpoint(async () => {
		throw new Error("desktop backend endpoint not ready");
	}, {pollMs:0}), /bounded discovery budget/);
	await assert.rejects(waitForInstalledBackendEndpoint(async () => {
		throw new Error("permanent owned startup failure");
	}), /permanent owned startup failure/);
	await assert.rejects(waitForInstalledBackendEndpoint(async () => "ws://external.example/transport"),
		/local WebSocket endpoint/);
	await assert.rejects(waitForInstalledBackendEndpoint(() => new Promise(() => {}), {timeoutMs:10}),
		/readiness deadline exceeded/);
});

test("native Node child receives exact per-process WebView2 environment and reports exit/output", async () => {
	const profile = "owned fixture profile with spaces";
	const flags =
		"--remote-debugging-port=12345 --remote-debugging-address=127.0.0.1";
	const child = startAcceptanceProcess(
		process.execPath,
		[
			"-e",
			`
		process.stdout.write(JSON.stringify({profile: process.env.WEBVIEW2_USER_DATA_FOLDER,
			flags: process.env.WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS,
			optIn: process.env.CLINE_INSTALLED_ACCEPTANCE}));
		process.stderr.write("owned startup diagnostic");
		process.exitCode = 7;
	`,
		],
		process.cwd(),
		{
			...process.env,
			CLINE_INSTALLED_ACCEPTANCE: "1",
			WEBVIEW2_USER_DATA_FOLDER: profile,
			WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: flags,
		},
	);
	assert.equal(await child.exited, 7);
	await child.closed;
	assert.deepEqual(JSON.parse(child.diagnostics.stdoutTail), {
		profile,
		flags,
		optIn: "1",
	});
	assert.equal(child.diagnostics.stderrTail, "owned startup diagnostic");
	assert.equal(child.diagnostics.launchError, "");
});
test("native Node launch failure is observed instead of becoming an unhandled error", async () => {
	const child = startAcceptanceProcess(
		join(tmpdir(), "owned-missing-executable-7bdb0c7f"),
		[],
		process.cwd(),
		process.env,
	);
	assert.equal(await child.exited, null);
	await child.closed;
	assert.match(child.diagnostics.launchError, /ENOENT/);
});
test("native Node process output retention is bounded", async () => {
	const child = startAcceptanceProcess(
		process.execPath,
		[
			"-e",
			`
		process.stdout.write("x".repeat(32768));
		process.stderr.write("y".repeat(32768));
	`,
		],
		process.cwd(),
		process.env,
	);
	assert.equal(await child.exited, 0);
	await child.closed;
	assert.equal(child.diagnostics.stdoutTail.length, 16384);
	assert.equal(child.diagnostics.stderrTail.length, 16384);
});

test("restart assertion waits for enabled hydrated UI and still rejects data loss", async () => {
	let ready = false;
	const instructions = {
		async click(options) {
			assert.deepEqual(options, { trial: true, timeout: 30000 });
			ready = true;
		},
		async inputValue() {
			assert.equal(ready, true);
			return "persisted";
		},
	};
	await verifyRestartInstructions(instructions, "persisted");
	await assert.rejects(
		verifyRestartInstructions(instructions, "lost"),
		/did not survive restart/,
	);
	await assert.rejects(
		verifyRestartInstructions(
			{
				async click() {
					throw new Error("not hydrated");
				},
			},
			"persisted",
		),
		/not hydrated/,
	);
});
test("descendant diagnostics reject recycled parent PIDs and unrelated processes", () => {
	const row = (pid, parentPid, createdAt) => ({
		name: "owned",
		pid,
		parentPid,
		createdAt,
		debuggingArgumentObserved: false,
		ownedProfileObserved: false,
	});
	const snapshot = [
		row(40, 1, "2026-10-08T12:00:00Z"),
		row(41, 40, "2026-10-08T12:00:01Z"),
		row(42, 41, "2026-10-08T12:00:02Z"),
		row(9, 40, "2026-10-07T00:00:00Z"),
		row(10, 9, "2026-10-08T12:01:00Z"),
		row(43, 41, "invalid"),
		row(90, 1, "2026-10-08T12:01:00Z"),
	];
	assert.deepEqual(
		ownedDescendantMetadata(snapshot, 40, "2026-10-08T12:00:00Z", "owned").map(
			(p) => p.pid,
		),
		[41, 42],
	);
	assert.deepEqual(
		ownedDescendantMetadata(snapshot, 40, "2026-10-09T12:00:00Z", "owned"),
		[],
	);
	assert.deepEqual(
		ownedDescendantMetadata(snapshot, 40, "2026-10-08T12:00:00Z", "foreign"),
		[],
	);
	assert.deepEqual(
		ownedDescendantMetadata(snapshot, 999, "2026-10-08T12:00:00Z", "owned"),
		[],
	);
	assert.deepEqual(
		ownedDescendantMetadata(
			[row(40, 1, "invalid")],
			40,
			"2026-10-08T12:00:00Z",
			"owned",
		),
		[],
	);
});

test("new installed receipt must match current parser profile, not historical profiles", () => {
  assert.equal(ANALYSIS_PROFILE, "cline-js-static/7");
  assert.doesNotThrow(() => verifyInstalledAnalysisProfile(ANALYSIS_PROFILE));
  for (const profile of ["cline-js-static/6", "cline-js-static/1", "", "unknown"])
    assert.throws(() => verifyInstalledAnalysisProfile(profile), /Installed analysis profile is stale/);
});


test("installed action deadline is Node-owned, single-shot and keeps successful results", async () => {
 let calls=0;
 assert.equal(await withInstalledActionDeadline("owned-read",async()=>{calls++;return 42;},100),42);
 assert.equal(calls,1);
 await assert.rejects(withInstalledActionDeadline("owned-stalled-ipc",()=>new Promise(()=>{}),10),/owned-stalled-ipc; no replay/);
});
test("timed-out accepted action is never replayed and late rejection remains handled", async () => {
 let calls=0;
 await assert.rejects(withInstalledActionDeadline("owned-accepted-action",()=>{calls++;return new Promise((_,reject)=>setTimeout(()=>reject(new Error("late failure")),30));},5),/deadline exceeded/);
 await new Promise(resolve=>setTimeout(resolve,50));
 assert.equal(calls,1);
});
test("invalid phase or deadline cannot invoke an installed action", async () => {
 let calls=0;
 for(const [phase,ms] of [["bad\nphase",10],["owned",0],["owned",Infinity],["owned",180001]])
  await assert.rejects(withInstalledActionDeadline(phase,async()=>{calls++;},ms),/Invalid installed action/);
 assert.equal(calls,0);
});
test("Windows browser creation is async and acceptance writes bounded action evidence", () => {
 const native=readFileSync(new URL("../apps/examples/desktop-app/src-tauri/src/built_in_browser.rs",import.meta.url),"utf8");
 assert.match(native, /#\[tauri::command\]\s+pub async fn built_in_browser_start\(/);
 assert.ok(native.includes("safe_url(&url)?"));
 assert.ok(native.includes("try_state::<crate::installed_webview_launch::AcceptanceWebviewState>()"));
 assert.ok(native.includes(".additional_browser_args(&options.additional_browser_args)"));
 assert.ok(native.includes(".data_directory(options.data_directory.clone())"));
 const main=readFileSync(new URL("../apps/examples/desktop-app/src-tauri/src/main.rs",import.meta.url),"utf8");
 assert.ok(main.includes("builder.manage(installed_webview_launch::AcceptanceWebviewState(acceptance_options))"));
 assert.ok(main.includes("window.additional_browser_args = Some(options.additional_browser_args.clone())"));
 assert.ok(main.includes("window.data_directory = Some(options.data_directory.clone())"));
 const installer=readFileSync(new URL("../apps/examples/desktop-app/scripts/windows-installer.test.ts",import.meta.url),"utf8");
 assert.ok(!installer.includes('Bun.spawnSync([nsis, "/VERSION"])'));
 assert.match(installer,/promisify\(execFile\)\(nsis, \["\/VERSION"\],[\s\S]*?timeout: 10_000/);
 assert.ok(installer.includes("version.stdout.trim()"));
 assert.ok(native.includes("crate::browser_readiness::await_browser_ready("));
 assert.ok(native.indexOf("await_browser_ready(") < native.indexOf(".show()"));
 const readiness=readFileSync(new URL("../apps/examples/desktop-app/src-tauri/src/browser_readiness.rs",import.meta.url),"utf8");
 assert.ok(readiness.includes("timeout_at(deadline, receiver)"));
 assert.ok(readiness.includes("for _ in 0..300"));
 assert.ok(readiness.includes("Ok(Ok(result)) => return result"));
 assert.ok(readiness.includes("creation was not acknowledged"));
 assert.ok(!readiness.includes("built_in_browser_cdp("));
 assert.ok(!readiness.includes("browser_capture::begin("));
 const workflow=readFileSync(new URL("../.github/workflows/build-custom-windows-installer.yml",import.meta.url),"utf8");
 assert.ok(workflow.includes("Cargo.toml browser_readiness::"));
 assert.ok(workflow.includes("throw 'Native browser readiness fixtures failed'"));
 const driver=readFileSync(new URL("../apps/vscode/scripts/desktop-installed-acceptance.ts",import.meta.url),"utf8");
 assert.ok(driver.includes('join(evidence, "phase.json")'));
 assert.ok(driver.includes('join(evidence, "action-progress.jsonl")'));
 assert.ok(driver.includes('assertInstalledActionSequence(sequence)'));
 assert.ok(driver.includes('sequence > INSTALLED_ACTION_LIMIT'));
 assert.ok(driver.includes('installed-owned-ui/processor-setup-core-full-core-120-row-v12'));
 assert.match(driver, /acceptanceAction\(`rpc-\$\{command\}`/);
 assert.match(driver, /acceptanceAction\(`native-\$\{name\}`/);
 assert.ok(driver.includes('installed-ai-batch-preview-approved-dag-checkpoint-no-replay-passed'));
 assert.ok(driver.includes('Installed completed batch was replayed'));
 assert.ok(driver.includes('installed-candidate-validation-review-hash-scope-preservation-passed'));
 assert.ok(driver.includes('installed-runtime-plan-owned-identity-no-attach-no-execute-passed'));
 assert.ok(driver.includes('Runtime planner executed owned target'));
 assert.ok(driver.includes('runtime-plan-fixture-cleanup'));
 assert.ok(driver.includes('installed-runtime-process-file-capture-approval-no-attach-passed'));
 assert.ok(driver.includes('Runtime approval replay succeeded'));
 assert.ok(driver.includes('Static enabled runtime metadata capture'));
 assert.ok(driver.includes('Installed candidate handle crossed session boundary'));
 assert.ok(driver.includes('installed-ai-batch-read-only-profile-denied'));
 assert.ok(driver.includes('Installed batch widened the Read Only session'));
 assert.ok(driver.indexOf('const triageScope=') < driver.indexOf('const batchRequest='));
 assert.ok(driver.includes('installed-owned-app-cleanup-confirmed'));
 assert.ok(driver.indexOf('installed-owned-app-cleanup-confirmed')<driver.indexOf('status: "passed"'));
});


test("expanded installed workload retains a finite fail-closed action evidence budget", () => {
 assert.equal(INSTALLED_ACTION_LIMIT,768);
 for(const sequence of [1,256,257,384,385,512,768]) assert.doesNotThrow(()=>assertInstalledActionSequence(sequence));
 for(const sequence of [0,-1,1.5,769,Infinity,NaN,Number.MAX_SAFE_INTEGER+1]) assert.throws(()=>assertInstalledActionSequence(sequence),/evidence budget reached/);
});

test("installed acceptance retains managed Node Execute approval, sampling limits and Off cleanup",()=>{
 const driver=readFileSync(new URL('../apps/vscode/scripts/desktop-installed-acceptance.ts',import.meta.url),'utf8');
 for(const text of ['installed-managed-node-approval-breakpoint-sampling-stop-cleanup-passed','debugger-activation-cleanup-may-pause-or-resume','v8-cpu-sampling-selected-script','managed-runtime-fixture-cleanup','Managed stop crossed owning sessions','Static enabled managed debugger'])assert.ok(driver.includes(text),text);
});


test("installed managed fixtures launch through a trusted canonical root, not Windows 8.3 aliases",()=>{
 const driver=readFileSync(new URL("../apps/vscode/scripts/desktop-installed-acceptance.ts",import.meta.url),"utf8");
 assert.ok(driver.includes('const root = realpathSync.native(await mkdtemp(join(tmpdir(), "cline-installed-ui-")))'));
});

test("installed saved correlation keeps identity, owner and no-rerun boundaries",()=>{
 const driver=readFileSync(new URL("../apps/vscode/scripts/desktop-installed-acceptance.ts",import.meta.url),"utf8");
 for(const text of ["installed-saved-static-runtime-correlation-owner-hash-no-rerun-passed","Saved correlation crossed owning sessions","saved-evidence-read","verifiedExecutionPath"])assert.ok(driver.includes(text),text);
});


test("evidence exhaustion fails acceptance without gating owned native cleanup", async () => {
 let terminated = false, disconnected = false;
 assert.throws(() => assertInstalledActionSequence(INSTALLED_ACTION_LIMIT + 1), /evidence budget reached/);
 await stopOwnedApplication(async () => { terminated = true; }, async () => { disconnected = true; });
 assert.equal(terminated, true); assert.equal(disconnected, true);
 const driver = readFileSync(new URL("../apps/vscode/scripts/desktop-installed-acceptance.ts", import.meta.url), "utf8");
 const cleanup = driver.slice(driver.indexOf("async function stop()"), driver.indexOf("async function stop()") + 1000);
 assert.ok(cleanup.includes("stopOwnedApplication("));
 assert.ok(!cleanup.includes("acceptanceAction("));
});


test("owned tree stop accepts native race errors only with identity-absence proof", () => {
 const receipt={schema:"cline-owned-tree-stop/v1",confirmed:true,taskkillExitCode:128,observedIdentities:4,remainingIdentities:0};
 verifyOwnedTreeStopReceipt(receipt);
 verifyOwnedTreeStopReceipt({...receipt,taskkillExitCode:0});
 for(const bad of [null,{}, {...receipt,confirmed:false}, {...receipt,remainingIdentities:1},
  {...receipt,observedIdentities:0},{...receipt,observedIdentities:257},
  {...receipt,taskkillExitCode:null}]) assert.throws(()=>verifyOwnedTreeStopReceipt(bad),/receipt/);
 assert.equal((OWNED_WINDOWS_TREE_STOP.match(/& \$taskkill \/PID/g)||[]).length,1);
 for(const text of ["Get-CimInstance Win32_Process -ErrorAction Stop", "CreationDate -eq $previous.CreationDate",
  "Owned root identity unavailable", "Owned tree identity budget exceeded", "$attempt -lt 20"])
  assert.ok(OWNED_WINDOWS_TREE_STOP.includes(text),text);
});

test("Windows owned tree cleanup confirms an actual Node root and child exited", {skip:process.platform!=="win32",timeout:45000}, async () => {
 const root=startAcceptanceProcess(process.execPath,["-e",
  'const {spawn}=require("node:child_process");const c=spawn(process.execPath,["-e","setInterval(()=>{},1000)"],{stdio:"ignore"});console.log(c.pid);setInterval(()=>{},1000);'],process.cwd(),process.env);
 try {
  await withInstalledActionDeadline("owned-test-child-ready",async()=>{
   while(!/^\d+\s*$/.test(root.diagnostics.stdoutTail)) await new Promise(r=>setTimeout(r,25));
  },10000);
  await stopOwnedWindowsTree(root.child.pid,process.cwd(),process.env);
  await withInstalledActionDeadline("owned-test-root-exit",()=>root.exited,5000);
  assert.notEqual(root.child.exitCode,null);
 } finally { if(root.child.exitCode===null && root.child.pid) await stopOwnedWindowsTree(root.child.pid,process.cwd(),process.env); }
});

test("saved-session navigation exits Settings before looking for a hidden session", async () => {
 const calls=[];let settings=true;
 const page={getByRole(role,options){
  assert.equal(role,"button");
  if(options.name==="Cline home")return {async click(){
   assert.equal(options.exact,true);calls.push("home");settings=false;
  }};
  assert.equal(settings,false,"session list is absent in Settings");
  assert.equal(String(options.name),String(/Installer owned session/));
  return {first(){return {async click(){calls.push("saved-session");}}}};
 }};
 await openInstalledSavedSession(page,/Installer owned session/);
 assert.deepEqual(calls,["home","saved-session"]);
 const failure=new Error("Home navigation failed");let lookups=0;
 await assert.rejects(openInstalledSavedSession({getByRole(){lookups++;return {async click(){throw failure;}};}},/owned/),error=>error===failure);
 assert.equal(lookups,1,"a failed navigation must not fall back to an RPC or force click");
 const driver=readFileSync(new URL("../apps/vscode/scripts/desktop-installed-acceptance.ts",import.meta.url),"utf8");
 assert.equal(driver.split("await openInstalledSavedSession(page, /Installer owned session/);").length-1,2);
});
