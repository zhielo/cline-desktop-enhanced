import { it, expect, vi } from "vitest";
import { mkdtemp, writeFile, rm, mkdir, symlink } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { AnalysisWorkflowStore, confinedArtifact } from "./analysis-workflow-store";
import {
	handleAnalysisWorkflow,
	featureTrace,
	buildEvidenceBundle,
} from "./analysis-workflow";
it("immutable artifact handles reject mutations and cross-session reads", async () => {
	const root = await mkdtemp(join(tmpdir(), "workflow-owned-"));
	await mkdir(join(root, "workspace"));
	const scope = { sessionId: "owned", workspace: join(root, "workspace") },
		store = new AnalysisWorkflowStore(join(root, "store.sqlite"));
	try {
		await writeFile(join(scope.workspace, "owned.exe"), "owned");
		const h = await store.open(scope, "owned.exe");
		expect((await store.verify(scope, h.id)).sha256).toBe(h.sha256);
		expect(() =>
			store.get({ ...scope, sessionId: "other" }, h.id, "artifact"),
		).toThrow("unavailable");
		await writeFile(join(scope.workspace, "owned.exe"), "changed");
		await expect(store.verify(scope, h.id)).rejects.toThrow("changed");
		await expect(store.open(scope, "../store.sqlite")).rejects.toThrow(
			"confined",
		);
	} finally {
		store.close();
		await rm(root, { recursive: true, force: true });
	}
});
it("confines native plan paths through workspace aliases while rejecting escapes", async () => {
	const root = await mkdtemp(join(tmpdir(), "workflow-alias-"));
	const owned = join(root, "owned");
	const alias = join(root, "owned-alias");
	const outside = join(root, "outside");
	await mkdir(owned);
	await mkdir(outside);
	await writeFile(join(owned, "owned.js"), "owned");
	await writeFile(join(outside, "outside.js"), "outside");
	await symlink(
		owned,
		alias,
		process.platform === "win32" ? "junction" : "dir",
	);
	await symlink(
		outside,
		join(owned, "escape"),
		process.platform === "win32" ? "junction" : "dir",
	);
	try {
		const nativeFile = realpathSync.native(join(owned, "owned.js"));
		expect((await confinedArtifact(alias, nativeFile)).path).toBe(nativeFile);
		await expect(
			confinedArtifact(alias, join(owned, "escape", "outside.js")),
		).rejects.toThrow("confined");
		await expect(
			confinedArtifact(alias, join(outside, "outside.js")),
		).rejects.toThrow("confined");
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
it("workflow does not bypass mode, trusted connection or one-use approvals", async () => {
	const invoke = vi.fn(),
		store = {
			verify: vi.fn(async () => ({ path: "/owned" })),
		} as unknown as AnalysisWorkflowStore;
	const ports = {
		invoke,
		staticReceipt: vi.fn(),
		taskBundle: vi.fn(),
		capture: vi.fn(),
	};
	const scope = { sessionId: "s", workspace: "/owned" };
	await expect(
		handleAnalysisWorkflow(
			"open_binary",
			{},
			scope,
			{ trusted: false, idle: true, mode: "static" },
			store,
			ports,
		),
	).rejects.toThrow("trusted");
	const input = {
		artifactId: "11111111-1111-4111-8111-111111111111",
		engine: "ghidra",
		selector: { symbol: "owned" },
		phase: "run",
	};
	await expect(
		handleAnalysisWorkflow(
			"analyze_function",
			input,
			scope,
			{ trusted: true, idle: true, mode: "static" },
			store,
			ports,
		),
	).rejects.toThrow("approved");
	expect(invoke).not.toHaveBeenCalled();
});
it("feature matching remains explicitly partial, never proof of a call chain", () => {
	expect(
		featureTrace(
			"owned",
			{ result: { facts: [{ kind: "call", value: "owned" }] } },
			[],
		),
	).toMatchObject({
		status: "partial",
		staticCandidates: [{ classification: "statically-inferred" }],
	});
	expect(featureTrace("absent", {}, []).status).toBe("unresolved");
});
it("export is selected, bounded and credential-filtered, not a settings backup", () => {
	const b = buildEvidenceBundle({ sessionId: "s", workspace: "/owned" }, [
		{
			authorization: "Bearer secret",
			executionToken: "private",
			note: "api_key=hidden",
		},
	]);
	expect(JSON.stringify(b)).not.toContain("Bearer secret");
	expect(JSON.stringify(b)).not.toContain("private");
	expect(b.bundleHash).toMatch(/^[a-f0-9]{64}$/);
	expect(() =>
		buildEvidenceBundle({ sessionId: "s", workspace: "/owned" }, [
			"x".repeat(5 * 1024 * 1024),
		]),
	).toThrow("4 MiB");
});
it("metadata recording may stop after mode changes, but never start while Off or busy", async () => {
	const capture = vi.fn(async () => ({
			purpose: "original",
			metadata: { cleanupVerified: true },
		})),
		put = vi.fn((scope, kind, body) => body);
	const ports = {
		capture,
		invoke: vi.fn(),
		staticReceipt: vi.fn(),
		taskBundle: vi.fn(),
	};
	const store = { put } as unknown as AnalysisWorkflowStore;
	const scope = { sessionId: "s", workspace: "/owned" };
	const req = {
		browserSessionId: "11111111-1111-4111-8111-111111111111",
		confirmRecord: true,
		purpose: "stop",
	};
	await expect(
		handleAnalysisWorkflow(
			"capture_browser_scenario",
			{ ...req, action: "start" },
			scope,
			{ trusted: true, idle: false, mode: "off" },
			store,
			ports,
		),
	).rejects.toThrow("idle Runtime");
	await handleAnalysisWorkflow(
		"capture_browser_scenario",
		{ ...req, action: "stop" },
		scope,
		{ trusted: true, idle: false, mode: "off" },
		store,
		ports,
	);
	expect(put).toHaveBeenCalledWith(
		scope,
		"scenario",
		expect.objectContaining({ purpose: "original" }),
	);
});
it("function analysis preparation and run reuse the existing approval protocol", async () => {
	const invoke = vi.fn(async () => ({ id: "plan" }));
	const store = {
		verify: vi.fn(async () => ({ path: "/owned/target.exe" })),
	} as unknown as AnalysisWorkflowStore;
	const ports = {
		invoke,
		staticReceipt: vi.fn(),
		taskBundle: vi.fn(),
		capture: vi.fn(),
	};
	const scope = { sessionId: "s", workspace: "/owned" };
	const req = {
		artifactId: "11111111-1111-4111-8111-111111111111",
		engine: "ghidra",
		selector: { address: "0x401000" },
	};
	await handleAnalysisWorkflow(
		"analyze_function",
		req,
		scope,
		{ trusted: true, idle: true, mode: "static" },
		store,
		ports,
	);
	expect(invoke).toHaveBeenCalledWith("prepare_analysis_task", {
		kind: "static",
		request: {
			engine: "ghidra",
			operation: "decompile",
			timeout_ms: 120000,
			target: "/owned/target.exe",
			function_selector: { address: "0x401000" },
		},
	});
	await handleAnalysisWorkflow(
		"analyze_function",
		{ ...req, phase: "run", planId: req.artifactId, executionToken: "one-use" },
		scope,
		{ trusted: true, idle: true, mode: "static" },
		store,
		ports,
	);
	expect(invoke).toHaveBeenLastCalledWith(
		"run_static_analysis",
		expect.objectContaining({ executionToken: "one-use" }),
	);
});
it("the real orchestrator accepts the wrapper's exact reviewed request once only",async()=>{
 const {AnalysisTaskOrchestrator}=await import("./analysis-task-orchestrator");const {ReverseEngineeringInputSchema}=await import("@cline/core");
 const root=await mkdtemp(join(tmpdir(),"workflow-plan-"));const scope={sessionId:"s",workspace:root};const store=new AnalysisWorkflowStore(join(root,"workflow.sqlite"));const orchestrator=new AnalysisTaskOrchestrator();
 try {await writeFile(join(root,"owned.exe"),"owned-static-fixture");const artifact=await store.open(scope,"owned.exe");const ports={staticReceipt:vi.fn(),taskBundle:vi.fn(),capture:vi.fn(),invoke:async(command:string,args:Record<string,unknown>)=>{
  const request=ReverseEngineeringInputSchema.parse(command==="prepare_analysis_task"?args.request:args.input);
  if(command==="prepare_analysis_task")return orchestrator.prepare({workspaceRoot:root,kind:"static",request,timeoutMs:120000});
  await orchestrator.consume({workspaceRoot:root,kind:"static",planId:String(args.planId),executionToken:String(args.executionToken),request});return orchestrator.complete(String(args.planId),{owned:true},"owned-fixture-no-engine-execution");
 }};const options={trusted:true,idle:true,mode:"static"};const req={artifactId:artifact.id,engine:"ghidra",selector:{symbol:"owned"}};const plan=await handleAnalysisWorkflow("analyze_function",req,scope,options,store,ports) as {id:string;requestHash:string;requirements:string[]};const approved=orchestrator.approve(plan.id,plan.requirements,plan.requestHash);const run={...req,phase:"run",planId:plan.id,executionToken:approved.executionToken};await handleAnalysisWorkflow("analyze_function",run,scope,options,store,ports);await expect(handleAnalysisWorkflow("analyze_function",run,scope,options,store,ports)).rejects.toThrow();} finally {store.close();await rm(root,{recursive:true,force:true});}
});
it("unknown workflow database versions are refused without overwriting their version",async()=>{const {loadSqliteDb}=await import("@cline/shared/db");const root=await mkdtemp(join(tmpdir(),"workflow-version-"));const file=join(root,"owned.sqlite");const db=loadSqliteDb(file);db.exec("PRAGMA user_version=2");db.close?.();const store=new AnalysisWorkflowStore(file);try{expect(()=>store.list({sessionId:"s",workspace:root},"artifact")).toThrow("Unsupported workflow database version");const check=loadSqliteDb(file);expect(check.prepare("PRAGMA user_version").get()?.user_version).toBe(2);check.close?.();}finally{store.close();await rm(root,{recursive:true,force:true});}});
it("failed receipt persistence returns stopped capture evidence without replay",async()=>{const capture=vi.fn(async()=>({purpose:"owned",status:"partial"}));const store={put:vi.fn(()=>{throw new Error("disk full");})} as unknown as AnalysisWorkflowStore;const result=await handleAnalysisWorkflow("capture_browser_scenario",{action:"stop",browserSessionId:"11111111-1111-4111-8111-111111111111",purpose:"owned",confirmRecord:true},{sessionId:"s",workspace:"/owned"},{trusted:true,idle:true,mode:"runtime"},store,{capture,invoke:vi.fn(),staticReceipt:vi.fn(),taskBundle:vi.fn()});expect(result).toMatchObject({capture:{purpose:"owned"},evidenceWarning:expect.stringContaining("do not replay")});expect(capture).toHaveBeenCalledTimes(1);});

it("redacts derived report fields as well as original selected records",()=>{const bundle=buildEvidenceBundle({sessionId:"owned",workspace:"/owned"},[{providerSnapshot:{result:{evidence:{selectedFunctions:[{name:"api_key=private-derived-secret"}]}}}}]);expect(JSON.stringify(bundle)).not.toContain("private-derived-secret");});
it("Hybrid browser start denies missing static basis or recording consent without capturing",async()=>{
 const capture=vi.fn(),ports={capture,invoke:vi.fn(),staticReceipt:vi.fn(),taskBundle:vi.fn()},scope={sessionId:"s",workspace:"/owned"},store={} as AnalysisWorkflowStore;
 const req={browserSessionId:"11111111-1111-4111-8111-111111111111",action:"start",purpose:"owned question",confirmRecord:true};
 for(const input of [req,{...req,confirmRecord:false}])await expect(handleAnalysisWorkflow("capture_browser_scenario",input,scope,{trusted:true,idle:true,mode:"hybrid"},store,ports)).rejects.toThrow();
 expect(capture).not.toHaveBeenCalled();
});
it("Hybrid preflight is unavailable to untrusted, Off or busy UI callers",async()=>{
 const ports={capture:vi.fn(),invoke:vi.fn(),staticReceipt:vi.fn(),taskBundle:vi.fn()},scope={sessionId:"s",workspace:"/owned"};
 for(const options of [{trusted:false,idle:true,mode:"hybrid"},{trusted:true,idle:true,mode:"off"},{trusted:true,idle:false,mode:"hybrid"}])await expect(handleAnalysisWorkflow("analysis_workflow_hybrid_prepare",{},scope,options,{} as AnalysisWorkflowStore,ports)).rejects.toThrow("trusted enabled");
 expect(ports.capture).not.toHaveBeenCalled();expect(ports.invoke).not.toHaveBeenCalled();
});
it("batch new work requires enabled trusted scope; cleanup remains possible after Off",async()=>{
 const root=await mkdtemp(join(tmpdir(),"batch-mode-")),store=new AnalysisWorkflowStore(join(root,"store.sqlite"));
 const batch=vi.fn(async()=>({status:"owned"}));const ports={invoke:vi.fn(),staticReceipt:vi.fn(),taskBundle:vi.fn(),capture:vi.fn(),batch};const scope={sessionId:"owned",workspace:root};
 try{for(const command of ["plan_batch","preview_batch","run_batch","resume_investigation"]){await expect(handleAnalysisWorkflow(command,{},scope,{trusted:true,idle:true,mode:"off"},store,ports)).rejects.toThrow("Analysis enabled");}for(const command of ["checkpoint_investigation","cancel_batch"]){expect(await handleAnalysisWorkflow(command,{},scope,{trusted:true,idle:false,mode:"off",actor:"model"},store,ports)).toEqual({status:"owned"});await expect(handleAnalysisWorkflow(command,{},scope,{trusted:false,idle:true,mode:"static"},store,ports)).rejects.toThrow("trusted");}}finally{store.close();await rm(root,{recursive:true,force:true});}
});
it.each(["validate_candidate","review_candidate_changes"])("%s binds immutable owning artifact into separately approved request",async(command)=>{
 const root=await mkdtemp(join(tmpdir(),"candidate-workflow-")),scope={sessionId:"owned",workspace:root},store=new AnalysisWorkflowStore(join(root,"workflow.sqlite"));
 const invoke=vi.fn(async()=>({id:"plan"})),ports={invoke,staticReceipt:vi.fn(),taskBundle:vi.fn(),capture:vi.fn()};
 try {
  await writeFile(join(root,"candidate.ts"),"export const owned=1;");const h=await store.open(scope,"candidate.ts");const input={artifactId:h.id,...(command==="validate_candidate"?{kind:"typescript"}:{})};
  await handleAnalysisWorkflow(command,input,scope,{trusted:true,idle:true,mode:"static"},store,ports);
  expect(invoke).toHaveBeenCalledWith("prepare_analysis_task",expect.objectContaining({kind:"static",request:expect.objectContaining({operation:command,target:h.path,...(command==="validate_candidate"?{candidate_validation:{expected_sha256:h.sha256,kind:"typescript"}}:{candidate_review:{manifest_sha256:h.sha256}})})}));
  await expect(handleAnalysisWorkflow(command,{...input,phase:"run"},scope,{trusted:true,idle:true,mode:"static"},store,ports)).rejects.toThrow("one-use");
  await expect(handleAnalysisWorkflow(command,input,{...scope,sessionId:"other"},{trusted:true,idle:true,mode:"static"},store,ports)).rejects.toThrow("unavailable");
  await expect(handleAnalysisWorkflow(command,input,scope,{trusted:true,idle:true,mode:"off"},store,ports)).rejects.toThrow("Analysis enabled");
  await expect(handleAnalysisWorkflow(command,input,scope,{trusted:false,idle:true,mode:"static"},store,ports)).rejects.toThrow("trusted");
  await writeFile(h.path,"changed");await expect(handleAnalysisWorkflow(command,input,scope,{trusted:true,idle:true,mode:"static"},store,ports)).rejects.toThrow("changed");
 } finally {store.close();await rm(root,{recursive:true,force:true});}
});
it("runtime planner binds owning immutable source but never invokes runtime from Static mode",async()=>{
 const root=await mkdtemp(join(tmpdir(),"runtime-plan-workflow-")),scope={sessionId:"owned",workspace:root},store=new AnalysisWorkflowStore(join(root,"workflow.sqlite"));
 const invoke=vi.fn(async()=>({id:"plan"})),ports={invoke,staticReceipt:vi.fn(),taskBundle:vi.fn(),capture:vi.fn()};
 try{
  await writeFile(join(root,"owned.js"),"throw new Error('MUST_NOT_EXECUTE');");const h=await store.open(scope,"owned.js");
  const input={artifactId:h.id,observation:{backend:"node-inspector",pid:123,processToken:"owned",endpoint:"ws://127.0.0.1:9229/00000000-0000-0000-0000-000000000000"}};
  await handleAnalysisWorkflow("plan_runtime_observation",input,scope,{trusted:true,idle:true,mode:"static"},store,ports);
  expect(invoke).toHaveBeenCalledWith("prepare_analysis_task",expect.objectContaining({kind:"static",request:expect.objectContaining({operation:"plan_runtime_observation",target:h.path,runtime_observation_plan:expect.objectContaining({expected_sha256:h.sha256})})}));
  await expect(handleAnalysisWorkflow("plan_runtime_observation",{...input,phase:"run"},scope,{trusted:true,idle:true,mode:"static"},store,ports)).rejects.toThrow("one-use");
  await expect(handleAnalysisWorkflow("plan_runtime_observation",input,{...scope,sessionId:"other"},{trusted:true,idle:true,mode:"static"},store,ports)).rejects.toThrow("unavailable");
  expect(ports.capture).not.toHaveBeenCalled();
 }finally{store.close();await rm(root,{recursive:true,force:true});}
});

it.each(["capture_process_tree","capture_file_activity"] as const)("%s cannot run in Static or cross artifact owners",async(command)=>{
 const root=await mkdtemp(join(tmpdir(),"runtime-workflow-")),scope={sessionId:"owned",workspace:root},store=new AnalysisWorkflowStore(join(root,"store.sqlite"));
 const runtimeCapture=vi.fn(async()=>({status:"prepared"})),ports={invoke:vi.fn(),staticReceipt:vi.fn(),taskBundle:vi.fn(),capture:vi.fn(),runtimeCapture};
 try{
  await writeFile(join(root,"owned.js"),"owned");const artifact=await store.open(scope,"owned.js");
  const input={artifactId:artifact.id,...(command==="capture_process_tree"?{pid:process.pid}:{durationMs:200})};
  await expect(handleAnalysisWorkflow(command,input,scope,{trusted:true,idle:true,mode:"static"},store,ports)).rejects.toThrow("Runtime or Hybrid");
  expect(runtimeCapture).not.toHaveBeenCalled();
  await handleAnalysisWorkflow(command,input,scope,{trusted:true,idle:true,mode:"runtime"},store,ports);
  expect(runtimeCapture).toHaveBeenCalledWith(command,expect.objectContaining({phase:"prepare",request:expect.objectContaining({target:artifact.path,expected_sha256:artifact.sha256})}));
  await expect(handleAnalysisWorkflow(command,input,{...scope,sessionId:"other"},{trusted:true,idle:true,mode:"runtime"},store,ports)).rejects.toThrow("unavailable");
  await expect(handleAnalysisWorkflow(command,{...input,confirmRecord:true},scope,{trusted:true,idle:true,mode:"runtime"},store,ports)).rejects.toThrow();
 }finally{store.close();await rm(root,{recursive:true,force:true});}
});
