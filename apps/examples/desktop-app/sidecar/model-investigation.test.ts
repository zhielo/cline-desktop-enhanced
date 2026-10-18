import { it, expect, vi } from "vitest";
import {
	runModelInvestigation,
	type ModelInvestigationPorts,
} from "./model-investigation";
const id = "11111111-1111-4111-8111-111111111111";
const req = { artifactId: id, engine: "ghidra", selector: { symbol: "owned" } };
function ports(): ModelInvestigationPorts {
	return {
		invoke: vi.fn(async (_name, input) =>
			input.phase === "prepare"
				? { id, requestHash: "hash", requirements: ["inspect"] }
				: { executionToken: "must-not-leak", result: "owned" },
		),
		review: vi.fn(async () => true),
		approve: vi.fn(() => ({ executionToken: "private-one-use" })),
		cancel: vi.fn(),
		assertCurrent: vi.fn(),
	};
}
it("independent human review precedes token issuance, consumption and redacted result", async () => {
	const p = ports();
	const result = await runModelInvestigation("analyze_function", req, p);
	expect(p.review).toHaveBeenCalledWith(
		expect.objectContaining({
			independentAnalysisApproval: true,
			plan: expect.objectContaining({ requestHash: "hash" }),
		}),
	);
	expect(p.approve).toHaveBeenCalledTimes(1);
	expect(p.invoke).toHaveBeenLastCalledWith(
		"analyze_function",
		expect.objectContaining({
			phase: "run",
			executionToken: "private-one-use",
		}),
	);
	expect(result).not.toContain("must-not-leak");
	expect(result).not.toContain("private-one-use");
	expect(p.cancel).not.toHaveBeenCalled();
});
it.each([
	"executionToken",
	"confirmRecord",
	"sessionId",
	"workspace",
	"mode",
	"phase",
])("rejects model supplied authority: %s", async (key) => {
	const p = ports();
	await expect(
		runModelInvestigation("analyze_function", { ...req, [key]: "fake" }, p),
	).rejects.toThrow();
	expect(p.invoke).not.toHaveBeenCalled();
});
it("denial cancels plan and never issues a token", async () => {
	const p = ports();
	p.review = vi.fn(async () => false);
	await expect(
		runModelInvestigation("analyze_function", req, p),
	).rejects.toThrow("denied");
	expect(p.approve).not.toHaveBeenCalled();
	expect(p.invoke).toHaveBeenCalledTimes(1);
	expect(p.cancel).toHaveBeenCalledWith(id);
});
it("mode change while reviewing invalidates approval", async () => {
	const p = ports();
	let changed = false;
	p.assertCurrent = () => {
		if (changed) throw new Error("mode changed");
	};
	p.review = async () => {
		changed = true;
		return true;
	};
	await expect(
		runModelInvestigation("analyze_function", req, p),
	).rejects.toThrow("mode changed");
	expect(p.approve).not.toHaveBeenCalled();
	expect(p.cancel).toHaveBeenCalledWith(id);
});
it("abort during execution cancels underlying plan, never retries", async () => {
	const p = ports(),
		controller = new AbortController();
	p.signal = controller.signal;
	p.invoke = vi.fn(async (_name, input) => {
		if (input.phase === "prepare")
			return { id, requestHash: "h", requirements: [] };
		controller.abort();
		throw new Error("aborted");
	});
	await expect(
		runModelInvestigation("analyze_function", req, p),
	).rejects.toThrow("aborted");
	expect(p.cancel).toHaveBeenCalledWith(id);
	expect(p.invoke).toHaveBeenCalledTimes(2);
});
it("recording cannot self-consent and start always requests human approval", async () => {
	const p = ports();
	p.review = vi.fn(async () => false);
	await expect(
		runModelInvestigation(
			"capture_browser_scenario",
			{ action: "start", browserSessionId: id, purpose: "owned" },
			p,
		),
	).rejects.toThrow("consent");
	expect(p.invoke).not.toHaveBeenCalled();
	await expect(
		runModelInvestigation(
			"capture_browser_scenario",
			{
				action: "start",
				browserSessionId: id,
				purpose: "owned",
				confirmRecord: true,
			},
			p,
		),
	).rejects.toThrow();
});
it("stop remains cleanup without a fresh start consent; list never starts recording", async () => {
	const p = ports();
	await runModelInvestigation(
		"capture_browser_scenario",
		{ action: "stop", browserSessionId: id, purpose: "cleanup" },
		p,
	);
	expect(p.review).not.toHaveBeenCalled();
	expect(p.invoke).toHaveBeenCalledWith(
		"capture_browser_scenario",
		expect.objectContaining({ action: "stop", confirmRecord: true }),
	);
	p.invoke = vi.fn(async () => ({ browsers: [{ id }] }));
	expect(
		JSON.parse(
			await runModelInvestigation(
				"capture_browser_scenario",
				{ action: "list" },
				p,
			),
		),
	).toEqual({ browsers: [{ id }] });
	expect(p.invoke).toHaveBeenLastCalledWith("analysis_workflow_status", {});
});

it("network metadata alias recording cannot self-consent and start always requests human approval", async () => {
	const p = ports();
	p.review = vi.fn(async () => false);
	await expect(
		runModelInvestigation(
			"capture_network_metadata",
			{ action: "start", browserSessionId: id, purpose: "owned" },
			p,
		),
	).rejects.toThrow("consent");
	expect(p.invoke).not.toHaveBeenCalled();
	await expect(
		runModelInvestigation(
			"capture_network_metadata",
			{
				action: "start",
				browserSessionId: id,
				purpose: "owned",
				confirmRecord: true,
			},
			p,
		),
	).rejects.toThrow();
});
it("network metadata alias stop remains cleanup without a fresh start consent; list never starts recording", async () => {
	const p = ports();
	await runModelInvestigation(
		"capture_network_metadata",
		{ action: "stop", browserSessionId: id, purpose: "cleanup" },
		p,
	);
	expect(p.review).not.toHaveBeenCalled();
	expect(p.invoke).toHaveBeenCalledWith(
		"capture_network_metadata",
		expect.objectContaining({ action: "stop", confirmRecord: true }),
	);
	p.invoke = vi.fn(async () => ({ browsers: [{ id }] }));
	expect(
		JSON.parse(
			await runModelInvestigation(
				"capture_network_metadata",
				{ action: "list" },
				p,
			),
		),
	).toEqual({ browsers: [{ id }] });
	expect(p.invoke).toHaveBeenLastCalledWith("analysis_workflow_status", {});
});

it("a failed execution keeps its original failure when the host reports a terminal plan", async () => {
	const p = ports();
	p.invoke = vi.fn(async (_name, input) => {
		if (input.phase === "prepare")
			return { id, requestHash: "h", requirements: [] };
		throw new Error("engine failed");
	});
	await expect(
		runModelInvestigation("analyze_function", req, p),
	).rejects.toThrow("engine failed");
	expect(p.cancel).toHaveBeenCalledTimes(1);
});
it("surfaces unconfirmed cancellation rather than claiming cleanup succeeded", async () => {
	const p = ports();
	p.review = async () => false;
	p.cancel = () => {
		throw new Error("ledger unavailable");
	};
	await expect(
		runModelInvestigation("analyze_function", req, p),
	).rejects.toThrow("cancellation could not be confirmed");
});
it("Hybrid preflight precedes fresh consent; denial never captures", async () => {
	const p = ports();
	p.mode = "hybrid";
	p.invoke = vi.fn(async () => ({ evidenceHash: "a".repeat(64) }));
	p.review = vi.fn(async () => false);
	const proposal = {
		baselineKind: "receipt",
		baselineId: id,
		question: "Which event occurs?",
	};
	await expect(
		runModelInvestigation(
			"capture_browser_scenario",
			{
				action: "start",
				browserSessionId: id,
				purpose: "owned",
				hybridProposal: proposal,
			},
			p,
		),
	).rejects.toThrow("denied");
	expect(p.invoke).toHaveBeenCalledTimes(1);
	expect(p.invoke).toHaveBeenCalledWith(
		"analysis_workflow_hybrid_prepare",
		proposal,
	);
	expect(p.review).toHaveBeenCalledWith(
		expect.objectContaining({
			hybrid: { evidenceHash: "a".repeat(64) },
			independentRecordingConsent: true,
		}),
	);
});
it("missing Hybrid evidence never reaches consent; stopping remains cleanup", async () => {
	const p = ports();
	p.mode = "hybrid";
	p.invoke = vi.fn(async (name) => {
		if (name === "analysis_workflow_hybrid_prepare")
			throw new Error("missing static basis");
		return { stopped: true };
	});
	await expect(
		runModelInvestigation(
			"capture_browser_scenario",
			{ action: "start", browserSessionId: id, purpose: "owned" },
			p,
		),
	).rejects.toThrow("missing static basis");
	expect(p.review).not.toHaveBeenCalled();
	await runModelInvestigation(
		"capture_browser_scenario",
		{ action: "stop", browserSessionId: id, purpose: "stop" },
		p,
	);
	expect(p.invoke).toHaveBeenLastCalledWith(
		"capture_browser_scenario",
		expect.objectContaining({ action: "stop" }),
	);
});

it("network metadata alias Hybrid preflight precedes fresh consent; denial never captures", async () => {
	const p = ports();
	p.mode = "hybrid";
	p.invoke = vi.fn(async () => ({ evidenceHash: "a".repeat(64) }));
	p.review = vi.fn(async () => false);
	const proposal = {
		baselineKind: "receipt",
		baselineId: id,
		question: "Which event occurs?",
	};
	await expect(
		runModelInvestigation(
			"capture_network_metadata",
			{
				action: "start",
				browserSessionId: id,
				purpose: "owned",
				hybridProposal: proposal,
			},
			p,
		),
	).rejects.toThrow("denied");
	expect(p.invoke).toHaveBeenCalledTimes(1);
	expect(p.invoke).toHaveBeenCalledWith(
		"analysis_workflow_hybrid_prepare",
		proposal,
	);
	expect(p.review).toHaveBeenCalledWith(
		expect.objectContaining({
			hybrid: { evidenceHash: "a".repeat(64) },
			independentRecordingConsent: true,
		}),
	);
});
it("network metadata alias missing Hybrid evidence never reaches consent; stopping remains cleanup", async () => {
	const p = ports();
	p.mode = "hybrid";
	p.invoke = vi.fn(async (name) => {
		if (name === "analysis_workflow_hybrid_prepare")
			throw new Error("missing static basis");
		return { stopped: true };
	});
	await expect(
		runModelInvestigation(
			"capture_network_metadata",
			{ action: "start", browserSessionId: id, purpose: "owned" },
			p,
		),
	).rejects.toThrow("missing static basis");
	expect(p.review).not.toHaveBeenCalled();
	await runModelInvestigation(
		"capture_network_metadata",
		{ action: "stop", browserSessionId: id, purpose: "stop" },
		p,
	);
	expect(p.invoke).toHaveBeenLastCalledWith(
		"capture_network_metadata",
		expect.objectContaining({ action: "stop" }),
	);
});
it.each(["run_batch","resume_investigation"] as const)("%s uses independent review and keeps the token private",async(name)=>{
 const p=ports();const input=name==="run_batch"?{operation_id:id,title:"Owned",stages:[{id:"a",request:{operation:"inspect",target:"owned.bin"}}]}:{receiptId:id,revision:3};
 const result=await runModelInvestigation(name,input,p);expect(p.review).toHaveBeenCalledBefore(p.approve as ReturnType<typeof vi.fn>);expect(p.approve).toHaveBeenCalledOnce();expect(p.invoke).toHaveBeenLastCalledWith(name,expect.objectContaining({phase:"run",executionToken:"private-one-use"}));expect(result).not.toContain("must-not-leak");
});
it.each(["run_batch","resume_investigation"] as const)("%s denial cancels prepared work without execution",async name=>{
 const p=ports();p.review=vi.fn(async()=>false);const input=name==="run_batch"?{operation_id:id,title:"Owned",stages:[{id:"a",request:{operation:"inspect",target:"owned.bin"}}]}:{receiptId:id,revision:1};await expect(runModelInvestigation(name,input,p)).rejects.toThrow("denied");expect(p.approve).not.toHaveBeenCalled();expect(p.invoke).toHaveBeenCalledOnce();expect(p.cancel).toHaveBeenCalledWith(id);
});
it.each([
 ["validate_candidate",{artifactId:id,kind:"typescript"}],
 ["review_candidate_changes",{artifactId:id}],
] as const)("%s requires independent approval and private tokens",async(name,input)=>{
 const p=ports();await runModelInvestigation(name,input,p);
 expect(p.review).toHaveBeenCalledWith(expect.objectContaining({operation:name,independentAnalysisApproval:true}));
 expect(p.invoke).toHaveBeenLastCalledWith(name,expect.objectContaining({phase:"run",executionToken:"private-one-use"}));
 const denied=ports();denied.review=vi.fn(async()=>false);await expect(runModelInvestigation(name,input,denied)).rejects.toThrow("denied");expect(denied.approve).not.toHaveBeenCalled();expect(denied.cancel).toHaveBeenCalledWith(id);
});
it("runtime planning requires independent review but never requests or self-grants runtime consent",async()=>{
 const p=ports(),input={artifactId:id,observation:{backend:"node-inspector",pid:123,processToken:"owned",endpoint:"ws://127.0.0.1:9229/00000000-0000-0000-0000-000000000000"}};
 await runModelInvestigation("plan_runtime_observation",input,p);
 expect(p.review).toHaveBeenCalledTimes(1);expect(p.approve).toHaveBeenCalledTimes(1);
 expect(p.invoke).toHaveBeenCalledWith("plan_runtime_observation",expect.objectContaining({phase:"run",executionToken:"private-one-use"}));
 p.review=vi.fn(async()=>false);p.approve=vi.fn();
 await expect(runModelInvestigation("plan_runtime_observation",input,p)).rejects.toThrow("denied");expect(p.approve).not.toHaveBeenCalled();
});

it.each([
 ["capture_process_tree",{artifactId:id,pid:123}],
 ["capture_file_activity",{artifactId:id,durationMs:200,maxEvents:2}],
] as const)("%s requires independent runtime metadata approval with private tokens",async(name,input)=>{
 const p=ports();await runModelInvestigation(name,input,p);
 expect(p.review).toHaveBeenCalledWith(expect.objectContaining({operation:name,independentAnalysisApproval:true}));
 expect(p.invoke).toHaveBeenLastCalledWith(name,expect.objectContaining({phase:"run",executionToken:"private-one-use"}));
 const denied=ports();denied.review=vi.fn(async()=>false);await expect(runModelInvestigation(name,input,denied)).rejects.toThrow("denied");expect(denied.approve).not.toHaveBeenCalled();expect(denied.cancel).toHaveBeenCalledWith(id);
});
it.each([
 ["attach_debug_session",{artifactId:id,pid:123,endpoint:"ws://127.0.0.1:9229/11111111-1111-4111-8111-111111111111"}],
 ["set_scoped_breakpoints",{runtimeSessionId:id,locations:[{line:2}]}],
 ["capture_execution_trace",{runtimeSessionId:id,durationMs:200}],
] as const)("%s requires fresh human approval and does not expose tokens",async(name,input)=>{
 const p=ports();p.review=vi.fn(async()=>false);
 await expect(runModelInvestigation(name,input,p)).rejects.toThrow("denied");
 expect(p.approve).not.toHaveBeenCalled();expect(p.invoke).toHaveBeenCalledTimes(1);
 const ok=ports(),result=await runModelInvestigation(name,input,ok);
 expect(ok.review).toHaveBeenCalledOnce();expect(ok.invoke).toHaveBeenCalledTimes(2);
 expect(result).not.toContain("private-one-use");
});
it("managed stop is cleanup without manufacturing a new approval",async()=>{
 const p=ports();await runModelInvestigation("stop_runtime_session",{runtimeSessionId:id},p);
 expect(p.review).not.toHaveBeenCalled();expect(p.approve).not.toHaveBeenCalled();expect(p.invoke).toHaveBeenCalledOnce();
});
