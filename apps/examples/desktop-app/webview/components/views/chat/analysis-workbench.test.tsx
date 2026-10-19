// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { desktopClient } from "@/lib/desktop-client";
import { AnalysisWorkbench } from "./analysis-workbench";

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	container = document.createElement("div");
	document.body.appendChild(container);
	root = createRoot(container);
});

afterEach(async () => {
	await act(async () => root.unmount());
	container.remove();
	vi.restoreAllMocks();
});

async function clickText(text: string) {
	const button = [...container.querySelectorAll("button")].find((candidate) =>
		candidate.textContent?.includes(text),
	);
	expect(button).toBeDefined();
	await act(async () => {
		button?.dispatchEvent(new MouseEvent("click", { bubbles: true }));
		await Promise.resolve();
	});
}

async function setInput(input: HTMLInputElement, value: string) {
	await act(async () => {
		const setter = Object.getOwnPropertyDescriptor(
			HTMLInputElement.prototype,
			"value",
		)?.set;
		setter?.call(input, value);
		input.dispatchEvent(new Event("input", { bubbles: true }));
	});
}

describe("AnalysisWorkbench approval flow", () => {
	it("prepares and executes the exact reviewed request envelope", async () => {
		const reviewedRequest = {
			engine: "auto",
			operation: "inspect",
			target: "C:\\work\\project\\sample.exe",
			reuse_analysis: true,
			report_format: "json",
			timeout_ms: 120_000,
		};
		const invoke = vi
			.spyOn(desktopClient, "invoke")
			.mockImplementation(async (command: string, args?: unknown) => {
				if (command === "discover_analysis_tools") return {};
				if (command === "list_analysis_tasks") return [];
				if (command === "get_analysis_diagnostics") return {};
				if (command === "prepare_analysis_task") {
					return {
						id: "plan-1",
						kind: "static",
						operation: "inspect",
						target: reviewedRequest.target,
						request: reviewedRequest,
						requestHash: "a".repeat(64),
						permission: "Inspect",
						status: "awaiting-approval",
						requirements: [],
						risk: "low",
						budget: {},
						createdAt: new Date().toISOString(),
						expiresAt: new Date(Date.now() + 60_000).toISOString(),
					};
				}
				if (command === "approve_analysis_task") {
					return { executionToken: "one-time-token" };
				}
				if (command === "run_static_analysis") {
					return { result: { ok: true } };
				}
				throw new Error(
					`Unexpected command: ${command} ${JSON.stringify(args)}`,
				);
			});

		await act(async () => {
			root.render(
				<AnalysisWorkbench cwd={"C:\\work\\project"} environmentId="local" />,
			);
			await Promise.resolve();
		});
		const target = container.querySelector(
			'input[placeholder="Workspace-relative or absolute path"]',
		) as HTMLInputElement;
		await setInput(target, "sample.exe");
		await clickText("Prepare static-analysis task");
		expect(invoke).toHaveBeenCalledWith(
			"prepare_analysis_task",
			expect.objectContaining({
				kind: "static",
				request: expect.objectContaining({
					operation: "inspect",
					target: "sample.exe",
					timeout_ms: 120_000,
				}),
			}),
		);
		await clickText("Approve exact plan and run");
		expect(invoke).toHaveBeenCalledWith("approve_analysis_task", {
			environmentId: "local",
			cwd: "C:\\work\\project",
			planId: "plan-1",
			requirements: [],
			requestHash: "a".repeat(64),
		});
		expect(invoke).toHaveBeenCalledWith(
			"run_static_analysis",
			expect.objectContaining({
				planId: "plan-1",
				executionToken: "one-time-token",
				input: reviewedRequest,
			}),
		);
	});
});

it("offers bounded Android investigations through the existing approval flow", async () => {
	const invoke = vi
		.spyOn(desktopClient, "invoke")
		.mockImplementation(async (command: string, args?: unknown) => {
			if (command === "list_analysis_tasks") return [];
			if (command === "prepare_analysis_task")
				return {
					id: "android-plan",
					kind: "static",
					operation: "advanced_analysis",
					target: "C:\\work\\sample.apk",
					request: (args as { request: unknown }).request,
					requestHash: "a".repeat(64),
					permission: "Inspect",
					status: "awaiting-approval",
					requirements: [],
					risk: "low",
					budget: {},
					createdAt: new Date().toISOString(),
					expiresAt: new Date(Date.now() + 60000).toISOString(),
				};
			return {};
		});
	await act(async () => {
		root.render(<AnalysisWorkbench cwd={"C:\\work"} environmentId="local" />);
		await Promise.resolve();
	});
	const operation = [...container.querySelectorAll("select")].find((select) =>
		[...select.options].some((option) => option.value === "advanced_analysis"),
	)!;
	await act(async () => {
		operation.value = "advanced_analysis";
		operation.dispatchEvent(new Event("change", { bubbles: true }));
	});
	const advanced = container.querySelector(
		'select[aria-label="Advanced function"]',
	) as HTMLSelectElement;
	for (const action of [
		"artifact_discovery",
		"android_relationships",
		"android_method",
		"android_method_code",
		"native_function",
		"analysis_readiness",
		"investigation_graph",
		"investigation_query",
	])
		expect(
			[...advanced.options].some((option) => option.value === action),
		).toBe(true);
	await act(async () => {
		advanced.value = "artifact_discovery";
		advanced.dispatchEvent(new Event("change", { bubbles: true }));
	});
	const target = container.querySelector(
		'input[placeholder="Workspace-relative or absolute path"]',
	) as HTMLInputElement;
	await setInput(target, "sample.apk");
	expect(container.textContent).toContain("not verified runtime relationships");
	await clickText("Prepare static-analysis task");
	expect(invoke).toHaveBeenCalledWith(
		"prepare_analysis_task",
		expect.objectContaining({
			kind: "static",
			request: expect.objectContaining({
				advanced_action: "artifact_discovery",
				operation: "advanced_analysis",
				target: "sample.apk",
			}),
		}),
	);
	expect(
		invoke.mock.calls.some(([command]) => command === "run_static_analysis"),
	).toBe(false);
});

it("keeps exact decompiler selectors in the approval request and rejects envelope overrides", async () => {
	const invoke = vi
		.spyOn(desktopClient, "invoke")
		.mockImplementation(async (command: string) =>
			command === "list_analysis_tasks" ? [] : {},
		);
	await act(async () => {
		root.render(<AnalysisWorkbench cwd={"C:\\work"} environmentId="local" />);
		await Promise.resolve();
	});
	const operation = [...container.querySelectorAll("select")].find((s) =>
		[...s.options].some((o) => o.value === "decompile"),
	)!;
	await act(async () => {
		operation.value = "decompile";
		operation.dispatchEvent(new Event("change", { bubbles: true }));
	});
	const options = container.querySelector(
		'textarea[aria-label="Targeted decompiler options JSON"]',
	) as HTMLTextAreaElement;
	async function value(text: string) {
		await act(async () => {
			Object.getOwnPropertyDescriptor(
				HTMLTextAreaElement.prototype,
				"value",
			)?.set?.call(options, text);
			options.dispatchEvent(new Event("input", { bubbles: true }));
		});
	}
	await setInput(
		container.querySelector(
			'input[placeholder="Workspace-relative or absolute path"]',
		) as HTMLInputElement,
		"owned.so",
	);

	invoke.mockClear();
	await value('{"engine":"ida","executionToken":"override"}');
	await clickText("Prepare static-analysis task");
	expect(
		invoke.mock.calls.some(
			([c]) => c === "prepare_analysis_task" || c === "run_static_analysis",
		),
	).toBe(false);
	await value(
		'{"function_selector":{"address":"0x1000"},"managed_worker":true,"confirm_managed_worker":true}',
	);
	await clickText("Prepare static-analysis task");
	expect(invoke).toHaveBeenCalledWith(
		"prepare_analysis_task",
		expect.objectContaining({
			request: expect.objectContaining({
				operation: "decompile",
				function_selector: { address: "0x1000" },
				managed_worker: true,
				confirm_managed_worker: true,
			}),
		}),
	);
});

it("prepares a native candidate preview without executing or overriding the envelope", async () => {
	const invoke = vi
		.spyOn(desktopClient, "invoke")
		.mockImplementation(async (command: string) =>
			command === "list_analysis_tasks" ? [] : {},
		);
	await act(async () => {
		root.render(<AnalysisWorkbench cwd={"C:\\work"} environmentId="local" />);
		await Promise.resolve();
	});
	const operation = [...container.querySelectorAll("select")].find((s) =>
		[...s.options].some((o) => o.value === "project_edit"),
	)!;
	const engine = [...container.querySelectorAll("select")].find((s) =>
		[...s.options].some((o) => o.value === "ghidra"),
	)!;
	await act(async () => {
		operation.value = "project_edit";
		operation.dispatchEvent(new Event("change", { bubbles: true }));
		engine.value = "ghidra";
		engine.dispatchEvent(new Event("change", { bubbles: true }));
	});
	await setInput(
		container.querySelector(
			'input[placeholder="Workspace-relative or absolute path"]',
		) as HTMLInputElement,
		"owned.so",
	);
	const textarea = container.querySelector(
		'textarea[aria-label="Targeted decompiler options JSON"]',
	) as HTMLTextAreaElement;
	await act(async () => {
		Object.getOwnPropertyDescriptor(
			HTMLTextAreaElement.prototype,
			"value",
		)?.set?.call(
			textarea,
			'{"function_selector":{"address":"0x1000"},"project_edit":{"mode":"preview"}}',
		);
		textarea.dispatchEvent(new Event("input", { bubbles: true }));
	});
	invoke.mockClear();
	await clickText("Prepare static-analysis task");
	expect(invoke).toHaveBeenCalledWith(
		"prepare_analysis_task",
		expect.objectContaining({
			request: expect.objectContaining({
				engine: "ghidra",
				operation: "project_edit",
				project_edit: { mode: "preview" },
				function_selector: { address: "0x1000" },
			}),
		}),
	);
	expect(
		invoke.mock.calls.some(([command]) => command === "run_static_analysis"),
	).toBe(false);
});

it("carries the owning session through advanced candidate preparation, approval and execution", async () => {
 const invoke = vi.spyOn(desktopClient, "invoke").mockImplementation(async (command: string, args?: unknown) => {
  if (["list_analysis_tasks", "binary_triage_history"].includes(command)) return [];
  if (command === "analysis_command_catalog") return { entries: [
   { command: "identify_artifact", effect: "static-analysis", limitations: "Read only" },
   { command: "build_apk", effect: "candidate-write", limitations: "Unsigned candidate" },
  ], unavailable: [] };
  if (command === "prepare_analysis_task") return { id: "owned-build", kind: "static", operation: "build_apk", request: (args as { request: unknown }).request, requestHash: "a".repeat(64), permission: "Modify", status: "awaiting-approval", requirements: [], risk: "low", budget: {}, createdAt: "", expiresAt: "" };
  if (command === "approve_analysis_task") return { executionToken: "owned-token" };
  if (command === "run_static_analysis") return { result: { succeeded: true } };
  return {};
 });
 await act(async () => { root.render(<AnalysisWorkbench sessionId="owning-chat" cwd={"C:\\owned"} environmentId="local" />); });
 await clickText("AI commands");
 await act(async () => {
  const select = container.querySelector('section[aria-label="Advanced AI commands"] select') as HTMLSelectElement;
  select.value = "build_apk"; select.dispatchEvent(new Event("change", { bubbles: true }));
 });
 await act(async () => {
  const textarea = container.querySelector("textarea") as HTMLTextAreaElement;
  Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set?.call(textarea, JSON.stringify({ target: "C:\\owned\\decoded", output_file: "C:\\owned\\candidate.apk", acknowledge_external_output: true }));
  textarea.dispatchEvent(new Event("input", { bubbles: true }));
 });
 await clickText("Prepare advanced command for review");
 await clickText("Approve exact plan and run");
 for (const command of ["prepare_analysis_task", "approve_analysis_task", "run_static_analysis"])
  expect(invoke).toHaveBeenCalledWith(command, expect.objectContaining({ sessionId: "owning-chat", environmentId: "local", cwd: "C:\\owned" }));
});
it.each([undefined, "shared-session"])("shares an artifact in fresh or attached session %s but changes AI JSON only explicitly",async(sessionId)=>{
 const invoke=vi.spyOn(desktopClient,"invoke").mockImplementation(async(command:string)=>{
  if(command==="list_analysis_tasks" || command==="binary_triage_history")return [];
  if(command==="first_party_analysis_status")return {mode:"off",receipts:[],readiness:{}};
  if(command==="analysis_command_catalog")return {entries:[{command:"identify_artifact",route:"static-review",effect:"read",availability:"implemented",limitations:"bounded"}],unavailable:[],limitations:[]};
  return {};
 });
 await act(async()=>root.render(<AnalysisWorkbench cwd="/owned-shared" environmentId="local" sessionId={sessionId}/>));
 const shared=container.querySelector<HTMLInputElement>('input[aria-label="Shared artifact path"]')!;
 await setInput(shared,"/owned-shared/app.apk");
 await clickText("Android tools");expect(container.querySelector<HTMLInputElement>('input[placeholder="app.apk, classes.dex, or decoded-project"]')!.value).toBe("/owned-shared/app.apk");
 await clickText("App analysis");expect(container.querySelector<HTMLInputElement>('input[aria-label="JavaScript analysis target"]')!.value).toBe("/owned-shared/app.apk");
 await clickText("AI commands");const json=container.querySelector<HTMLTextAreaElement>("textarea")!;expect(JSON.parse(json.value).target).toBe("");
 await clickText("Use shared artifact in command JSON");expect(JSON.parse(json.value).target).toBe("/owned-shared/app.apk");
 expect(invoke.mock.calls.some(([c])=>/^(prepare_analysis_task|approve_analysis_task|run_static_analysis|first_party_analysis_inspect|first_party_analysis_run)$/.test(c))).toBe(false);
 await act(async()=>root.render(<AnalysisWorkbench cwd="/other-workspace" environmentId="local"/>));expect(container.querySelector<HTMLInputElement>('input[aria-label="Shared artifact path"]')!.value).toBe("");
});
it("does not carry an in-flight reviewed plan across workspace scopes",async()=>{
 let finish!:(value:unknown)=>void;
 const delayed=new Promise(resolve=>{finish=resolve;});
 const invoke=vi.spyOn(desktopClient,"invoke").mockImplementation(async(command:string)=>{
  if(command==="list_analysis_tasks")return [];
  if(command==="prepare_analysis_task")return delayed;
  return {};
 });
 await act(async()=>root.render(<AnalysisWorkbench cwd="/old-workspace" environmentId="local"/>));
 await setInput(container.querySelector<HTMLInputElement>('input[placeholder="Workspace-relative or absolute path"]')!,"old.bin");
 await clickText("Prepare static-analysis task");
 await act(async()=>root.render(<AnalysisWorkbench cwd="/new-workspace" environmentId="local"/>));
 await act(async()=>finish({id:"stale-plan",kind:"static",operation:"inspect",target:"old.bin",request:{operation:"inspect",target:"old.bin"},requestHash:"a".repeat(64),permission:"Inspect",status:"awaiting-approval",requirements:[],risk:"low",budget:{},createdAt:new Date().toISOString(),expiresAt:new Date(Date.now()+60000).toISOString()}));
 expect(container.textContent).not.toContain("Approve exact plan and run");
 expect(container.querySelector<HTMLInputElement>('input[aria-label="Shared artifact path"]')!.value).toBe("");
 expect(invoke.mock.calls.some(([command])=>command==="approve_analysis_task")).toBe(false);
});
it("navigates from saved evidence to its task target without replay or identity claims",async()=>{
 const saved={id:"saved-evidence",operation:"inspect",target:"/owned/source.exe",status:"completed",requestHash:"a".repeat(64),permission:"Inspect",risk:"low",evidence:{tool:"owned",resultHash:"b".repeat(64),outputPaths:[]}};
 const invoke=vi.spyOn(desktopClient,"invoke").mockImplementation(async(command:string)=>command==="list_analysis_tasks"?[saved]:{});
 await act(async()=>root.render(<AnalysisWorkbench cwd="/evidence-navigation" environmentId="local"/>));
 await clickText("Evidence");
 await act(async()=>container.querySelector<HTMLButtonElement>('button[aria-label="Select target from evidence saved-evidence"]')!.click());
 expect(container.querySelector<HTMLInputElement>('input[aria-label="Shared artifact path"]')!.value).toBe(saved.target);
 expect(container.querySelector<HTMLInputElement>('input[placeholder="Workspace-relative or absolute path"]')!.value).toBe(saved.target);
 expect(container.textContent).toContain(saved.evidence.resultHash);
 expect(invoke.mock.calls.some(([command])=>/^(prepare_analysis_task|approve_analysis_task|run_static_analysis|open_artifact)$/.test(command))).toBe(false);
});


it("confines selection details so long source snapshots cannot push pane controls below the composer", async () => {
 vi.spyOn(desktopClient,"invoke").mockImplementation(async command=> command === "list_analysis_tasks" ? [] : {});
 await act(async()=>root.render(<AnalysisWorkbench cwd="/bounded-layout" environmentId="local"/>));
 const workbench=container.querySelector('[aria-label="Analysis workbench"]');
 expect(workbench?.classList.contains("min-h-0")).toBe(true);
 expect(workbench?.classList.contains("overflow-hidden")).toBe(true);
 const selection=container.querySelector('[aria-label="Analysis selection details"]');
 expect(selection?.classList.contains("max-h-[40%]")).toBe(true);
 expect(selection?.classList.contains("overflow-auto")).toBe(true);
 expect(selection?.querySelector('[aria-label="Shared analysis artifact"]')).not.toBeNull();
});

it("prepares APK verification from a build ID, exposes approval and never automatically runs", async () => {
 const build = { id:"owned-build", kind:"static", operation:"build_android_candidate", status:"completed", request:{output_file:"/work/candidate.apk"}, requestHash:"a".repeat(64), evidence:{tool:"owned-fixture",resultHash:"b".repeat(64),outputPaths:[]}, candidateOutcome:{version:"candidate-outcome/v1",operation:"build_android_candidate",evidence:"bounded-checks-passed",scope:"android-project-build",outputSha256:"c".repeat(64),publication:"new-unsigned-candidate",checks:[],limitations:[]} };
 const request = { engine:"auto",operation:"validate_candidate",target:"/work/candidate.apk",candidate_validation:{kind:"apk",expected_sha256:"c".repeat(64)},timeout_ms:120000 };
 const invoke = vi.spyOn(desktopClient,"invoke").mockImplementation(async(command:string)=>{
  if(command==="list_analysis_tasks") return [build];
  if(command==="prepare_candidate_verification") return { id:"verify-plan",kind:"static",operation:"validate_candidate",status:"awaiting-approval",permission:"Inspect",requirements:[],risk:"low",budget:{},request,requestHash:"d".repeat(64) };
  if(command==="approve_analysis_task") return {executionToken:"new-verification-token"};
  if(command==="run_static_analysis") return {result:{status:"failed",reason:"unsigned candidate"}};
  return {};
 });
 await act(async()=>{root.render(<AnalysisWorkbench cwd="/work" environmentId="local"/>);await Promise.resolve();});
 await clickText("Evidence");
 await clickText("Prepare separate APK verification");
 expect(invoke).toHaveBeenCalledWith("prepare_candidate_verification",{environmentId:"local",cwd:"/work",planId:"owned-build",allowExternalTarget:false});
 expect(invoke.mock.calls.some(([c])=>c==="approve_analysis_task"||c==="run_static_analysis")).toBe(false);
 expect(container.textContent).toContain("Approval boundary");
 expect(container.textContent).toContain("validate_candidate");
 await clickText("Approve exact plan and run");
 expect(invoke).toHaveBeenCalledWith("run_static_analysis",expect.objectContaining({planId:"verify-plan",executionToken:"new-verification-token",input:request}));
});

it("does not offer APK verification from a partial build", async()=>{
 vi.spyOn(desktopClient,"invoke").mockImplementation(async(command:string)=>command==="list_analysis_tasks"?[{id:"partial",operation:"build_android_candidate",status:"completed",request:{},evidence:{tool:"fixture",outputPaths:[]},candidateOutcome:{version:"candidate-outcome/v1",operation:"build_android_candidate",evidence:"partial",scope:"android-project-build",checks:[],limitations:[]}}]:{});
 await act(async()=>{root.render(<AnalysisWorkbench cwd="/work" environmentId="local"/>);await Promise.resolve();});
 await clickText("Evidence");
 expect(container.textContent).not.toContain("Prepare separate APK verification");
});
