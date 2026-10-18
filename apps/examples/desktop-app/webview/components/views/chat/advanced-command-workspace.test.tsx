// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { desktopClient } from "@/lib/desktop-client";
import { AdvancedCommandWorkspace } from "./advanced-command-workspace";

let container: HTMLDivElement;
let root: Root;
const catalog = {
	recommendations: [
		{
			command: "attach_debug_session",
			scope: "not-implemented",
			limitations: "Persistent lifecycle pending",
		},
	],
	entries: [
 {command:"check_release_gate",route:"ai-workflow",effect:"approved-public-network-read",availability:"implemented-bounded",limitations:"Fixed public release policy only"},
 {command:"run_device_smoke_test",route:"ai-workflow",effect:"runtime-execution",availability:"implemented-bounded",limitations:"Owning approved Android workflow only"},
		{
			command: "identify_artifact",
			effect: "static-analysis",
			availability: "adapter",
			limitations: "No execution",
		},
		{
			command: "patch_smali_method",
			effect: "candidate-write",
			availability: "implemented",
			limitations: "Exact-method candidate only",
		},
		...[
			"explain_behavior",
			"trace_android_method",
			"decompile_function_bundle",
			"annotate_analysis_project",
			"verify_hypothesis",
			"compare_public_api",
			"build_android_candidate",
			"preview_batch",
			"patch_binary",
			"apply_ast_transform",
			"patch_dotnet_constant",
			"patch_jvm_constant",
			"apply_candidate_batch",
			"trace_source_sink",
			"audit_candidate_batch",
			"trace_cross_language",
			"trace_data_flow",
			"decompile_dotnet_method",
			"read_jvm_method",
		].map((command) => ({
			command,
			effect: "candidate-write",
			availability: "implemented",
			limitations: "Bounded candidate only",
		})),
	],
	unavailable: ["general_native_rewriting"],
};
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
async function mount(environmentId = "local", onPrepare = vi.fn()) {
	const invoke = vi.spyOn(desktopClient, "invoke").mockResolvedValue(catalog);
	await act(async () => {
		root.render(
			<AdvancedCommandWorkspace
				environmentId={environmentId}
				onPrepare={onPrepare}
			/>,
		);
	});
	return { invoke, onPrepare };
}
async function click() {
	await act(async () => {
		container.querySelector("button")!.click();
	});
}
async function edit(value: string) {
	await act(async () => {
		const textarea = container.querySelector("textarea")!;
		Object.getOwnPropertyDescriptor(
			HTMLTextAreaElement.prototype,
			"value",
		)!.set!.call(textarea, value);
		textarea.dispatchEvent(new Event("input", { bubbles: true }));
	});
}
it("loads only the catalog and grants no approvals or execution on mount", async () => {
	const { invoke, onPrepare } = await mount();
	expect(invoke).toHaveBeenCalledTimes(1);
	expect(invoke).toHaveBeenCalledWith("analysis_command_catalog", {
		environmentId: "local",
	});
	expect(onPrepare).not.toHaveBeenCalled();
	expect(container.textContent).toContain("general_native_rewriting");
});
it("prepares one selected command and ignores operation substitution in JSON", async () => {
	const { onPrepare } = await mount();
	await edit(JSON.stringify({ target: "/owned.apk", operation: "sign_apk" }));
	await click();
	expect(onPrepare).toHaveBeenCalledWith({
		target: "/owned.apk",
		operation: "identify_artifact",
	});
});
it("rejects non-object and malformed JSON", async () => {
	const { onPrepare } = await mount();
	for (const value of ["[]", "null", "bad-json"]) {
		await edit(value);
		await click();
		expect(container.querySelector('[role="alert"]')).not.toBeNull();
	}
	expect(onPrepare).not.toHaveBeenCalled();
});
it("shows hash-bound patch template without running it", async () => {
	const { onPrepare } = await mount();
	await act(async () => {
		const select = container.querySelector("select")!;
		select.value = "patch_smali_method";
		select.dispatchEvent(new Event("change", { bubbles: true }));
	});
	expect(container.querySelector("textarea")!.value).toContain(
		"preview_sha256",
	);
	expect(onPrepare).not.toHaveBeenCalled();
});
it("does not inspect local tools for a remote environment", async () => {
	const { invoke } = await mount("ssh-owned");
	expect(invoke).not.toHaveBeenCalled();
	expect(container.querySelector("button")!.disabled).toBe(true);
});
it("reports failed preparation without running a fallback", async () => {
	const onPrepare = vi.fn().mockRejectedValue(new Error("Permission denied"));
	const { invoke } = await mount("local", onPrepare);
	await click();
	expect(container.textContent).toContain("Permission denied");
	expect(invoke).toHaveBeenCalledTimes(1);
});

it.each([
	["patch_binary", "byte_patch"],
	["apply_ast_transform", "literal"],
	["patch_dotnet_constant", "managed"],
	["patch_jvm_constant", "jvm"],
	["apply_candidate_batch", "batch_preview_sha256"],
	["trace_source_sink", "source_sink"],
	["audit_candidate_batch", "target"],
	["trace_cross_language", "evidence_trace"],
	["trace_data_flow", "evidence_trace"],
	["decompile_dotnet_method", "managed_method"],
	["read_jvm_method", "jvm_method"],
])("prepares %s explicitly without executing on selection", async (command, key) => {
	const { invoke, onPrepare } = await mount();
	await act(async () => {
		const select = container.querySelector("select")!;
		select.value = command;
		select.dispatchEvent(new Event("change", { bubbles: true }));
	});
	const value = JSON.parse(container.querySelector("textarea")!.value);
	expect(JSON.stringify(value)).toContain(key);
	if (value.candidate) expect(value.candidate).toHaveProperty("preview_sha256");
	expect(invoke).toHaveBeenCalledTimes(1);
	expect(onPrepare).not.toHaveBeenCalled();
	await click();
	expect(onPrepare).toHaveBeenCalledWith({ ...value, operation: command });
});

it.each([
	["explain_behavior", "workflow_query"],
	["trace_android_method", "advanced_options"],
	["decompile_function_bundle", "function_selector"],
	["annotate_analysis_project", "project_edit"],
	["verify_hypothesis", "hypothesis"],
	["compare_public_api", "compare_target"],
	["build_android_candidate", "output_file"],
])("prepares %s with its scoped review template, never runs it", async (command, field) => {
	const { onPrepare, invoke } = await mount();
	await act(async () => {
		const select = container.querySelector("select")!;
		select.value = command;
		select.dispatchEvent(new Event("change", { bubbles: true }));
	});
	const request = JSON.parse(container.querySelector("textarea")!.value);
	expect(request).toHaveProperty(field);
	expect(onPrepare).not.toHaveBeenCalled();
	expect(invoke).toHaveBeenCalledTimes(1);
	await click();
	expect(onPrepare).toHaveBeenCalledWith(
		expect.objectContaining({ operation: command, [field]: request[field] }),
	);
	if (command === "annotate_analysis_project")
		expect(request.project_edit).toEqual({ mode: "preview" });
});
it("shows unresolved original recommendations without certifying release", async () => {
	await mount();
	expect(container.textContent).toContain("attach_debug_session");
	expect(container.textContent).toContain("not-implemented");
	expect(container.textContent).toContain("not complete workflow coverage");
});

it("host-only workflows never submit malformed legacy static requests",async()=>{
 const {onPrepare}=await mount();
 for(const command of ["check_release_gate","run_device_smoke_test"]){
  await act(async()=>{const select=container.querySelector("select")!;select.value=command;select.dispatchEvent(new Event("change",{bubbles:true}));});
  expect(container.querySelector("button")!.disabled).toBe(true);expect(container.querySelector("textarea")!.disabled).toBe(true);expect(container.textContent).toContain("owning AI investigation workflow");await click();expect(onPrepare).not.toHaveBeenCalled();
 }
});
