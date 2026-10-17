// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { desktopClient } from "@/lib/desktop-client";
import { AdvancedCommandWorkspace } from "./advanced-command-workspace";
let container: HTMLDivElement;
let root: Root;
const catalog = {
	entries: [
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
			"patch_binary",
			"apply_ast_transform",
			"patch_dotnet_constant",
			"patch_jvm_constant",
			"apply_candidate_batch",
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
