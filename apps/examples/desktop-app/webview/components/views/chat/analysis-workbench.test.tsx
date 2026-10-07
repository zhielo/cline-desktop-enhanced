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
