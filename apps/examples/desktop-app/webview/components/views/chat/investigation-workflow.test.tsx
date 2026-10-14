// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { beforeEach, afterEach, it, expect, vi } from "vitest";
const invoke = vi.hoisted(() => vi.fn());
vi.mock("@/lib/desktop-client", () => ({ desktopClient: { invoke } }));
import { InvestigationWorkflow } from "./investigation-workflow";
let el: HTMLDivElement, root: Root;
const artifact = "11111111-1111-4111-8111-111111111111";
beforeEach(() => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	el = document.createElement("div");
	document.body.append(el);
	root = createRoot(el);
	invoke.mockReset();
	invoke.mockImplementation(async (command: string) =>
		command === "analysis_workflow_status"
			? {
					workspace: "/owned",
					mode: "static",
					artifacts: [{ id: artifact, path: "/owned/app.exe" }],
					scenarios: [],
					browsers: [],
				}
			: command === "approve_analysis_task"
				? { executionToken: "one-use" }
				: {
						id: artifact,
						requestHash: "reviewed-hash",
						requirements: ["Execute"],
						request: { target: "/owned/app.exe" },
					},
	);
	vi.spyOn(window, "confirm").mockReturnValue(true);
});
afterEach(async () => {
	await act(async () => root.unmount());
	el.remove();
	vi.restoreAllMocks();
});
const click = async (label: string) => {
	await act(async () => {
		const b = [...el.querySelectorAll("button")].find(
			(b) => b.textContent === label,
		)!;
		b.click();
	});
};
const change = async (label: string, value: string) => {
	await act(async () => {
		const input = el.querySelector(
			`[aria-label="${label}"]`,
		) as HTMLInputElement;
		const proto =
			input.tagName === "SELECT"
				? HTMLSelectElement.prototype
				: HTMLInputElement.prototype;
		Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(input, value);
		input.dispatchEvent(
			new Event(input.tagName === "SELECT" ? "change" : "input", {
				bubbles: true,
			}),
		);
	});
};
const render = async (mode = "static", sessionId = "owned") => {
	await act(async () =>
		root.render(
			<InvestigationWorkflow
				sessionId={sessionId}
				environmentId="local"
				mode={mode}
				receiptIds={[]}
			/>,
		),
	);
};
const open = async () => {
	await act(async () => {
		const d = el.querySelector("details")!;
		d.open = true;
		d.dispatchEvent(new Event("toggle"));
	});
};
it("opening the panel performs only a scoped read, then prepare and approval remain separate", async () => {
	await render();
	expect(invoke).not.toHaveBeenCalled();
	await open();
	expect(invoke.mock.calls.map((c) => c[0])).toEqual([
		"analysis_workflow_status",
	]);
	await change("Investigation artifact", artifact);
	await change("Exact function selector", "owned");
	await click("Prepare function analysis");
	expect(
		invoke.mock.calls.filter((c) => c[0] === "analyze_function"),
	).toHaveLength(1);
	expect(
		invoke.mock.calls.find((c) => c[0] === "approve_analysis_task"),
	).toBeUndefined();
	await click("Approve reviewed function analysis");
	const approved = invoke.mock.calls.find(
		(c) => c[0] === "approve_analysis_task",
	)!;
	expect(approved[1]).toMatchObject({
		sessionId: "owned",
		cwd: "/owned",
		requestHash: "reviewed-hash",
		requirements: ["Execute"],
	});
	expect(
		invoke.mock.calls.filter((c) => c[0] === "analyze_function")[1][1].input,
	).toMatchObject({ phase: "run", executionToken: "one-use" });
});
it("changing the selector or session invalidates the reviewed plan", async () => {
	await render();
	await open();
	await change("Investigation artifact", artifact);
	await change("Exact function selector", "owned");
	await click("Prepare function analysis");
	await change("Exact function selector", "other");
	expect(el.textContent).not.toContain("Approve reviewed function analysis");
	await click("Prepare function analysis");
	await render("static", "different");
	expect(el.textContent).not.toContain("Approve reviewed function analysis");
	expect(invoke.mock.calls.some((c) => c[0] === "approve_analysis_task")).toBe(
		false,
	);
});
it("Off prevents new analysis and recording, without automatically replaying work", async () => {
	await render("off");
	await open();
	expect(
		[...el.querySelectorAll("button")].find(
			(b) => b.textContent === "Open immutable binary handle",
		)!.disabled,
	).toBe(true);
	expect(
		[...el.querySelectorAll("button")].find(
			(b) => b.textContent === "Start approved metadata recording",
		)!.disabled,
	).toBe(true);
	expect(
		invoke.mock.calls.every((c) => c[0] === "analysis_workflow_status"),
	).toBe(true);
});
