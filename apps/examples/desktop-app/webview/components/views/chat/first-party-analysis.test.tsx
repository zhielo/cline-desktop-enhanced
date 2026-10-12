// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
const invoke = vi.hoisted(() => vi.fn());
vi.mock("@/lib/desktop-client", () => ({ desktopClient: { invoke } }));
import { AnalysisModeControl } from "./analysis-mode-control";
import { FirstPartyAnalysisWorkspace } from "./first-party-analysis-workspace";
let el: HTMLDivElement, root: Root;
beforeEach(() => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	el = document.createElement("div");
	document.body.append(el);
	root = createRoot(el);
	invoke.mockReset();
	let mode: unknown = "off";
	invoke.mockImplementation(
		async (command: string, args?: Record<string, unknown>) => {
			if (command === "first_party_analysis_mode") mode = args?.mode;
			return { mode, receipts: [], readiness: {} };
		},
	);
});
afterEach(async () => {
	await act(async () => root.unmount());
	el.remove();
	vi.restoreAllMocks();
});
it("loads persisted mode without any analysis execution and changes only on user action", async () => {
	await act(async () =>
		root.render(
			<AnalysisModeControl
				sessionId="s"
				environmentId="local"
				status="completed"
			/>,
		),
	);
	expect(invoke.mock.calls.map((c) => c[0])).toEqual([
		"first_party_analysis_status",
	]);
	await act(async () => {
		const select = el.querySelector("select")!;
		select.value = "static";
		select.dispatchEvent(new Event("change", { bubbles: true }));
	});
	expect(invoke).toHaveBeenCalledWith("first_party_analysis_mode", {
		sessionId: "s",
		environmentId: "local",
		mode: "static",
	});
	expect(el.querySelector("select")?.value).toBe("static");
});
it("disables mode changes during active turns and requires runtime confirmation", async () => {
	await act(async () =>
		root.render(
			<AnalysisModeControl
				sessionId="s"
				environmentId="local"
				status="running"
			/>,
		),
	);
	expect(el.querySelector("select")?.disabled).toBe(true);
	await act(async () =>
		root.render(
			<AnalysisModeControl
				sessionId="s"
				environmentId="local"
				status="completed"
			/>,
		),
	);
	vi.spyOn(window, "confirm").mockReturnValue(false);
	await act(async () => {
		const select = el.querySelector("select")!;
		select.value = "runtime";
		select.dispatchEvent(new Event("change", { bubbles: true }));
	});
	expect(
		invoke.mock.calls.some((c) => c[0] === "first_party_analysis_mode"),
	).toBe(false);
});
it("does not expose local controls on remote sessions", async () => {
	await act(async () =>
		root.render(<AnalysisModeControl sessionId="s" environmentId="ssh:test" />),
	);
	expect(el.querySelector("select")).toBeNull();
	expect(invoke).not.toHaveBeenCalled();
});
it("keeps saved evidence available in Off and never auto-runs inspection", async () => {
	invoke.mockImplementation(async (command: string) =>
		command === "first_party_analysis_evidence"
			? { verifiedBehavior: false, status: "completed" }
			: {
					mode: "off",
					receipts: [
						{
							id: "a",
							status: "completed",
							target: "app.js",
							createdAt: "now",
						},
					],
					readiness: {},
				},
	);
	await act(async () =>
		root.render(
			<FirstPartyAnalysisWorkspace sessionId="s" environmentId="local" />,
		),
	);
	const run = [...el.querySelectorAll("button")].find(
		(b) => b.textContent === "Inspect static sources",
	)!;
	expect(run.disabled).toBe(true);
	await act(async () => {
		const select = el.querySelector("select")!;
		select.value = "a";
		select.dispatchEvent(new Event("change", { bubbles: true }));
	});
	const verification = [...el.querySelectorAll("button")].find(
		(b) => b.textContent === "verification",
	)!;
	await act(async () => verification.click());
	expect(el.textContent).toContain('"verifiedBehavior": false');
	expect(
		invoke.mock.calls.some((c) => c[0] === "first_party_analysis_run"),
	).toBe(false);
});
