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

it("reads bounded finding comparisons while Off without starting a worker", async () => {
	invoke.mockImplementation(async (command: string) =>
		command === "first_party_analysis_evidence"
			? {
					items: [
						{
							change: "removed",
							kind: "resolved-endpoint",
							value: "https://old.invalid",
						},
					],
					total: 1,
					nextOffset: null,
				}
			: {
					mode: "off",
					receipts: [
						{ id: "a", status: "completed", target: "new", createdAt: "now" },
					],
					readiness: {},
				},
	);
	await act(async () =>
		root.render(
			<FirstPartyAnalysisWorkspace sessionId="s" environmentId="local" />,
		),
	);
	await act(async () => {
		const select = el.querySelector("select")!;
		select.value = "a";
		select.dispatchEvent(new Event("change", { bubbles: true }));
	});
	await act(async () =>
		[...el.querySelectorAll("button")]
			.find((b) => b.textContent === "comparison")!
			.click(),
	);
	expect(invoke).toHaveBeenCalledWith("first_party_analysis_evidence", {
		sessionId: "s",
		environmentId: "local",
		query: {
			receiptId: "a",
			view: "comparison",
			filter: "",
			offset: 0,
			limit: 20,
		},
	});
	expect(el.textContent).toContain("https://old.invalid");
	expect(
		invoke.mock.calls.some((c) => c[0] === "first_party_analysis_run"),
	).toBe(false);
});

it("keeps sensitive console capture opt-in, invalidates reviewed plans and resets across sessions", async () => {
	invoke.mockImplementation(
		async (command: string, args?: Record<string, unknown>) =>
			command === "first_party_analysis_inspector_prepare"
				? {
						id: "owned",
						requestHash: "owned-hash",
						requirements: [
							"authorized-target",
							"sensitive-console-protocol-capture",
						],
						request: args?.input,
					}
				: { mode: "runtime", receipts: [], readiness: {} },
	);
	await act(async () =>
		root.render(
			<FirstPartyAnalysisWorkspace sessionId="s" environmentId="local" />,
		),
	);
	const checkbox = el.querySelector<HTMLInputElement>(
		'[aria-label="Capture source-bound console reports"]',
	)!;
	expect(checkbox.checked).toBe(false);
	expect(el.textContent).toContain("may include secrets");
	await act(async () => checkbox.click());
	expect(checkbox.checked).toBe(true);
	const review = () =>
		[...el.querySelectorAll("button")].find(
			(b) => b.textContent === "Review Inspector plan",
		)!;
	await act(async () => review().click());
	expect(invoke).toHaveBeenCalledWith(
		"first_party_analysis_inspector_prepare",
		expect.objectContaining({
			input: expect.objectContaining({ captureConsole: true }),
		}),
	);
	expect(el.textContent).toContain("Authorize reviewed observation");
	await act(async () => checkbox.click());
	expect(el.textContent).not.toContain("Authorize reviewed observation");
	await act(async () => checkbox.click());
	await act(async () =>
		root.render(
			<FirstPartyAnalysisWorkspace sessionId="other" environmentId="local" />,
		),
	);
	expect(
		el.querySelector<HTMLInputElement>(
			'[aria-label="Capture source-bound console reports"]',
		)!.checked,
	).toBe(false);
	expect(
		invoke.mock.calls.some(
			(c) => c[0] === "first_party_analysis_inspector_run",
		),
	).toBe(false);
});
it("does not restore a stale opt-in plan after its checkbox changes", async () => {
	let resolvePlan: (value: unknown) => void = () => {};
	invoke.mockImplementation(async (command: string) => {
		if (command === "first_party_analysis_inspector_prepare")
			return await new Promise((r) => {
				resolvePlan = r;
			});
		return { mode: "runtime", receipts: [], readiness: {} };
	});
	await act(async () =>
		root.render(
			<FirstPartyAnalysisWorkspace sessionId="s" environmentId="local" />,
		),
	);
	const checkbox = el.querySelector<HTMLInputElement>(
		'[aria-label="Capture source-bound console reports"]',
	)!;
	await act(async () => checkbox.click());
	await act(async () => {
		[...el.querySelectorAll("button")]
			.find((b) => b.textContent === "Review Inspector plan")!
			.click();
	});
	await act(async () => checkbox.click());
	await act(async () =>
		resolvePlan({
			id: "stale",
			requestHash: "stale",
			requirements: [],
			request: { captureConsole: true },
		}),
	);
	expect(el.textContent).not.toContain("Authorize reviewed observation");
});

it.each([
	"session-change",
	"unmount",
])("never starts an old observation after asynchronous approval and %s", async (action) => {
	let resolveApproval: (value: unknown) => void = () => {};
	invoke.mockImplementation(
		async (command: string, args?: Record<string, unknown>) => {
			if (command === "first_party_analysis_inspector_prepare")
				return {
					id: "old",
					requestHash: "owned",
					requirements: ["authorized-target"],
					request: args?.input,
				};
			if (command === "approve_analysis_task")
				return await new Promise((r) => {
					resolveApproval = r;
				});
			return { mode: "runtime", receipts: [], readiness: {} };
		},
	);
	vi.spyOn(window, "confirm").mockReturnValue(true);
	await act(async () =>
		root.render(
			<FirstPartyAnalysisWorkspace sessionId="old" environmentId="local" />,
		),
	);
	await act(async () =>
		[...el.querySelectorAll("button")]
			.find((b) => b.textContent === "Review Inspector plan")!
			.click(),
	);
	await act(async () =>
		[...el.querySelectorAll("button")]
			.find((b) => b.textContent === "Authorize reviewed observation")!
			.click(),
	);
	expect(
		el.querySelector<HTMLInputElement>(
			'[aria-label="Capture source-bound console reports"]',
		)!.disabled,
	).toBe(true);
	await act(async () =>
		root.render(
			action === "unmount" ? (
				<p>Closed</p>
			) : (
				<FirstPartyAnalysisWorkspace sessionId="new" environmentId="local" />
			),
		),
	);
	await act(async () => resolveApproval({ executionToken: "owned" }));
	expect(
		invoke.mock.calls.some(
			(c) => c[0] === "first_party_analysis_inspector_run",
		),
	).toBe(false);
	if (action !== "unmount")
		expect(
			el.querySelector<HTMLInputElement>(
				'[aria-label="Capture source-bound console reports"]',
			)!.disabled,
		).toBe(false);
});
