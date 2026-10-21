// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@/lib/desktop-client", () => ({ desktopClient: { invoke } }));

import { ApplicationEvidenceWorkflows } from "./application-evidence-workflows";
import { ActiveJavaScriptScenario } from "./active-javascript-scenario";
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

it("selects a filterable application view before filtering saved verification evidence", async () => {
	invoke.mockImplementation(async (command: string) =>
		command === "first_party_analysis_evidence"
			? { items: [], total: 0, nextOffset: null, verifiedBehavior: false }
			: {
					mode: "off",
					receipts: [
						{ id: "a", status: "completed", target: "app", createdAt: "now" },
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
		const select = el.querySelector<HTMLSelectElement>(
			'[aria-label="Saved analysis receipt"]',
		)!;
		select.value = "a";
		select.dispatchEvent(new Event("change", { bubbles: true }));
	});
	const view = (name: string) =>
		[...el.querySelectorAll("button")].find((b) => b.textContent === name)!;
	await act(async () => view("verification").click());
	expect(
		el.querySelector('[aria-label="Filter analysis evidence"]'),
	).toBeNull();
	await act(async () => view("application-nodes").click());
	expect(
		el.querySelector('[aria-label="Filter analysis evidence"]'),
	).not.toBeNull();
	expect(invoke).toHaveBeenCalledWith("first_party_analysis_evidence", {
		sessionId: "s",
		environmentId: "local",
		query: {
			receiptId: "a",
			view: "application-nodes",
			filter: "",
			offset: 0,
			limit: 20,
		},
	});
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

async function prepareOwnedScenario() {
	await act(async () =>
		root.render(
			<ActiveJavaScriptScenario
				sessionId="s"
				environmentId="local"
				enabled={true}
			/>,
		),
	);
	await act(async () => {
		const input = el.querySelector<HTMLInputElement>(
			'[aria-label="Isolated JavaScript target"]',
		)!;
		Object.getOwnPropertyDescriptor(
			HTMLInputElement.prototype,
			"value",
		)!.set!.call(input, "owned.cjs");
		input.dispatchEvent(new Event("input", { bubbles: true }));
	});
	await act(async () =>
		Array.from(el.querySelectorAll("button"))
			.find((b) => b.textContent?.includes("Prepare independently"))!
			.click(),
	);
	await vi.waitFor(() =>
		expect(el.textContent).toContain("Approve Execute and run once"),
	);
}
it("invalidates independent Execute approval on session change before run", async () => {
	let release!: (v: unknown) => void;
	invoke.mockImplementation((command: string) =>
		command.endsWith("_prepare")
			? Promise.resolve({
					id: "p",
					requestHash: "h",
					requirements: ["independent-execute-approval"],
					request: { operation: "js_isolated_execute", target: "owned.cjs" },
				})
			: command === "approve_analysis_task"
				? new Promise((r) => {
						release = r;
					})
				: Promise.resolve({}),
	);
	vi.spyOn(window, "confirm").mockReturnValue(true);
	await prepareOwnedScenario();
	await act(async () =>
		Array.from(el.querySelectorAll("button"))
			.find((b) => b.textContent?.includes("Approve Execute"))!
			.click(),
	);
	expect(invoke.mock.calls.some((c) => c[0] === "approve_analysis_task")).toBe(
		true,
	);
	await act(async () =>
		root.render(
			<ActiveJavaScriptScenario
				sessionId="other"
				environmentId="local"
				enabled={true}
			/>,
		),
	);
	await act(async () => release({ executionToken: "old-token" }));
	expect(invoke.mock.calls.some((c) => String(c[0]).endsWith("_run"))).toBe(
		false,
	);
});
it("editing target discards prepared Execute plan and never executes automatically", async () => {
	invoke.mockResolvedValue({
		id: "p",
		requestHash: "h",
		requirements: [],
		request: { operation: "js_isolated_execute" },
	});
	await prepareOwnedScenario();
	expect(el.textContent).toContain("Approve Execute and run once");
	await act(async () => {
		const input = el.querySelector<HTMLInputElement>(
			'[aria-label="Isolated JavaScript target"]',
		)!;
		Object.getOwnPropertyDescriptor(
			HTMLInputElement.prototype,
			"value",
		)!.set!.call(input, "changed.cjs");
		input.dispatchEvent(new Event("input", { bubbles: true }));
	});
	expect(el.textContent).not.toContain("Approve Execute and run once");
	expect(
		invoke.mock.calls.some(
			(c) => c[0] === "approve_analysis_task" || String(c[0]).endsWith("_run"),
		),
	).toBe(false);
});
it("Hybrid selection is explicit and does not auto-run inspection or execution", async () => {
	await act(async () =>
		root.render(
			<AnalysisModeControl
				sessionId="s"
				environmentId="local"
				status="completed"
			/>,
		),
	);
	const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
	await act(async () => {
		const select = el.querySelector("select")!;
		select.value = "hybrid";
		select.dispatchEvent(new Event("change", { bubbles: true }));
	});
	expect(confirm).toHaveBeenCalledWith(
		expect.stringContaining("prior static evidence"),
	);
	expect(el.querySelector("select")?.value).toBe("hybrid");
	expect(
		invoke.mock.calls
			.map((c) => c[0])
			.every((c) =>
				["first_party_analysis_status", "first_party_analysis_mode"].includes(
					c,
				),
			),
	).toBe(true);
});

it("offers draft Analysis before any session without invoking tools or granting permissions", async () => {
	const change = vi.fn();
	await act(async () =>
		root.render(
			<AnalysisModeControl
				environmentId="local"
				draftMode="off"
				onDraftModeChange={change}
			/>,
		),
	);
	expect(el.querySelector("select")?.disabled).toBe(false);
	await act(async () => {
		const select = el.querySelector("select")!;
		select.value = "static";
		select.dispatchEvent(new Event("change", { bubbles: true }));
	});
	expect(change).toHaveBeenCalledWith("static");
	expect(invoke).not.toHaveBeenCalled();
	vi.spyOn(window, "confirm").mockReturnValue(false);
	await act(async () => {
		const select = el.querySelector("select")!;
		select.value = "hybrid";
		select.dispatchEvent(new Event("change", { bubbles: true }));
	});
	expect(change).toHaveBeenCalledTimes(1);
	expect(invoke).not.toHaveBeenCalled();
});

it("gives mounted draft and session controls distinct accessible identities", async () => {
	await act(async () =>
		root.render(
			<>
				<AnalysisModeControl
					sessionId="s"
					environmentId="local"
					status="completed"
				/>
				<AnalysisModeControl
					environmentId="local"
					onDraftModeChange={vi.fn()}
				/>
			</>,
		),
	);
	const session = el.querySelector(
		'select[aria-label="Session Analysis mode"]',
	)!;
	const draft = el.querySelector('select[aria-label="Draft Analysis mode"]')!;
	expect(session).not.toBeNull();
	expect(draft).not.toBeNull();
	expect(session.id).not.toBe(draft.id);
	expect(
		el.querySelectorAll('button[aria-label="Open Analysis Workspace"]'),
	).toHaveLength(1);
	expect(
		el.querySelectorAll('button[aria-label="Open draft Analysis workspace"]'),
	).toHaveLength(1);
	expect(
		[...el.querySelectorAll("select")].filter(
			(control) => control.id === session.id,
		),
	).toHaveLength(1);
	expect(
		[...el.querySelectorAll("select")].filter(
			(control) => control.id === draft.id,
		),
	).toHaveLength(1);
});

it("allows draft path selection locally without a session, host calls or runtime authority", async () => {
	await act(async () =>
		root.render(<FirstPartyAnalysisWorkspace environmentId="local" />),
	);
	const target = el.querySelector<HTMLInputElement>(
		'input[aria-label="JavaScript analysis target"]',
	)!;
	expect(target.value).toBe(".");
	await act(async () => {
		Object.getOwnPropertyDescriptor(
			HTMLInputElement.prototype,
			"value",
		)?.set?.call(target, "owned.ts");
		target.dispatchEvent(new Event("input", { bubbles: true }));
	});
	expect(target.value).toBe("owned.ts");
	const inspect = [...el.querySelectorAll("button")].find((b) =>
		b.textContent?.includes("Inspect static sources"),
	)!;
	expect(inspect.disabled).toBe(true);
	await act(async () => inspect.click());
	expect(el.textContent).toContain("Path selection only");
	expect(
		el.querySelector('input[aria-label="Inspector source target"]'),
	).toBeNull();
	expect(invoke).not.toHaveBeenCalled();
	await act(async () =>
		root.render(<FirstPartyAnalysisWorkspace environmentId="ssh:remote" />),
	);
	expect(
		el.querySelector('input[aria-label="JavaScript analysis target"]'),
	).toBeNull();
	expect(invoke).not.toHaveBeenCalled();
});
it("only requests integrated semantics after explicit selection and preserves the existing analysis route", async () => {
	invoke.mockImplementation(async (command: string) =>
		command === "first_party_analysis_run"
			? { id: "owned-semantic", status: "partial" }
			: { mode: "static", receipts: [], readiness: {} },
	);
	await act(async () =>
		root.render(
			<FirstPartyAnalysisWorkspace sessionId="s" environmentId="local" />,
		),
	);
	const toggle = [
		...el.querySelectorAll<HTMLInputElement>('input[type="checkbox"]'),
	].find((input) =>
		input.parentElement?.textContent?.includes(
			"Include file-local semantic graph",
		),
	);
	expect(toggle).toBeDefined();
	expect(toggle?.checked).toBe(false);
	expect(
		invoke.mock.calls.some((c) => c[0] === "first_party_analysis_run"),
	).toBe(false);
	await act(async () => toggle!.click());
	const run = [...el.querySelectorAll("button")].find(
		(b) => b.textContent === "Inspect static sources",
	)!;
	await act(async () => run.click());
	expect(invoke).toHaveBeenCalledWith(
		"first_party_analysis_run",
		{
			sessionId: "s",
			environmentId: "local",
			input: { target: ".", semanticGraph: true },
		},
		{ timeoutMs: 330000 },
	);
	expect(el.textContent).toContain("semantic-nodes");
});

it("requires explicit application opt-in, binds semantic analysis and resets it on session change", async () => {
	invoke.mockImplementation(async (command: string) =>
		command === "first_party_analysis_run"
			? { id: "app-receipt", status: "partial" }
			: { mode: "static", receipts: [], readiness: {} },
	);
	await act(async () =>
		root.render(
			<FirstPartyAnalysisWorkspace sessionId="owner" environmentId="local" />,
		),
	);
	const boxes = [
		...el.querySelectorAll<HTMLInputElement>('input[type="checkbox"]'),
	];
	const application = boxes.find((b) =>
		b.parentElement?.textContent?.includes("Include application graph"),
	)!;
	const semantic = boxes.find((b) =>
		b.parentElement?.textContent?.includes("Include file-local"),
	)!;
	expect(application.checked).toBe(false);
	expect(semantic.checked).toBe(false);
	await act(async () => application.click());
	expect(application.checked).toBe(true);
	expect(semantic.checked).toBe(true);
	expect(semantic.disabled).toBe(true);
	expect(
		invoke.mock.calls.some((c) => c[0] === "first_party_analysis_run"),
	).toBe(false);
	await act(async () =>
		[...el.querySelectorAll("button")]
			.find((b) => b.textContent === "Inspect static sources")!
			.click(),
	);
	expect(invoke).toHaveBeenCalledWith(
		"first_party_analysis_run",
		expect.objectContaining({
			sessionId: "owner",
			input: expect.objectContaining({
				semanticGraph: true,
				applicationGraph: true,
			}),
		}),
		{ timeoutMs: 330000 },
	);
	await act(async () =>
		root.render(
			<FirstPartyAnalysisWorkspace sessionId="other" environmentId="local" />,
		),
	);
	expect(
		[...el.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')].find(
			(b) =>
				b.parentElement?.textContent?.includes("Include application graph"),
		)!.checked,
	).toBe(false);
});

it("queries saved application workflows only on explicit action and pages the committed query", async () => {
	invoke.mockResolvedValue({ items: [{ owned: true }], nextOffset: 20 });
	await act(async () =>
		root.render(
			<ApplicationEvidenceWorkflows
				receiptId="left"
				sessionId="owner"
				environmentId="local"
				receipts={[
					{ id: "left", target: "same" },
					{ id: "right", target: "other" },
				]}
			/>,
		),
	);
	expect(invoke).not.toHaveBeenCalled();
	const setText = async (label: string, value: string) =>
		act(async () => {
			const input = el.querySelector<HTMLInputElement>(
				`input[aria-label="${label}"]`,
			)!;
			Object.getOwnPropertyDescriptor(
				HTMLInputElement.prototype,
				"value",
			)!.set!.call(input, value);
			input.dispatchEvent(new Event("input", { bubbles: true }));
		});
	const select = async (label: string, value: string) =>
		act(async () => {
			const input = el.querySelector<HTMLSelectElement>(
				`select[aria-label="${label}"]`,
			)!;
			input.value = value;
			input.dispatchEvent(new Event("change", { bubbles: true }));
		});
	await setText("Application feature seed", "owned:add");
	expect(invoke).not.toHaveBeenCalled();
	const run = () =>
		[...el.querySelectorAll("button")].find(
			(b) => b.textContent === "Run saved application query",
		)!;
	await act(async () => run().click());
	expect(invoke).toHaveBeenLastCalledWith("first_party_analysis_evidence", {
		sessionId: "owner",
		environmentId: "local",
		query: {
			receiptId: "left",
			view: "application-trace",
			offset: 0,
			limit: 20,
			applicationTrace: {
				seed: {
					kind: "channel",
					value: "owned:add",
					match: "exact",
					case_sensitive: false,
				},
				direction: "both",
			},
		},
	});
	await setText("Application feature seed", "not-submitted");
	await act(async () =>
		[...el.querySelectorAll("button")]
			.find((b) => b.textContent === "Next saved application page")!
			.click(),
	);
	expect(invoke.mock.lastCall?.[1].query.applicationTrace.seed.value).toBe(
		"owned:add",
	);
	expect(invoke.mock.lastCall?.[1].query.offset).toBe(20);
	await select("Application workflow", "application-comparison");
	expect(
		el.querySelector(
			'select[aria-label="Application comparison receipt"] option[value="left"]',
		),
	).toBeNull();
	await select("Application comparison receipt", "right");
	await act(async () => run().click());
	expect(invoke.mock.lastCall?.[1].query).toEqual({
		receiptId: "left",
		view: "application-comparison",
		offset: 0,
		limit: 20,
		compareReceiptId: "right",
	});
	await select("Application workflow", "application-exports");
	await setText("Left export module", "api.cjs");
	await setText("Right export module", "api.cjs");
	await setText("Left export name", "add");
	await setText("Right export name", "add");
	await act(async () => run().click());
	expect(invoke.mock.lastCall?.[1].query.exportSelectors).toEqual({
		left: { modulePath: "api.cjs", exportName: "add" },
		right: { modulePath: "api.cjs", exportName: "add" },
	});
	invoke.mockRejectedValueOnce(new Error("Receipt not found"));
	await act(async () => run().click());
	expect(el.querySelector('[role="alert"]')?.textContent).toBe(
		"Receipt not found",
	);
	expect(
		el.querySelector('section[aria-label="Saved application workflow result"]'),
	).toBeNull();
	expect(
		invoke.mock.calls.every((c) => c[0] === "first_party_analysis_evidence"),
	).toBe(true);
});

it("requires explicit fuse-only selection, prevents mixed options and resets on session change", async () => {
	invoke.mockImplementation(async (command: string) =>
		command === "first_party_analysis_run"
			? { id: "fuse-receipt", status: "partial" }
			: { mode: "static", receipts: [], readiness: {} },
	);
	await act(async () =>
		root.render(
			<FirstPartyAnalysisWorkspace sessionId="owner" environmentId="local" />,
		),
	);
	const box = () =>
		[...el.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')].find(
			(b) =>
				b.parentElement?.textContent?.includes(
					"Inspect executable Electron fuses only",
				),
		)!;
	expect(box().checked).toBe(false);
	expect(
		invoke.mock.calls.some((c) => c[0] === "first_party_analysis_run"),
	).toBe(false);
	await act(async () => box().click());
	expect(
		el.querySelector<HTMLInputElement>(
			'[aria-label="JavaScript comparison target"]',
		)?.disabled,
	).toBe(true);
	expect(
		[...el.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')].find(
			(b) => b.parentElement?.textContent?.includes("Include file-local"),
		)?.disabled,
	).toBe(true);
	await act(async () =>
		[...el.querySelectorAll("button")]
			.find((b) => b.textContent === "Inspect executable fuses")!
			.click(),
	);
	expect(invoke).toHaveBeenCalledWith(
		"first_party_analysis_run",
		{
			sessionId: "owner",
			environmentId: "local",
			input: { target: ".", electronFuses: true },
		},
		{ timeoutMs: 75000 },
	);
	expect(el.textContent).toContain("No automatic .app selection");
	expect(el.textContent).toContain("electron-fuses");
	await act(async () =>
		root.render(
			<FirstPartyAnalysisWorkspace sessionId="other" environmentId="local" />,
		),
	);
	expect(box().checked).toBe(false);
});

it("reads and switches individual saved fuse wires while Off without starting inspection", async () => {
	invoke.mockImplementation(async (command: string) =>
		command === "first_party_analysis_status"
			? {
					mode: "off",
					readiness: {},
					receipts: [
						{
							id: "owned-fuses",
							target: "owned.exe",
							status: "partial",
							createdAt: "owned-time",
						},
					],
				}
			: {
					available: true,
					artifact: { sha256: "owned-hash" },
					items: [],
					limitations: ["Static bytes only"],
					verifiedBehavior: false,
				},
	);
	await act(async () =>
		root.render(
			<FirstPartyAnalysisWorkspace sessionId="owner" environmentId="local" />,
		),
	);
	const receipt = el.querySelector<HTMLSelectElement>(
		'[aria-label="Saved analysis receipt"]',
	)!;
	await act(async () => {
		receipt.value = "owned-fuses";
		receipt.dispatchEvent(new Event("change", { bubbles: true }));
	});
	await act(async () =>
		[...el.querySelectorAll("button")]
			.find((b) => b.textContent === "electron-fuses")!
			.click(),
	);
	expect(invoke).toHaveBeenCalledWith("first_party_analysis_evidence", {
		sessionId: "owner",
		environmentId: "local",
		query: {
			receiptId: "owned-fuses",
			view: "electron-fuses",
			filter: "",
			offset: 0,
			limit: 20,
			fuseSection: "slices",
		},
	});
	const section = el.querySelector<HTMLSelectElement>(
		'[aria-label="Fuse evidence section"]',
	)!;
	await act(async () => {
		section.value = "sentinels";
		section.dispatchEvent(new Event("change", { bubbles: true }));
	});
	expect(invoke).toHaveBeenCalledWith("first_party_analysis_evidence", {
		sessionId: "owner",
		environmentId: "local",
		query: {
			receiptId: "owned-fuses",
			view: "electron-fuses",
			filter: "",
			offset: 0,
			limit: 20,
			fuseSection: "sentinels",
		},
	});
	expect(el.textContent).toContain("Static bytes only");
	expect(el.textContent).toContain("owned-hash");
	expect(
		invoke.mock.calls.some((c) => c[0] === "first_party_analysis_run"),
	).toBe(false);
});

it("reads acquisition and original container evidence while Off without an analysis run", async () => {
	invoke.mockImplementation(
		async (command: string, args?: Record<string, unknown>) =>
			command === "first_party_analysis_evidence"
				? {
						available: true,
						selection: "explicit-workspace-target",
						coverage: "partial",
						providerCalls: 0,
						targetExecuted: false,
						verifiedBehavior: false,
						items: [],
						total: 0,
						nextOffset: null,
					}
				: {
						mode: "off",
						receipts: [
							{
								id: "owned",
								status: "partial",
								target: "app.asar",
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
	await act(async () => {
		const select = el.querySelector("select")!;
		select.value = "owned";
		select.dispatchEvent(new Event("change", { bubbles: true }));
	});
	for (const view of ["source-acquisition", "source-containers"]) {
		const button = [...el.querySelectorAll("button")].find(
			(b) => b.textContent === view,
		)!;
		await act(async () => button.click());
		expect(
			invoke.mock.calls.some(
				([cmd, args]) =>
					cmd === "first_party_analysis_evidence" &&
					(args?.query as { view?: string })?.view === view,
			),
		).toBe(true);
		expect(el.textContent).toContain('"targetExecuted": false');
	}
	expect(
		invoke.mock.calls.some(([cmd]) => cmd === "first_party_analysis_run"),
	).toBe(false);
});
