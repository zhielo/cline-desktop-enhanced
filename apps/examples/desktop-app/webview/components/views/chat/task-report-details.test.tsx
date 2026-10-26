// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { beforeEach, afterEach, describe, it, expect, vi } from "vitest";
import { TaskReportPanel } from "./task-report-panel";
import { TaskReportDetails, ChatReports } from "./task-report-details";
import { AnalysisResultView } from "./analysis-result-view";
let container: HTMLDivElement;
let root: Root;
beforeEach(() => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	container = document.createElement("div");
	document.body.append(container);
	root = createRoot(container);
	Object.defineProperty(navigator, "clipboard", {
		configurable: true,
		value: { writeText: vi.fn().mockResolvedValue(undefined) },
	});
});
afterEach(async () => {
	await act(async () => root.unmount());
	container.remove();
	vi.restoreAllMocks();
});
describe("reports and structured analysis", () => {
	it("renders final cancelled reports and all required sections without execution controls", async () => {
		await act(async () =>
			root.render(<TaskReportDetails status="cancelled" />),
		);
		for (const label of [
			"Final task report",
			"Cancelled",
			"Delivered",
			"Verified",
			"Not verified",
			"Remaining and blockers",
			"Artifacts",
			"Next action",
		])
			expect(container.textContent).toContain(label);
		expect(container.querySelectorAll("button")).toHaveLength(5);
		expect(container.textContent).not.toContain("Resume task");
	});
	it("copies a redacted summary and handles clipboard failures", async () => {
		await act(async () => root.render(<TaskReportDetails status="idle" />));
		const button = [...container.querySelectorAll("button")].find(
			(x) => x.textContent === "Copy summary",
		)!;
		await act(async () => {
			button.click();
			await Promise.resolve();
		});
		expect(navigator.clipboard.writeText).toHaveBeenCalledOnce();
		expect(container.textContent).toContain("Report copied");
		vi.mocked(navigator.clipboard.writeText).mockRejectedValueOnce(
			new Error("denied"),
		);
		await act(async () => {
			button.click();
			await Promise.resolve();
		});
		expect(container.textContent).toContain("Could not copy");
	});
	it("keeps missing session history explicitly unverified", async () => {
		await act(async () =>
			root.render(<ChatReports messages={[]} status="idle" />),
		);
		expect(container.textContent).toContain("Unverified");
		expect(container.textContent).toContain("never runs tools");
	});
	it("renders bounded untrusted findings as text, with raw output collapsed", async () => {
		await act(async () =>
			root.render(
				<AnalysisResultView
					busy={false}
					value={{
						status: "partial",
						findings: Array.from({ length: 40 }, (_, i) => ({
							id: String(i),
							title: "<script>not instructions</script>",
							description: "candidate",
						})),
						limitations: ["Indirect calls unresolved"],
					}}
				/>,
			),
		);
		expect(container.querySelector("script")).toBeNull();
		expect(container.querySelectorAll("li")).toHaveLength(31);
		expect(container.textContent).toContain("partial");
		expect(container.querySelector("details")?.open).toBe(false);
	});
});

function longReport() {
	return {
		mode: "activity" as const,
		steps: [],
		evidence: Array.from({ length: 225 }, (_, i) => ({
			id: `e${i}`,
			label: `Receipt ${i}`,
			status: "completed" as const,
			toolName: "read_files",
			createdAt: 1000 - i,
		})),
		completedCount: 0,
		progressPercent: 0,
		sourceMessageId: "m",
		sourceTool: "read_files",
		turnId: "u",
		updatedAt: 1000,
	};
}
async function clickLabel(label: string) {
	const button = [...container.querySelectorAll("button")].find(
		(button) => button.textContent === label,
	);
	expect(button).toBeDefined();
	await act(async () => button!.click());
}
describe("bounded report navigation", () => {
	it("pages beyond 200 entries with bounded DOM and stable receipt anchors during streaming", async () => {
		const report = longReport();
		await act(async () =>
			root.render(<TaskReportDetails report={report} status="running" />),
		);
		for (let i = 0; i < 10; i++) await clickLabel("Older evidence");
		expect(container.textContent).toContain("Showing 201–220 of 225");
		expect(container.querySelectorAll("ol > li")).toHaveLength(20);
		const next = {
			...report,
			evidence: [
				{ ...report.evidence[0], id: "new", label: "New receipt" },
				...report.evidence,
			],
		};
		await act(async () =>
			root.render(<TaskReportDetails report={next} status="running" />),
		);
		expect(container.querySelector("ol > li strong")?.textContent).toBe(
			"Receipt 200",
		);
		await clickLabel("Older evidence");
		expect(container.textContent).toContain("Receipt 224");
		await clickLabel("Latest evidence");
		expect(container.querySelector("ol > li strong")?.textContent).toBe(
			"New receipt",
		);
		expect(container.textContent).toContain("Upstream history total unknown");
	});
	it("keeps report history beyond fifty turns reachable without mounting every details body", async () => {
		const messages = Array.from({ length: 55 }, (_, i) => [
			{
				id: `u${i}`,
				sessionId: "s",
				role: "user" as const,
				content: `Goal ${i}`,
				createdAt: i * 2,
			},
			{
				id: `t${i}`,
				sessionId: "s",
				role: "tool" as const,
				content: JSON.stringify({
					toolName: "read_files",
					input: { paths: ["a.ts"] },
					result: { ok: true },
				}),
				createdAt: i * 2 + 1,
			},
		]).flat();
		await act(async () =>
			root.render(<ChatReports messages={messages} status="completed" />),
		);
		expect(
			container.querySelectorAll('[aria-label="Evidence-backed task report"]'),
		).toHaveLength(1);
		for (let i = 0; i < 5; i++) await clickLabel("Older reports");
		expect(container.textContent).toContain("Goal 0");
		expect(
			container.querySelectorAll('[aria-label="Evidence-backed task report"]'),
		).toHaveLength(0);
		expect(container.querySelectorAll("details")).toHaveLength(5);
	});
});

it("keeps task header execution separate from an evidence-verified outcome", async () => {
	const report = {
		...longReport(),
		mode: "plan" as const,
		goal: "Declared scope",
		planId: "plan",
		steps: [
			{
				id: "step",
				label: "Check",
				kind: "work" as const,
				status: "completed" as const,
				validationScope: "scope",
			},
		],
		completedCount: 1,
		evidence: [
			{
				id: "check",
				label: "Check",
				toolName: "task_validation",
				status: "completed" as const,
				createdAt: 20,
				observation: {
					version: "task-observation/v1" as const,
					id: "check",
					sessionId: "s",
					toolCallId: "check",
					toolName: "task_validation",
					source: "host-validation" as const,
					execution: "finished" as const,
					outcome: "bounded-checks-passed" as const,
					checkCount: 1,
					planId: "plan",
					stepId: "step",
					validationScope: "scope",
					recordedAtMs: 20,
				},
			},
		],
	};
	await act(async () =>
		root.render(<TaskReportPanel report={report} status="running" />),
	);
	expect(container.textContent).toContain("Running");
	expect(container.textContent).toContain("Declared checks passed");
	expect(container.textContent).not.toContain("outcome unverified");
});
