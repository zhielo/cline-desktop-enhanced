// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { beforeEach, afterEach, describe, it, expect, vi } from "vitest";
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
		expect(container.querySelectorAll("button")).toHaveLength(4);
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
