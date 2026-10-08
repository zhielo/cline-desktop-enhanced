// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
const calls = vi.hoisted(() => vi.fn());
vi.mock("@/lib/desktop-client", () => ({ desktopClient: { invoke: calls } }));
import { AnalysisEnvironmentView } from "./analysis-environment-view";
it("requires explicit readiness action and renders missing engines without claiming IDA failure", async () => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	calls.mockResolvedValue({
		configured: true,
		interpreter: { executable: "C:\\owned\\python.exe", version: "3.13" },
		toolchain: { status: "completed", evidence: { engines: [] } },
		readiness: {
			status: "partial",
			evidence: {
				checks: [
					{
						engine: "lief",
						status: "blocked",
						executionVerified: false,
						reason: "Required static engine missing",
					},
				],
			},
		},
		externalCapabilities: [
			{ id: "IDA / IDAPython", reason: "Separate acceptance required" },
		],
		setup: "Explicit opt-in setup",
	});
	const element = document.createElement("div");
	document.body.append(element);
	const root = createRoot(element);
	try {
		await act(async () => root.render(<AnalysisEnvironmentView />));
		expect(calls).not.toHaveBeenCalled();
		const button = [...element.querySelectorAll("button")].find(
			(node) => node.textContent === "Check analysis readiness",
		)!;
		await act(async () => {
			button.click();
		});
		expect(calls).toHaveBeenCalledWith(
			"get_analysis_environment",
			{ environmentId: "local" },
			{ timeoutMs: 90_000 },
		);
		expect(element.textContent).toContain("Missing dependency");
		expect(element.textContent).toContain(
			"Configuration / acceptance required",
		);
		expect(element.textContent).toContain("C:\\owned\\python.exe");
	} finally {
		await act(async () => root.unmount());
		element.remove();
	}
});
