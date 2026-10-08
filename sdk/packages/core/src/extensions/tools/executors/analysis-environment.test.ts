import { describe, expect, it, vi } from "vitest";
const calls = vi.hoisted(() => vi.fn());
vi.mock("./advanced-analysis", () => ({ runAdvancedAnalysis: calls }));
import { checkAnalysisEnvironment } from "./analysis-environment";
describe("explicit environment readiness", () => {
	it("runs only bounded inventory and owned fixtures; does not claim external readiness", async () => {
		calls.mockResolvedValue({
			status: "partial",
			evidence: { checks: [] },
			diagnostics: { interpreter: "/owned/python" },
		});
		const result = await checkAnalysisEnvironment();
		expect(calls.mock.calls.map(([request]) => request.action)).toEqual([
			"toolchain",
			"analysis_readiness",
		]);
		expect(
			calls.mock.calls.every(
				([request]) => !request.target && request.timeoutMs <= 60_000,
			),
		).toBe(true);
		expect(
			result.externalCapabilities.every(
				(item) => item.status === "configuration-required",
			),
		).toBe(true);
	});
});
