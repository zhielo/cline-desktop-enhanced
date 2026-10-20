import { it, expect } from "vitest";
import {
	resolveAnalysisTimeoutMs,
	IDA_OVERALL_TIMEOUT_MS,
	IDA_AUTO_ANALYSIS_TIMEOUT_MS,
} from "./analysis-budgets";
it("preserves IDA's one-hour phase within its 75-minute overall envelope", () => {
	expect(IDA_AUTO_ANALYSIS_TIMEOUT_MS).toBe(3600000);
	expect(resolveAnalysisTimeoutMs({ engine: "ida" })).toBe(4500000);
	expect(resolveAnalysisTimeoutMs({ engine: "ida", timeout_ms: 4500000 })).toBe(
		IDA_OVERALL_TIMEOUT_MS,
	);
	expect(resolveAnalysisTimeoutMs({ engine: "ida" }, 60000)).toBe(60000);
	expect(resolveAnalysisTimeoutMs({ engine: "auto" })).toBe(120000);
	expect(resolveAnalysisTimeoutMs({ engine: "auto" }, 4500000)).toBe(1800000);
	for (const n of [NaN, Infinity, -1, 0])
		expect(() => resolveAnalysisTimeoutMs({ engine: "ida" }, n)).toThrow();
});
