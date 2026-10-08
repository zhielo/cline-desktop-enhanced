import { expect, it, vi } from "vitest";
const check = vi.hoisted(() => vi.fn());
vi.mock("@cline/core", () => ({ checkAnalysisEnvironment: check }));
import { getAnalysisEnvironment } from "./analysis-environment";
it("coalesces simultaneous checks but does not retain stale results", async () => {
	let finish!: (value: unknown) => void;
	check.mockImplementationOnce(
		() =>
			new Promise((resolve) => {
				finish = resolve;
			}),
	);
	const first = getAnalysisEnvironment(),
		second = getAnalysisEnvironment();
	expect(first).toBe(second);
	expect(check).toHaveBeenCalledTimes(1);
	finish({ status: "owned" });
	await first;
	check.mockResolvedValueOnce({ status: "new-check" });
	await getAnalysisEnvironment();
	expect(check).toHaveBeenCalledTimes(2);
});
