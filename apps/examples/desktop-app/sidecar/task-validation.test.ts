import { describe, expect, it, vi } from "vitest";
import { advanceDurableTaskState } from "./task-state-machine";
import {
	type DurableTaskValidationExecutor,
	runDurableTaskValidations,
	validationCandidates,
} from "./task-validation";

function completedState() {
	return advanceDurableTaskState({
		planId: "plan-1",
		steps: [
			{
				id: "step-1",
				label: "Implement",
				status: "completed",
				kind: "work",
				validationCommands: ["first", "second"],
			},
		],
	});
}

describe("durable task validation", () => {
	it("runs declared commands sequentially and completes the step", async () => {
		const states: string[] = [];
		const execute = vi.fn<DurableTaskValidationExecutor>(async () => ({
			exitCode: 0,
		}));
		const result = await runDurableTaskValidations({
			state: completedState(),
			stepId: "step-1",
			cwd: "/workspace",
			execute,
			onState(state) {
				states.push(state.status);
			},
		});
		expect(execute.mock.calls.map(([command]) => command)).toEqual([
			"first",
			"second",
		]);
		expect(result.status).toBe("completed");
		expect(result.steps[0]?.validation?.map((item) => item.status)).toEqual([
			"passed",
			"passed",
		]);
		expect(states).toContain("verifying");
	});

	it("stops execution after failure and records later commands as skipped", async () => {
		const execute = vi.fn<DurableTaskValidationExecutor>(async () => ({
			exitCode: 1,
		}));
		const result = await runDurableTaskValidations({
			state: completedState(),
			stepId: "step-1",
			cwd: "/workspace",
			execute,
			onState() {},
		});
		expect(execute).toHaveBeenCalledOnce();
		expect(result.status).toBe("failed");
		expect(result.steps[0]?.validation?.map((item) => item.status)).toEqual([
			"failed",
			"skipped",
		]);
	});

	it("selects only newly completed steps with unexecuted commands", () => {
		expect(validationCandidates(completedState())).toEqual(["step-1"]);
	});
});
