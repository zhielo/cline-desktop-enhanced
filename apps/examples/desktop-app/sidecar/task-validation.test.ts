import { describe, expect, it, vi } from "vitest";
import { advanceDurableTaskState } from "./task-state-machine";
import {
	executeValidationCommand,
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

// These checks use owned fixtures; no user target is executed.
it("never launches a validation after cancellation or permission withdrawal", async () => {
	for (const denied of ["abort", "permission"]) {
		const controller = new AbortController();
		if (denied === "abort") controller.abort();
		const execute = vi.fn<DurableTaskValidationExecutor>(async () => ({
			exitCode: 0,
		}));
		const result = await runDurableTaskValidations({
			state: completedState(),
			stepId: "step-1",
			cwd: "/workspace",
			execute,
			signal: controller.signal,
			authorize: () => denied !== "permission",
			onState() {},
		});
		expect(execute).not.toHaveBeenCalled();
		expect(result.status).toBe("cancelled");
		expect(result.steps[0].validation?.map((c) => c.status)).toEqual([
			"cancelled",
			"cancelled",
		]);
	}
});
it("does not record a late successful executor result as passed after abort", async () => {
	const controller = new AbortController();
	const execute = vi.fn<DurableTaskValidationExecutor>(async () => {
		controller.abort();
		return { exitCode: 0 };
	});
	const result = await runDurableTaskValidations({
		state: completedState(),
		stepId: "step-1",
		cwd: "/workspace",
		execute,
		signal: controller.signal,
		onState() {},
	});
	expect(execute).toHaveBeenCalledOnce();
	expect(result.status).toBe("cancelled");
	expect(result.steps[0].validation?.some((c) => c.status === "passed")).toBe(
		false,
	);
});
it("rechecks authorization before every command", async () => {
	const execute = vi.fn<DurableTaskValidationExecutor>(async () => ({
		exitCode: 0,
	}));
	let approvals = 0;
	const result = await runDurableTaskValidations({
		state: completedState(),
		stepId: "step-1",
		cwd: "/workspace",
		execute,
		authorize: () => ++approvals === 1,
		onState() {},
	});
	expect(execute).toHaveBeenCalledOnce();
	expect(result.status).toBe("cancelled");
});
it("terminates an owned long-running shell on abort", async () => {
	const controller = new AbortController();
	const command = `"${process.execPath}" -e "setInterval(()=>{},1000)"`;
	const pending = executeValidationCommand(command, {
		cwd: process.cwd(),
		timeoutMs: 10000,
		signal: controller.signal,
	});
	setTimeout(() => controller.abort(), 100);
	await expect(pending).resolves.toMatchObject({
		exitCode: 130,
		cancelled: true,
	});
}, 10000);
it("does not spawn for an already aborted signal", async () => {
	const controller = new AbortController();
	controller.abort();
	await expect(
		executeValidationCommand("must-not-run", {
			cwd: process.cwd(),
			timeoutMs: 1000,
			signal: controller.signal,
		}),
	).resolves.toMatchObject({ cancelled: true });
});
