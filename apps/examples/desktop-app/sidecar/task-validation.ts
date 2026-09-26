import { spawn } from "node:child_process";
import type { DurableTaskState } from "./task-state-machine";
import {
	beginDurableTaskValidation,
	recordDurableTaskValidation,
} from "./task-state-machine";

const DEFAULT_VALIDATION_TIMEOUT_MS = 2 * 60_000;

export type DurableTaskValidationResult = {
	exitCode: number;
	error?: string;
};

export type DurableTaskValidationExecutor = (
	command: string,
	options: { cwd: string; timeoutMs: number },
) => Promise<DurableTaskValidationResult>;

export function validationCandidates(state: DurableTaskState): string[] {
	return state.steps.flatMap((step) =>
		step.status === "completed" &&
		step.validationCommands?.length &&
		!step.validation
			? [step.id]
			: [],
	);
}

export const executeValidationCommand: DurableTaskValidationExecutor = (
	command,
	options,
) =>
	new Promise((resolve) => {
		const child = spawn(command, {
			cwd: options.cwd,
			shell: true,
			stdio: "ignore",
			windowsHide: true,
			detached: process.platform !== "win32",
		});
		let settled = false;
		const finish = (result: DurableTaskValidationResult) => {
			if (settled) return;
			settled = true;
			clearTimeout(timeout);
			resolve(result);
		};
		const timeout = setTimeout(() => {
			if (child.pid && process.platform === "win32") {
				spawn("taskkill", ["/pid", String(child.pid), "/t", "/f"], {
					stdio: "ignore",
					windowsHide: true,
				}).unref();
			} else if (child.pid) {
				try {
					process.kill(-child.pid, "SIGTERM");
				} catch {
					child.kill();
				}
			} else {
				child.kill();
			}
			finish({
				exitCode: 124,
				error: `Validation timed out after ${options.timeoutMs}ms`,
			});
		}, options.timeoutMs);
		timeout.unref?.();
		child.once("error", () =>
			finish({ exitCode: 1, error: "Validation command could not start" }),
		);
		child.once("exit", (code, signal) =>
			finish({
				exitCode: code ?? 1,
				...(signal ? { error: `Validation ended by signal ${signal}` } : {}),
			}),
		);
	});

export async function runDurableTaskValidations(input: {
	state: DurableTaskState;
	stepId: string;
	cwd: string;
	onState: (state: DurableTaskState) => void | Promise<void>;
	execute?: DurableTaskValidationExecutor;
	timeoutMs?: number;
}): Promise<DurableTaskState> {
	const execute = input.execute ?? executeValidationCommand;
	const timeoutMs = input.timeoutMs ?? DEFAULT_VALIDATION_TIMEOUT_MS;
	let state = beginDurableTaskValidation({
		state: input.state,
		stepId: input.stepId,
	});
	await input.onState(state);
	const step = state.steps.find((item) => item.id === input.stepId);
	if (!step?.validationCommands?.length) return state;

	let previousFailed = false;
	for (const command of step.validationCommands) {
		if (previousFailed) {
			state = recordDurableTaskValidation({
				state,
				stepId: input.stepId,
				command,
				status: "skipped",
				error: "Skipped because an earlier validation command failed",
			});
			await input.onState(state);
			continue;
		}
		state = recordDurableTaskValidation({
			state,
			stepId: input.stepId,
			command,
			status: "running",
		});
		await input.onState(state);
		const result = await execute(command, {
			cwd: input.cwd,
			timeoutMs,
		});
		previousFailed = result.exitCode !== 0;
		state = recordDurableTaskValidation({
			state,
			stepId: input.stepId,
			command,
			status: previousFailed ? "failed" : "passed",
			exitCode: result.exitCode,
			error: result.error,
		});
		await input.onState(state);
	}
	return state;
}
