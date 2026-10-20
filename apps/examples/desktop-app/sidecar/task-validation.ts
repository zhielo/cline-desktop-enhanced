import { spawn } from "node:child_process";
import type { DurableTaskState } from "./task-state-machine";
import {
	advanceDurableTaskState,
	beginDurableTaskValidation,
	recordDurableTaskValidation,
} from "./task-state-machine";

const DEFAULT_VALIDATION_TIMEOUT_MS = 2 * 60_000;

export type DurableTaskValidationResult = {
	exitCode: number;
	cancelled?: boolean;
	error?: string;
};

export type DurableTaskValidationExecutor = (
	command: string,
	options: { cwd: string; timeoutMs: number; signal?: AbortSignal },
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

/** Cancellation waits for the owned shell/process-tree termination, not just a timer. */
export const executeValidationCommand: DurableTaskValidationExecutor = (
	command,
	options,
) =>
	new Promise((resolve) => {
		if (options.signal?.aborted) {
			resolve({
				exitCode: 130,
				cancelled: true,
				error: "Validation cancelled before launch",
			});
			return;
		}
		const child = spawn(command, {
			cwd: options.cwd,
			shell: true,
			stdio: "ignore",
			windowsHide: true,
			detached: process.platform !== "win32",
		});
		let settled = false;
		let stopResult: DurableTaskValidationResult | undefined;
		let treeStopped: Promise<void> = Promise.resolve();
		const finish = (result: DurableTaskValidationResult) => {
			if (settled) return;
			settled = true;
			clearTimeout(timeout);
			options.signal?.removeEventListener("abort", abort);
			resolve(result);
		};
		const stop = (result: DurableTaskValidationResult) => {
			if (settled || stopResult) return;
			stopResult = result;
			if (child.pid && process.platform === "win32") {
				treeStopped = new Promise<void>((done) => {
					const killer = spawn(
						"taskkill",
						["/pid", String(child.pid), "/t", "/f"],
						{ stdio: "ignore", windowsHide: true },
					);
					killer.once("error", () => {
						child.kill();
						done();
					});
					killer.once("close", () => done());
				});
			} else if (child.pid) {
				try {
					process.kill(-child.pid, "SIGKILL");
				} catch {
					child.kill("SIGKILL");
				}
			} else {
				child.kill("SIGKILL");
			}
		};
		const abort = () =>
			stop({ exitCode: 130, cancelled: true, error: "Validation cancelled" });
		const timeout = setTimeout(
			() =>
				stop({
					exitCode: 124,
					error: `Validation timed out after ${options.timeoutMs}ms`,
				}),
			options.timeoutMs,
		);
		timeout.unref?.();
		child.once("error", () =>
			finish(
				stopResult ?? {
					exitCode: 1,
					error: "Validation command could not start",
				},
			),
		);
		child.once("close", (code, signal) => {
			void treeStopped.then(() =>
				finish(
					stopResult ?? {
						exitCode: code ?? 1,
						...(signal
							? { error: `Validation ended by signal ${signal}` }
							: {}),
					},
				),
			);
		});
		options.signal?.addEventListener("abort", abort, { once: true });
		if (options.signal?.aborted) abort();
	});

function cancelledValidation(
	state: DurableTaskState,
	stepId: string,
	reason: string,
): DurableTaskState {
	return advanceDurableTaskState({
		planId: state.planId,
		previous: state,
		reason: "validation.cancelled:" + stepId,
		steps: state.steps.map((step) =>
			step.id !== stepId
				? step
				: {
						...step,
						status: "cancelled",
						validation: step.validation?.map((check) =>
							check.status === "pending" || check.status === "running"
								? {
										...check,
										status: "cancelled",
										completedAtMs: Date.now(),
										error: reason,
									}
								: check,
						),
					},
		),
	});
}

export async function runDurableTaskValidations(input: {
	state: DurableTaskState;
	stepId: string;
	cwd: string;
	onState: (state: DurableTaskState) => void | Promise<void>;
	execute?: DurableTaskValidationExecutor;
	timeoutMs?: number;
	signal?: AbortSignal;
	authorize?: () => boolean | Promise<boolean>;
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
		if (
			input.signal?.aborted ||
			(input.authorize && !(await input.authorize()))
		) {
			state = cancelledValidation(
				state,
				input.stepId,
				"Validation cancelled or permission withdrawn",
			);
			await input.onState(state);
			return state;
		}
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
			signal: input.signal,
		});
		if (input.signal?.aborted || result.cancelled) {
			state = cancelledValidation(state, input.stepId, "Validation cancelled");
			await input.onState(state);
			return state;
		}
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
