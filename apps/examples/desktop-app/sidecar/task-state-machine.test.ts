import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	advanceDurableTaskState,
	beginDurableTaskValidation,
	type DurableTaskStep,
	persistDurableTaskState,
	readDurableTaskState,
	readOrMigrateDurableTaskState,
	recordDurableTaskValidation,
	rollbackDurableTaskState,
} from "./task-state-machine";

const previousSessionDataDir = process.env.CLINE_SESSION_DATA_DIR;
let sessionDataDir: string | undefined;

afterEach(() => {
	if (sessionDataDir) rmSync(sessionDataDir, { recursive: true, force: true });
	sessionDataDir = undefined;
	if (previousSessionDataDir === undefined) {
		delete process.env.CLINE_SESSION_DATA_DIR;
	} else {
		process.env.CLINE_SESSION_DATA_DIR = previousSessionDataDir;
	}
});

const steps = (statuses: Array<DurableTaskStep["status"]>): DurableTaskStep[] =>
	statuses.map((status, index) => ({
		id: `step-${index + 1}`,
		label: `Step ${index + 1}`,
		status,
		kind: index === 1 ? "verification" : "work",
	}));

describe("advanceDurableTaskState", () => {
	it("persists canonical transitions and active step identity", () => {
		const planned = advanceDurableTaskState({
			planId: "plan-1",
			steps: steps(["pending", "pending"]),
			atMs: 10,
		});
		const running = advanceDurableTaskState({
			planId: "plan-1",
			steps: steps(["in_progress", "pending"]),
			previous: planned,
			atMs: 20,
		});
		expect(running.status).toBe("running");
		expect(running.activeStepId).toBe("step-1");
		expect(running.transitions).toEqual([
			{ to: "planned", atMs: 10, reason: "plan.updated" },
			{ from: "planned", to: "running", atMs: 20, reason: "plan.updated" },
		]);
	});

	it("rejects multiple active steps", () => {
		expect(() =>
			advanceDurableTaskState({
				planId: "plan-1",
				steps: steps(["in_progress", "in_progress"]),
			}),
		).toThrow("Only one task step");
	});

	it("blocks work advancement after failure until repair or verification completes", () => {
		const failedThenAdvanced: DurableTaskStep[] = [
			{ id: "build", label: "Build", status: "failed", kind: "work" },
			{ id: "ship", label: "Ship", status: "in_progress", kind: "work" },
		];
		expect(() =>
			advanceDurableTaskState({
				planId: "plan-1",
				steps: failedThenAdvanced,
			}),
		).toThrow("cannot advance past a failed step");

		const failed = advanceDurableTaskState({
			planId: "plan-1",
			steps: [failedThenAdvanced[0]],
		});
		const repaired: DurableTaskStep[] = [
			failedThenAdvanced[0],
			{ id: "repair", label: "Repair", status: "completed", kind: "repair" },
			failedThenAdvanced[1],
		];
		expect(
			advanceDurableTaskState({
				planId: "plan-1",
				steps: repaired,
				previous: failed,
			}).status,
		).toBe("running");
	});

	it("rejects a completed plan regressing to running", () => {
		const completed = advanceDurableTaskState({
			planId: "plan-1",
			steps: steps(["completed", "completed"]),
		});
		expect(() =>
			advanceDurableTaskState({
				planId: "plan-1",
				steps: steps(["in_progress", "pending"]),
				previous: completed,
			}),
		).toThrow("completed -> running");
	});

	it("requires a reason for every skipped step", () => {
		expect(() =>
			advanceDurableTaskState({
				planId: "plan-1",
				steps: steps(["skipped"]),
			}),
		).toThrow("requires a reason");
		expect(
			advanceDurableTaskState({
				planId: "plan-1",
				steps: [{ ...steps(["skipped"])[0], skipReason: "Not applicable" }],
			}).status,
		).toBe("skipped");
	});

	it("records automatic validation and blocks completion on failure", () => {
		const completed = advanceDurableTaskState({
			planId: "plan-1",
			steps: [
				{
					...steps(["completed"])[0],
					validationCommands: ["bun test", "bun run typecheck"],
				},
			],
		});
		const validating = beginDurableTaskValidation({
			state: completed,
			stepId: "step-1",
			atMs: 20,
		});
		expect(validating.status).toBe("verifying");
		const running = recordDurableTaskValidation({
			state: validating,
			stepId: "step-1",
			command: "bun test",
			status: "running",
			atMs: 21,
		});
		const failed = recordDurableTaskValidation({
			state: running,
			stepId: "step-1",
			command: "bun test",
			status: "failed",
			exitCode: 1,
			atMs: 22,
		});
		expect(failed.status).toBe("failed");
		expect(failed.repair?.state).toBe("repair_required");
	});

	it("rewinds task progress at and after a restored checkpoint", () => {
		const completed = advanceDurableTaskState({
			planId: "plan-1",
			steps: [
				{ ...steps(["completed"])[0], checkpointRunCount: 1 },
				{
					...steps(["completed", "completed"])[1],
					checkpointRunCount: 2,
				},
			],
			atMs: 10,
		});
		const rolledBack = rollbackDurableTaskState({
			state: completed,
			checkpointRunCount: 2,
			atMs: 20,
		});
		expect(rolledBack.steps.map((step) => step.status)).toEqual([
			"completed",
			"pending",
		]);
		expect(rolledBack.status).toBe("planned");
		expect(rolledBack.rollback).toMatchObject({ checkpointRunCount: 2 });
	});

	it("persists and reloads task state independently from chat projection", () => {
		sessionDataDir = mkdtempSync(join(tmpdir(), "cline-task-state-"));
		process.env.CLINE_SESSION_DATA_DIR = sessionDataDir;
		const state = advanceDurableTaskState({
			planId: "plan-1",
			steps: [
				{
					id: "implement",
					label: "Implement durable state",
					status: "in_progress",
					kind: "work",
					acceptanceCriteria: ["State reloads after restart"],
					validationCommands: ["bun test"],
					ownerAgentId: "agent-1",
					worktree: "C:/worktrees/task-1",
					artifacts: ["report.json"],
					startedAtMs: 100,
					repairAttempt: 0,
					maxRepairAttempts: 3,
				},
			],
			atMs: 100,
		});
		persistDurableTaskState("session-1", state);
		expect(readDurableTaskState("session-1")).toEqual(state);
	});

	it("migrates the latest projected task report once", () => {
		sessionDataDir = mkdtempSync(join(tmpdir(), "cline-task-state-"));
		process.env.CLINE_SESSION_DATA_DIR = sessionDataDir;
		const migrated = readOrMigrateDurableTaskState("legacy-session", [
			{
				role: "tool",
				meta: {
					taskEvent: {
						type: "plan.updated",
						planId: "legacy-plan",
						updatedAtMs: 123,
						steps: [
							{
								id: "legacy-step",
								label: "Legacy projected work",
								status: "in_progress",
								kind: "work",
							},
						],
					},
				},
			},
		]);
		expect(migrated).toMatchObject({
			planId: "legacy-plan",
			status: "running",
			transitions: [{ reason: "migration.projected-report" }],
		});
		expect(readDurableTaskState("legacy-session")).toEqual(migrated);
	});
});
