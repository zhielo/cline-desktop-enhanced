import { describe, expect, it } from "vitest";
import type { ChatMessage } from "@/lib/chat-schema";
import { buildSessionTaskReport } from "@/lib/task-report";

function userMessage(id: string, content = "Do the work"): ChatMessage {
	return {
		id,
		sessionId: "session-1",
		role: "user",
		content,
		createdAt: Number(id.replace(/\D/g, "")) || 1,
	};
}

function toolMessage(
	id: string,
	toolName: string,
	input: unknown,
	options?: {
		isError?: boolean;
		result?: unknown;
		toolCallId?: string;
		hookEventName?: string;
	},
): ChatMessage {
	return {
		id,
		sessionId: "session-1",
		role: "tool",
		content: JSON.stringify({
			toolName,
			input,
			result:
				options && "result" in options
					? options.result
					: options?.isError
						? "failed"
						: { ok: true },
			isError: options?.isError ?? false,
		}),
		createdAt: Number(id.replace(/\D/g, "")) || 1,
		meta: {
			toolName,
			toolCallId: options?.toolCallId,
			hookEventName: options?.hookEventName,
		},
	};
}

describe("buildSessionTaskReport", () => {
	it("projects the newest Codex plan with stable progress metadata", () => {
		const report = buildSessionTaskReport(
			[
				userMessage("user-1"),
				toolMessage("tool-2", "update_plan", {
					explanation: "Implement and verify the desktop panel.",
					plan: [
						{
							id: "inspect",
							step: "Inspect the desktop flow",
							status: "completed",
						},
						{
							id: "build",
							step: "Build the report panel",
							status: "inProgress",
						},
						{
							id: "test",
							step: "Run focused tests",
							status: "pending",
							kind: "verification",
						},
					],
				}),
			],
			"running",
		);

		expect(report).toMatchObject({
			mode: "plan",
			explanation: "Implement and verify the desktop panel.",
			activeStepId: "build",
			completedCount: 1,
			progressPercent: 33,
		});
		expect(report?.steps.map((step) => step.status)).toEqual([
			"completed",
			"in_progress",
			"pending",
		]);
		expect(report?.steps[2]?.kind).toBe("verification");
	});

	it("prefers structured step kinds and retains label heuristics as fallback", () => {
		const report = buildSessionTaskReport([
			userMessage("user-1"),
			toolMessage("tool-2", "update_todo_list", {
				todos: [
					{
						id: "a",
						content: "Reconcile generated state",
						status: "pending",
						kind: "repair",
					},
					{ id: "b", content: "Run focused tests", status: "pending" },
				],
			}),
		]);
		expect(report?.steps.map((step) => step.kind)).toEqual([
			"repair",
			"verification",
		]);
	});

	it("enforces one active step and blocks advancement until repair", () => {
		const report = buildSessionTaskReport([
			userMessage("user-1"),
			toolMessage("tool-2", "update_plan", {
				repair_attempt: 2,
				max_repair_attempts: 3,
				plan: [
					{
						id: "tests",
						step: "Run desktop tests",
						status: "failed",
						kind: "verification",
					},
					{ id: "ship", step: "Open the pull request", status: "in_progress" },
					{ id: "extra", step: "Publish artifacts", status: "running" },
				],
			}),
		]);
		expect(report?.steps.slice(1).map((step) => step.status)).toEqual([
			"pending",
			"pending",
		]);
		expect(report?.repair).toMatchObject({
			state: "repair_required",
			failedStepLabel: "Run desktop tests",
			attempt: 2,
			maxAttempts: 3,
		});
	});

	it("uses explicit repair state when supplied by the runtime", () => {
		const report = buildSessionTaskReport([
			userMessage("user-1"),
			toolMessage("tool-2", "update_plan", {
				repair: { state: "verifying", attempt: 1, max_attempts: 2 },
				plan: [
					{
						id: "test",
						step: "Run tests",
						status: "failed",
						kind: "verification",
					},
					{
						id: "repair",
						step: "Correct the regression",
						status: "completed",
						kind: "repair",
					},
					{
						id: "verify",
						step: "Confirm the fix",
						status: "in_progress",
						kind: "verification",
					},
				],
			}),
		]);
		expect(report?.repair).toMatchObject({
			state: "verifying",
			attempt: 1,
			maxAttempts: 2,
		});
	});

	it("attaches deduplicated tool evidence from the current user turn", () => {
		const report = buildSessionTaskReport([
			toolMessage("tool-1", "run_command", { command: "old command" }),
			userMessage("user-2"),
			toolMessage("tool-3", "update_plan", {
				plan: [{ id: "build", step: "Build UI", status: "in_progress" }],
			}),
			toolMessage(
				"tool-4",
				"run_command",
				{ command: "bun test" },
				{
					result: undefined,
					toolCallId: "call-1",
					hookEventName: "tool_call_start",
				},
			),
			toolMessage(
				"tool-5",
				"run_command",
				{ command: "bun test" },
				{
					result: { exitCode: 0 },
					toolCallId: "call-1",
				},
			),
		]);
		expect(report?.evidence).toHaveLength(1);
		expect(report?.evidence[0]).toMatchObject({
			id: "call-1",
			label: "Running a command",
			detail: "bun test",
			status: "completed",
		});
	});

	it("falls back to live task activity when no plan tool is available", () => {
		const report = buildSessionTaskReport(
			[
				userMessage("user-1"),
				toolMessage(
					"tool-2",
					"apply_patch",
					{ path: "src/task-report.ts" },
					{
						result: undefined,
						hookEventName: "tool_call_start",
					},
				),
			],
			"running",
		);
		expect(report).toMatchObject({ mode: "activity", progressPercent: null });
		expect(report?.steps).toEqual([]);
		expect(report?.evidence[0]?.status).toBe("running");
	});

	it("does not leak an older turn's plan into a new user request", () => {
		const report = buildSessionTaskReport([
			userMessage("user-1"),
			toolMessage("tool-2", "update_plan", {
				plan: [{ step: "Old task", status: "completed" }],
			}),
			userMessage("user-3", "Start something else"),
		]);
		expect(report).toBeNull();
	});

	it("ignores failed and malformed plan updates", () => {
		const report = buildSessionTaskReport([
			userMessage("user-1"),
			toolMessage(
				"tool-2",
				"update_plan",
				{
					plan: [{ step: "Broken", status: "pending" }],
				},
				{ isError: true },
			),
			{
				...toolMessage("tool-3", "update_plan", {}),
				content: "not json",
			},
		]);
		expect(report).toBeNull();
	});
});
