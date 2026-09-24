import { describe, expect, it } from "vitest";
import type { ChatMessage } from "@/lib/chat-schema";
import { buildSessionTaskReport } from "@/lib/task-report";

function toolMessage(
	id: string,
	toolName: string,
	input: unknown,
	options?: { isError?: boolean },
): ChatMessage {
	return {
		id,
		sessionId: "session-1",
		role: "tool",
		content: JSON.stringify({
			toolName,
			input,
			result: options?.isError ? "failed" : { ok: true },
			isError: options?.isError ?? false,
		}),
		createdAt: Number(id.replace(/\D/g, "")) || 1,
		meta: { toolName },
	};
}

describe("buildSessionTaskReport", () => {
	it("projects the newest Codex update_plan call", () => {
		const report = buildSessionTaskReport([
			toolMessage("tool-1", "update_plan", {
				explanation: "Implement and verify the desktop panel.",
				plan: [
					{ step: "Inspect the desktop flow", status: "completed" },
					{ step: "Build the report panel", status: "inProgress" },
					{ step: "Run focused tests", status: "pending" },
				],
			}),
		]);

		expect(report?.explanation).toBe(
			"Implement and verify the desktop panel.",
		);
		expect(report?.steps.map((step) => step.status)).toEqual([
			"completed",
			"in_progress",
			"pending",
		]);
	});

	it("supports Cline todo-list field names and operational states", () => {
		const report = buildSessionTaskReport([
			toolMessage("tool-2", "update_todo_list", {
				todos: [
					{ content: "Wait for approval", status: "waiting_for_user" },
					{ content: "Fix failing tests", status: "blocked" },
				],
			}),
		]);

		expect(report?.steps.map((step) => step.status)).toEqual([
			"waiting_for_user",
			"blocked",
		]);
	});

	it("enforces a single active step in the UI projection", () => {
		const report = buildSessionTaskReport([
			toolMessage("tool-3", "update_plan", {
				plan: [
					{ step: "First", status: "in_progress" },
					{ step: "Second", status: "running" },
				],
			}),
		]);

		expect(report?.steps.map((step) => step.status)).toEqual([
			"in_progress",
			"pending",
		]);
	});

	it("ignores failed and malformed updates", () => {
		const valid = toolMessage("tool-4", "update_plan", {
			plan: [{ step: "Keep this report", status: "pending" }],
		});
		const report = buildSessionTaskReport([
			valid,
			toolMessage(
				"tool-5",
				"update_plan",
				{ plan: [{ step: "Broken", status: "pending" }] },
				{ isError: true },
			),
			{
				...valid,
				id: "tool-6",
				content: "not json",
			},
		]);

		expect(report?.sourceMessageId).toBe("tool-4");
	});
});
