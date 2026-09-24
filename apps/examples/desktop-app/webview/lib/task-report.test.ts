import { describe, expect, it } from "vitest";
import type { ChatMessage } from "@/lib/chat-schema";
import { buildTaskExecutionReport, reportProgress } from "./task-report";

const message = (overrides: Partial<ChatMessage>): ChatMessage => ({
	id: "message-1",
	sessionId: "session-1",
	role: "user",
	content: "Improve the installer",
	createdAt: 1,
	...overrides,
});

describe("task report", () => {
	it("uses runtime tool results as evidence", () => {
		const report = buildTaskExecutionReport({
			sessionId: "session-1",
			status: "completed",
			messages: [
				message({}),
				message({
					id: "tool-1",
					role: "tool",
					content: JSON.stringify({
						toolName: "run_tests",
						result: "12 passed",
						isError: false,
					}),
					meta: { toolName: "run_tests", hookEventName: "tool_call_end" },
					createdAt: 2,
				}),
				message({
					id: "assistant-1",
					role: "assistant",
					content: "Done",
					createdAt: 3,
				}),
			],
			fileDiffs: [
				{ path: "workflow.yml", additions: 3, deletions: 1, hunks: [] },
			],
		});
		expect(report.evidence[0]).toMatchObject({
			label: "run_tests",
			status: "success",
			type: "test",
		});
		expect(report.changedFiles[0]?.path).toBe("workflow.yml");
		expect(reportProgress(report).percent).toBe(100);
	});

	it("uses the latest assistant checklist as the visible plan", () => {
		const report = buildTaskExecutionReport({
			status: "running",
			messages: [
				message({}),
				message({
					id: "assistant-1",
					role: "assistant",
					content: "- [x] Inspect\n- [ ] Implement\n- [ ] Verify",
					createdAt: 2,
				}),
			],
			fileDiffs: [],
		});
		expect(report.steps.map((step) => step.status)).toEqual([
			"passed",
			"running",
			"pending",
		]);
	});

	it("removes transport markup from the displayed objective", () => {
		const report = buildTaskExecutionReport({
			status: "completed",
			messages: [
				message({
					content: '<user_input mode="yolo">Inspect the project</user_input>',
				}),
			],
			fileDiffs: [],
		});
		expect(report.objective).toBe("Inspect the project");
	});
});
