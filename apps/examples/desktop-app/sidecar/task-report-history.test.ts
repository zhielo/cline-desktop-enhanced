import { describe, it, expect } from "vitest";
import {
	decorateTaskReportEvents,
	restoreTaskReportEvents,
} from "./task-report-history";
import { hostToolObservation } from "../shared/task-observation";
const row = {
	sessionId: "s1",
	role: "tool",
	meta: { toolCallId: "t1", toolName: "analyze" },
	content: "existing",
};
const end = {
	type: "tool.completed",
	toolCallId: "t1",
	observation: hostToolObservation({
		sessionId: "s1",
		toolCallId: "t1",
		toolName: "analyze",
		now: 20,
	}),
};
const line = (event: unknown, name = "analyze", id = "t1") =>
	JSON.stringify({
		stream: "chat_tool_call_end",
		chunk: JSON.stringify({ toolCallId: id, toolName: name, taskEvent: event }),
	});
describe("bounded task report history restoration", () => {
	it("decorates only existing exact-session tool rows without creating turns", () => {
		const result = decorateTaskReportEvents(
			"s1",
			[row, { ...row, sessionId: "other" }],
			[line(end)],
		);
		expect(result).toHaveLength(2);
		expect(result[0].content).toBe("existing");
		expect((result[0].meta as any).taskEvent.type).toBe("tool.completed");
		expect(result[1]).toEqual({ ...row, sessionId: "other" });
		expect(
			decorateTaskReportEvents("s1", [row], [line(end, "wrong")])[0],
		).toEqual(row);
	});
	it("does not regress terminal receipts on duplicate starts", () => {
		const start = { ...end, type: "tool.started" };
		const result = decorateTaskReportEvents(
			"s1",
			[row],
			[line(end), line(start)],
		);
		expect((result[0].meta as any).taskEvent.type).toBe("tool.completed");
	});
	it("ignores malformed, oversized, wrong-session and unproven tool events", () => {
		const invalid = { ...end, observation: undefined };
		for (const lines of [
			["bad json"],
			["x".repeat(300000)],
			[line(invalid)],
			[
				line({
					...end,
					observation: { ...end.observation, sessionId: "other" },
				}),
			],
		])
			expect(decorateTaskReportEvents("s1", [row], lines)).toEqual([row]);
	});
	it("restores host checks onto their matching known plan only", () => {
		const planRow = {
			...row,
			meta: { toolCallId: "p1", toolName: "update_plan" },
		};
		const plan = { type: "plan.updated", planId: "plan-1", steps: [] };
		const check = {
			type: "plan.updated",
			planId: "plan-1",
			observation: {
				...end.observation,
				source: "host-validation",
				planId: "plan-1",
				toolCallId: "v1",
				toolName: "task_validation",
			},
		};
		const result = decorateTaskReportEvents(
			"s1",
			[planRow],
			[line(plan, "update_plan", "p1"), line(check, "task_validation", "v1")],
		);
		expect((result[0].meta as any).taskEvent.hostValidations).toHaveLength(1);
	});
	it("does not resolve unsafe filesystem session identifiers", async () => {
		expect(await restoreTaskReportEvents("../../anything", [row])).toEqual([
			row,
		]);
	});
});

it("restores bounded local disk receipts across reads and tolerates missing logs", async () => {
	const { mkdtemp, mkdir, writeFile, rm } = await import("node:fs/promises");
	const { tmpdir } = await import("node:os");
	const { join } = await import("node:path");
	const root = await mkdtemp(join(tmpdir(), "report-history-"));
	const before = process.env.CLINE_KANBAN_DATA_DIR;
	process.env.CLINE_KANBAN_DATA_DIR = root;
	try {
		await mkdir(join(root, "sessions"));
		await writeFile(
			join(root, "sessions", "s1.jsonl"),
			"x".repeat(2 * 1024 * 1024) + "\n" + line(end) + "\n{partial",
		);
		const restored = await restoreTaskReportEvents("s1", [row]);
		expect((restored[0].meta as any).taskEvent.observation.source).toBe(
			"host-tool",
		);
		expect(await restoreTaskReportEvents("s1", [row])).toEqual(restored);
		expect(await restoreTaskReportEvents("missing", [row])).toEqual([row]);
	} finally {
		if (before === undefined) delete process.env.CLINE_KANBAN_DATA_DIR;
		else process.env.CLINE_KANBAN_DATA_DIR = before;
		await rm(root, { recursive: true, force: true });
	}
});
