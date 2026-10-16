import { describe, expect, it } from "vitest";
import { buildTaskGraph } from "@/lib/task-graph";
import type { SessionTaskReport } from "@/lib/task-report";

function report(
	input: Partial<SessionTaskReport> = {},
): SessionTaskReport {
	return {
		mode: "plan",
		steps: [],
		evidence: [],
		completedCount: 0,
		progressPercent: null,
		sourceMessageId: "message-1",
		sourceTool: "task_protocol",
		updatedAt: 1,
		...input,
	};
}

describe("buildTaskGraph", () => {
	it("uses explicit step dependencies for branching graphs", () => {
		const graph = buildTaskGraph(
			report({
				steps: [
					{
						id: "inspect",
						label: "Inspect project",
						status: "completed",
						kind: "work",
					},
					{
						id: "build",
						label: "Build project",
						status: "in_progress",
						kind: "work",
						parentStepId: "inspect",
					},
					{
						id: "test",
						label: "Run tests",
						status: "pending",
						kind: "verification",
						parentStepId: "inspect",
					},
				],
			}),
		);

		expect(graph.edges).toEqual([
			{ from: "inspect", to: "build" },
			{ from: "inspect", to: "test" },
		]);
		expect(graph.levels.map((level) => level.map((node) => node.id))).toEqual([
			["inspect"],
			["build", "test"],
		]);
	});

	it("creates a chronological command graph for activity-only turns", () => {
		const graph = buildTaskGraph(
			report({
				mode: "activity",
				evidence: [
					{
						id: "command-2",
						label: "Running tests",
						status: "running",
						toolName: "bash",
						createdAt: 20,
					},
					{
						id: "command-1",
						label: "Running a command",
						status: "completed",
						toolName: "bash",
						detail: "bun test",
						createdAt: 10,
					},
				],
			}),
		);

		expect(graph.nodes.map((node) => node.id)).toEqual([
			"command-1",
			"command-2",
		]);
		expect(graph.edges).toEqual([
			{ from: "command-1", to: "command-2" },
		]);
		expect(graph.nodes[1].status).toBe("in_progress");
	});

	it("falls back to plan order when dependencies are not supplied", () => {
		const graph = buildTaskGraph(
			report({
				steps: [
					{ id: "one", label: "One", status: "pending", kind: "work" },
					{ id: "two", label: "Two", status: "pending", kind: "work" },
				],
			}),
		);

		expect(graph.edges).toEqual([{ from: "one", to: "two" }]);
	});
});
