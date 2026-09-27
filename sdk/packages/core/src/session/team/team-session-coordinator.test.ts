import { TeamMessageType } from "@cline/shared";
import { describe, expect, it, vi } from "vitest";
import { dispatchTeamEventToBackend } from "./team-session-coordinator";

describe("dispatchTeamEventToBackend", () => {
	it("persists intentionally aborted teammate tasks as cancelled", async () => {
		const invokeOptional = vi.fn(async () => {});
		const error = new DOMException("This operation was aborted", "AbortError");

		await dispatchTeamEventToBackend(
			"root-session",
			{
				type: TeamMessageType.TaskEnd,
				agentId: "teammate-1",
				status: "cancelled",
				error,
				messages: [],
			},
			invokeOptional,
		);

		expect(invokeOptional).toHaveBeenCalledWith(
			"onTeamTaskEnd",
			"root-session",
			"teammate-1",
			"cancelled",
			"[done] aborted",
			undefined,
			[],
		);
	});
	it("routes settled run overlap metadata to persistence", async () => {
		const invokeOptional = vi.fn(async () => {});
		const run = {
			id: "run_00002",
			agentId: "writer-b",
			status: "completed" as const,
			message: "edit shared code",
			priority: 0,
			retryCount: 0,
			maxRetries: 0,
			startedAt: new Date(),
			worktreePath: "/worktrees/writer-b",
			changedFiles: ["src/shared.ts"],
			overlapsWithRunIds: ["run_00001"],
			overlapFiles: ["src/shared.ts"],
		};

		await dispatchTeamEventToBackend(
			"root-session",
			{ type: TeamMessageType.RunCompleted, run },
			invokeOptional,
		);

		expect(invokeOptional).toHaveBeenCalledWith(
			"onTeamRunSettled",
			"root-session",
			run,
		);
	});
});
