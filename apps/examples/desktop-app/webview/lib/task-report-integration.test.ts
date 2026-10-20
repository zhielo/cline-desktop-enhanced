import { it, expect } from "vitest";
import { readSessionMessages } from "../../sidecar/session-data/messages";

it("projects the installed offline report fixture without acquiring host verification", async () => {
	const { buildSessionTaskReport } = await import("./task-report");
	const { taskReportView } = await import("./task-report-view");
	const { ChatMessageSchema } = await import("./chat-schema");
	const sessionId = "owned-offline-report-integration";
	const messages = [
		{ id: "question", role: "user", content: "Inspect the owned fixture" },
		{
			id: "plan",
			role: "assistant",
			content: [
				{
					type: "tool_use",
					id: "p1",
					name: "update_plan",
					input: {
						steps: [
							{
								id: "owned-recorded-step",
								label: "Owned recorded step",
								status: "completed",
							},
						],
					},
				},
			],
		},
		{
			id: "plan-result",
			role: "user",
			content: [
				{ type: "tool_result", tool_use_id: "p1", content: '{"ok":true}' },
			],
		},
		{
			id: "tool",
			role: "assistant",
			content: [
				{
					type: "tool_use",
					id: "r1",
					name: "read_files",
					input: { paths: ["OWNED_SCROLL_REPORT.md"] },
				},
			],
		},
		{
			id: "tool-result",
			role: "user",
			content: [
				{
					type: "tool_result",
					tool_use_id: "r1",
					content:
						'{"status":"partial","limitations":["Owned offline recorded fixture, not executed"]}',
				},
			],
		},
		{
			id: "artifact",
			role: "assistant",
			content: "Owned report: `./OWNED_SCROLL_REPORT.md`",
		},
	];
	for (const stored of [messages, JSON.parse(JSON.stringify(messages))]) {
		const rows = await readSessionMessages(
			{
				liveSessions: new Map([[sessionId, { messages: stored }]]),
			} as Parameters<typeof readSessionMessages>[0],
			sessionId,
		);
		const report = buildSessionTaskReport(
			rows.map((row) => ChatMessageSchema.parse(row)),
			"idle",
		);
		const view = taskReportView(report, "idle");
		expect(view.outcome).toBe("Partial / unverified");
		expect(view.delivered).toContain(
			"Owned recorded step (plan-marked complete)",
		);
		expect(view.verified).toEqual([]);
        expect(view.artifacts).toContain("./OWNED_SCROLL_REPORT.md");
	}
});
