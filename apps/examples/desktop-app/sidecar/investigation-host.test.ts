import { afterEach, it, expect, vi } from "vitest";
vi.mock("./commands", () => ({
	executeModelInvestigation: async (
		_ctx: unknown,
		name: string,
		_input: unknown,
		_context: unknown,
		review: (details: Record<string, unknown>) => Promise<boolean>,
	) =>
		JSON.stringify({
			approved: await review({
				operation: name,
				independentAnalysisApproval: true,
				requestHash: "owned-hash",
			}),
		}),
}));
import {
	createSidecarContext,
	createSidecarRuntimeCapabilities,
	cancelSidecarToolApprovalsForOwner,
} from "./context";
const context = {
	sessionId: "owned-session",
	agentId: "lead",
	conversationId: "conversation",
	toolCallId: "call",
	iteration: 1,
};
afterEach(() => {
	vi.useRealTimers();
});
function fixture() {
	const ctx = createSidecarContext("/owned");
	const owner = { data: { canApproveTools: true }, send: vi.fn() };
	ctx.wsClients.add(owner);
	const execute =
		createSidecarRuntimeCapabilities(ctx).toolExecutors!.investigation!;
	return { ctx, owner, execute };
}
it("requires a connected human approval surface even with an installed model executor", async () => {
	const { ctx, execute } = fixture();
	ctx.wsClients.clear();
	expect(JSON.parse(await execute("analyze_function", {}, context))).toEqual({
		approved: false,
	});
	expect(ctx.pendingApprovals.size).toBe(0);
});
it("routes independent review to a real owner and clears it on explicit approval", async () => {
	const { ctx, owner, execute } = fixture();
	const result = execute("analyze_function", {}, context);
	await vi.waitFor(() => expect(ctx.pendingApprovals.size).toBe(1));
	const pending = [...ctx.pendingApprovals.values()][0]!;
	expect(pending.owner).toBe(owner);
	expect(pending.item).toMatchObject({
		sessionId: "owned-session",
		toolName: "analyze_function",
		input: { independentAnalysisApproval: true, requestHash: "owned-hash" },
	});
	pending.resolve({ approved: true });
	expect(JSON.parse(await result)).toEqual({ approved: true });
	expect(ctx.pendingApprovals.size).toBe(0);
});
it("aborting a model request clears its pending review without granting consent", async () => {
	const { ctx, execute } = fixture();
	const abort = new AbortController();
	const result = execute(
		"capture_browser_scenario",
		{ action: "start" },
		{ ...context, signal: abort.signal },
	);
	await vi.waitFor(() => expect(ctx.pendingApprovals.size).toBe(1));
	abort.abort();
	expect(JSON.parse(await result)).toEqual({ approved: false });
	expect(ctx.pendingApprovals.size).toBe(0);
});
it("disconnecting the approval owner denies pending review", async () => {
	const { ctx, owner, execute } = fixture();
	const result = execute("analyze_function", {}, context);
	await vi.waitFor(() => expect(ctx.pendingApprovals.size).toBe(1));
	cancelSidecarToolApprovalsForOwner(ctx, owner);
	expect(JSON.parse(await result)).toEqual({ approved: false });
	expect(ctx.pendingApprovals.size).toBe(0);
});
it("review deadline denies and removes the request rather than hanging forever", async () => {
	vi.useFakeTimers();
	const { ctx, execute } = fixture();
	const result = execute("analyze_function", {}, context);
	await vi.waitFor(() => expect(ctx.pendingApprovals.size).toBe(1));
	await vi.advanceTimersByTimeAsync(120001);
	expect(JSON.parse(await result)).toEqual({ approved: false });
	expect(ctx.pendingApprovals.size).toBe(0);
});
