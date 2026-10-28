import { expect, it, vi } from "vitest";
import type { SidecarContext, SidecarWebSocketClient } from "./types";
const trusted = { data: { canApproveTools: true } } as SidecarWebSocketClient;
function fixture() {
	const live = { config: {} as Record<string, unknown>, environmentId: "local" };
	const command = vi
		.fn()
		.mockResolvedValue({
			ok: true,
			payload: {
				snapshot: {
					sessionId: "owner",
					toolExposure: { status: "unavailable" },
				},
			},
		});
	const ctx = {
		liveSessions: new Map([["owner", live]]),
		sessionEnvironmentIds: new Map(),
		runtimeBindings: new Map([
			["local", { kind: "local", hubClient: { command } }],
		]),
		activeEnvironmentId: "local",
		localWorkspaceRoot: "/workspace",
	} as unknown as SidecarContext;
	return { ctx, command, live };
}
it("requires trusted connection and exact attached ownership before any Hub call", async () => {
	const { handleCommand } = await import("./commands");
	const { ctx, command } = fixture();
	await expect(
		handleCommand(ctx, "session_tool_inventory", { sessionId: "owner" }),
	).rejects.toThrow("trusted desktop");
	await expect(
		handleCommand(
			ctx,
			"session_tool_inventory",
			{ sessionId: "other" },
			{ connection: trusted },
		),
	).rejects.toThrow("attached owning");
	expect(command).not.toHaveBeenCalled();
	await expect(
		handleCommand(
			ctx,
			"session_tool_inventory",
			{ sessionId: "owner" },
			{ connection: trusted },
		),
	).resolves.toMatchObject({ status: "unavailable" });
	expect(command).toHaveBeenCalledExactlyOnceWith(
		"session.get",
		{ includeSnapshot: true, includeToolExposure: true },
		"owner",
	);
});
it("listing is memory-only; remote, mismatched and changed ownership cannot become evidence", async () => {
	const { handleCommand } = await import("./commands");
	const { ctx, command, live } = fixture();
	expect(
		await handleCommand(ctx, "session_tool_inventory_sessions", undefined, {
			connection: trusted,
		}),
	).toEqual({ sessions: [{ sessionId: "owner", local: true }] });
	expect(command).not.toHaveBeenCalled();
	live.environmentId = "ssh";
	expect(
		await handleCommand(
			ctx,
			"session_tool_inventory",
			{ sessionId: "owner" },
			{ connection: trusted },
		),
	).toMatchObject({ status: "unavailable" });
	expect(command).not.toHaveBeenCalled();
	live.environmentId = "local";
 live.config.executionTarget = "cloud";
 expect(await handleCommand(ctx, "session_tool_inventory", {sessionId:"owner"}, {connection:trusted})).toMatchObject({status:"unavailable"});
 expect(command).not.toHaveBeenCalled();
 delete live.config.executionTarget;

	command.mockResolvedValueOnce({
		ok: true,
		payload: {
			snapshot: {
				sessionId: "different",
				toolExposure: { status: "last-request" },
			},
		},
	});
	expect(
		await handleCommand(
			ctx,
			"session_tool_inventory",
			{ sessionId: "owner" },
			{ connection: trusted },
		),
	).toMatchObject({ status: "unavailable" });
	command.mockImplementationOnce(async () => {
		ctx.liveSessions.delete("owner");
		return { ok: true, payload: {} };
	});
	await expect(
		handleCommand(
			ctx,
			"session_tool_inventory",
			{ sessionId: "owner" },
			{ connection: trusted },
		),
	).rejects.toThrow("Owning session changed");
});
