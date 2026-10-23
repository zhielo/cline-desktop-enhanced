import { mkdtempSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, it, expect, vi } from "vitest";
import type { SidecarContext, LiveSession } from "./types";
import type { ModelTriagePorts } from "./model-binary-triage";
const state = vi.hoisted(() => ({
	mode: "static",
	workspace: "",
	ports: undefined as ModelTriagePorts | undefined,
}));
vi.mock("./first-party-analysis", async () => ({
	...(await vi.importActual("./first-party-analysis")),
	firstPartyStore: () => ({
		session: () => ({ mode: state.mode, workspace: state.workspace }),
	}),
}));
vi.mock("./model-binary-triage", () => ({
	runModelBinaryTriage: async (_raw: unknown, ports: ModelTriagePorts) => {
		state.ports = ports;
		ports.assertCurrent(true);
		return "host-gated";
	},
}));
import { executeModelBinaryTriage, handleCommand } from "./commands";
let root: string, ctx: SidecarContext, live: LiveSession;
beforeEach(() => {
	root = mkdtempSync(join(tmpdir(), "triage-host-guard-"));
	state.workspace = realpathSync(root);
	state.mode = "static";
	state.ports = undefined;
	live = {
		config: { permissionProfile: "full-access", workspaceRoot: root },
		messages: [],
		promptsInQueue: [],
		busy: true,
		startedAt: Date.now(),
		status: "running",
	};
	ctx = {
		activeEnvironmentId: "local",
		localWorkspaceRoot: root,
		liveSessions: new Map([["owner", live]]),
		runtimeBindings: new Map([
			[
				"local",
				{
					kind: "local",
					sessionManager: {
						get: async (id: string) =>
							id === "owner" ? { workspaceRoot: root } : undefined,
					},
				},
			],
		]),
	} as unknown as SidecarContext;
});
afterEach(() => rmSync(root, { recursive: true, force: true }));
const toolContext = {
	sessionId: "owner",
	agentId: "lead",
	iteration: 0,
	toolCallId: "call",
};
it("allows the actual busy owning task but not a restricted, missing or switching session", async () => {
	expect(
		await executeModelBinaryTriage(ctx, {}, toolContext, async () => true),
	).toBe("host-gated");
	live.config.permissionProfile = "read-only";
	await expect(
		executeModelBinaryTriage(ctx, {}, toolContext, async () => true),
	).rejects.toThrow("Full Access");
	live.config.permissionProfile = "full-access";
	live.transitioningProvider = true;
	await expect(
		executeModelBinaryTriage(ctx, {}, toolContext, async () => true),
	).rejects.toThrow("session");
	ctx.liveSessions.clear();
	await expect(
		executeModelBinaryTriage(ctx, {}, toolContext, async () => true),
	).rejects.toThrow("session");
});
it("rejects Off/runtime modes and invalidates the captured scope after mode/profile/session drift", async () => {
	for (const mode of ["off", "runtime"]) {
		state.mode = mode;
		await expect(
			executeModelBinaryTriage(ctx, {}, toolContext, async () => true),
		).rejects.toThrow("Static or Hybrid");
	}
	state.mode = "static";
	await executeModelBinaryTriage(ctx, {}, toolContext, async () => true);
	const ports = state.ports!;
	state.mode = "hybrid";
	expect(() => ports.assertCurrent(true)).toThrow("unchanged");
	// Saved reads do not need Analysis enabled, but still require the owning attached profile.
	state.mode = "off";
	expect(() => ports.assertCurrent(false)).not.toThrow();
	live.config.permissionProfile = "read-only";
	expect(() => ports.assertCurrent(false)).toThrow("Full Access");
	live.config.permissionProfile = "full-access";
	ctx.liveSessions.set("owner", { ...live });
	expect(() => ports.assertCurrent(false)).toThrow("session");
});
it("rejects absent or remote tool ownership and does not open the manual RPC to models", async () => {
	await expect(
		executeModelBinaryTriage(
			ctx,
			{},
			{ ...toolContext, toolCallId: undefined },
			async () => true,
		),
	).rejects.toThrow("context");
	ctx.runtimeBindings.set("local", {
		kind: "ssh",
		sessionManager: { get: async () => ({ workspaceRoot: root }) },
	} as never);
	await expect(
		executeModelBinaryTriage(ctx, {}, toolContext, async () => true),
	).rejects.toThrow("local model session");
	ctx.runtimeBindings.set("local", {
		kind: "local",
		sessionManager: { get: async () => ({ workspaceRoot: root }) },
	} as never);
	await expect(
		handleCommand(ctx, "binary_triage_run", {
			environmentId: "local",
			sessionId: "owner",
			confirmed: true,
		}),
	).rejects.toThrow("trusted desktop");
});
