import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DesktopComputerUseManager } from "./computer-use-manager";
import { readComputerUseMetrics } from "./computer-use-metrics";
import type { DesktopSettings } from "./desktop-settings";

const EXECUTABLE = "C:\\Program Files\\Example\\Example.exe";
let dataDir: string;

beforeEach(() => {
	dataDir = mkdtempSync(join(tmpdir(), "cline-computer-use-"));
	process.env.CLINE_DATA_DIR = dataDir;
});

afterEach(() => {
	delete process.env.CLINE_DATA_DIR;
	rmSync(dataDir, { recursive: true, force: true });
});

function settings(overrides: Partial<DesktopSettings> = {}): DesktopSettings {
	return {
		cloudSessionsEnabled: false,
		customAiInstructions: "",
		computerUseEnabled: true,
		computerUseAllowedApplications: [EXECUTABLE],
		...overrides,
	};
}

const context = {
	sessionId: "session-1",
	agentId: "agent-1",
	iteration: 1,
};

describe("DesktopComputerUseManager", () => {
	it("requires explicit opt-in and an exact executable allowlist", async () => {
		const runner = vi.fn(async () => ({ pid: 42, foreground: true }));
		const disabled = new DesktopComputerUseManager({
			platform: "win32",
			readSettings: () => settings({ computerUseEnabled: false }),
			runPowerShell: runner,
		});
		await expect(
			disabled.executor(
				{ action: "start", executable: EXECUTABLE, acknowledge_risk: true },
				context,
			),
		).rejects.toThrow("disabled");

		const manager = new DesktopComputerUseManager({
			platform: "win32",
			readSettings: () => settings(),
			runPowerShell: runner,
		});
		await expect(
			manager.executor(
				{
					action: "start",
					executable: "C:\\Windows\\System32\\notepad.exe",
					acknowledge_risk: true,
				},
				context,
			),
		).rejects.toThrow("allowlist");
	});

	it("isolates sessions by owner and supports immediate takeover", async () => {
		const states: unknown[] = [];
		const manager = new DesktopComputerUseManager({
			platform: "win32",
			readSettings: () => settings(),
			runPowerShell: async (payload) =>
				payload.action === "inspect_process"
					? { pid: 42, foreground: true }
					: { ok: true },
			onStateChanged: (items) => states.push(items),
		});
		const started = JSON.parse(
			await manager.executor(
				{ action: "start", executable: EXECUTABLE, acknowledge_risk: true },
				context,
			),
		) as { computerSessionId: string };
		expect(manager.list("session-1")).toHaveLength(1);
		await expect(
			manager.executor(
				{
					action: "key",
					computer_session_id: started.computerSessionId,
					key: "ENTER",
				},
				{ ...context, sessionId: "session-2" },
			),
		).rejects.toThrow("unowned");
		expect(await manager.takeOver("session-1")).toBe(1);
		expect(manager.list()).toHaveLength(0);
		expect(states.length).toBeGreaterThanOrEqual(2);
	});

	it("requires the owner to grant child agents bounded, revocable leases", async () => {
		let now = 1_000;
		const manager = new DesktopComputerUseManager({
			platform: "win32",
			now: () => now,
			readSettings: () => settings(),
			runPowerShell: async (payload) =>
				payload.action === "inspect_process"
					? { pid: 42, foreground: true }
					: { ok: true },
		});
		const childContext = {
			...context,
			agentId: "agent-child",
			snapshot: {
				agentId: "agent-child",
				parentAgentId: "agent-1",
				status: "running" as const,
				iteration: 1,
				messages: [],
				pendingToolCalls: [],
				usage: {
					inputTokens: 0,
					outputTokens: 0,
					totalTokens: 0,
					cacheReadTokens: 0,
					cacheWriteTokens: 0,
				},
			},
		};
		await expect(
			manager.executor(
				{ action: "start", executable: EXECUTABLE, acknowledge_risk: true },
				childContext,
			),
		).rejects.toThrow("cannot start");

		const started = JSON.parse(
			await manager.executor(
				{ action: "start", executable: EXECUTABLE, acknowledge_risk: true },
				context,
			),
		) as { computerSessionId: string };
		await expect(
			manager.executor(
				{
					action: "observe",
					computer_session_id: started.computerSessionId,
					include_screenshot: false,
				},
				childContext,
			),
		).rejects.toThrow("no active");

		await manager.executor(
			{
				action: "delegate",
				computer_session_id: started.computerSessionId,
				target_agent_id: "agent-child",
				duration_ms: 2_000,
				max_actions: 1,
			},
			context,
		);
		await manager.executor(
			{
				action: "observe",
				computer_session_id: started.computerSessionId,
				include_screenshot: false,
			},
			childContext,
		);
		await expect(
			manager.executor(
				{
					action: "key",
					computer_session_id: started.computerSessionId,
					key: "ENTER",
				},
				childContext,
			),
		).rejects.toThrow("no active");

		await manager.executor(
			{
				action: "delegate",
				computer_session_id: started.computerSessionId,
				target_agent_id: "agent-child",
				duration_ms: 2_000,
				max_actions: 2,
			},
			context,
		);
		await manager.executor(
			{
				action: "revoke_delegation",
				computer_session_id: started.computerSessionId,
				target_agent_id: "agent-child",
			},
			context,
		);
		await expect(
			manager.executor(
				{
					action: "observe",
					computer_session_id: started.computerSessionId,
					include_screenshot: false,
				},
				childContext,
			),
		).rejects.toThrow("no active");

		now += 3_000;
		expect(
			JSON.parse(await manager.executor({ action: "list" }, childContext))
				.sessions,
		).toHaveLength(0);
	});

	it("records only aggregate local computer-use metrics", async () => {
		const manager = new DesktopComputerUseManager({
			platform: "win32",
			readSettings: () => settings(),
			runPowerShell: async (payload) =>
				payload.action === "inspect_process"
					? { pid: 42, foreground: true }
					: { ok: true },
		});
		const started = JSON.parse(
			await manager.executor(
				{ action: "start", executable: EXECUTABLE, acknowledge_risk: true },
				context,
			),
		) as { computerSessionId: string };
		await manager.executor(
			{
				action: "click",
				computer_session_id: started.computerSessionId,
				selector: { automation_id: "safe-button" },
				button: "left",
			},
			context,
		);
		await manager.executor(
			{
				action: "scroll",
				computer_session_id: started.computerSessionId,
				delta: -120,
			},
			context,
		);
		await manager.executor(
			{ action: "stop", computer_session_id: started.computerSessionId },
			context,
		);

		const metrics = await readComputerUseMetrics();
		expect(metrics.sessionsStarted).toBe(1);
		expect(metrics.sessionsCompleted).toBe(1);
		expect(metrics.actions).toBe(2);
		expect(metrics.accessibilityActions).toBe(1);
		expect(metrics.coordinateActions).toBe(1);
		const serialized = JSON.stringify(metrics);
		expect(serialized).not.toContain(EXECUTABLE);
		expect(serialized).not.toContain("safe-button");
	});
});
