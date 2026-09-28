import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DesktopComputerUseManager } from "./computer-use-manager";
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
});
