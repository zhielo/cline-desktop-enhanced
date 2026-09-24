import {
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	DEFAULT_AGENT_INSTRUCTIONS,
	MAX_AGENT_INSTRUCTIONS_LENGTH,
	readDesktopSettings,
	resetAgentInstructions,
	resolveDesktopSettingsPath,
	setAgentInstructions,
	setCloudSessionsEnabled,
} from "./desktop-settings";

let dataDir: string;

beforeEach(() => {
	dataDir = mkdtempSync(join(tmpdir(), "cline-desktop-settings-"));
	process.env.CLINE_DATA_DIR = dataDir;
});

afterEach(() => {
	delete process.env.CLINE_DATA_DIR;
	rmSync(dataDir, { recursive: true, force: true });
});

describe("desktop settings", () => {
	it("provides defaults when no settings file exists", () => {
		expect(readDesktopSettings()).toEqual({
			cloudSessionsEnabled: false,
			agentInstructions: DEFAULT_AGENT_INSTRUCTIONS,
		});
	});

	it("persists the cloud sessions opt-in and reads it back", () => {
		expect(setCloudSessionsEnabled(true)).toEqual({
			cloudSessionsEnabled: true,
			agentInstructions: DEFAULT_AGENT_INSTRUCTIONS,
		});
		expect(readDesktopSettings()).toEqual({
			cloudSessionsEnabled: true,
			agentInstructions: DEFAULT_AGENT_INSTRUCTIONS,
		});
		expect(resolveDesktopSettingsPath().endsWith("code-settings.json")).toBe(
			true,
		);
		expect(
			JSON.parse(readFileSync(resolveDesktopSettingsPath(), "utf8")),
		).toMatchObject({ cloudSessionsEnabled: true });
		expect(setCloudSessionsEnabled(false)).toEqual({
			cloudSessionsEnabled: false,
			agentInstructions: DEFAULT_AGENT_INSTRUCTIONS,
		});
		expect(readDesktopSettings()).toEqual({
			cloudSessionsEnabled: false,
			agentInstructions: DEFAULT_AGENT_INSTRUCTIONS,
		});
	});

	it("persists, clears, and resets editable agent instructions", () => {
		expect(
			setAgentInstructions("  Use concise plans.  ").agentInstructions,
		).toBe("Use concise plans.");
		expect(readDesktopSettings().agentInstructions).toBe("Use concise plans.");
		expect(setAgentInstructions("").agentInstructions).toBe("");
		expect(resetAgentInstructions().agentInstructions).toBe(
			DEFAULT_AGENT_INSTRUCTIONS,
		);
	});

	it("rejects instructions that exceed the persisted limit", () => {
		expect(() =>
			setAgentInstructions("x".repeat(MAX_AGENT_INSTRUCTIONS_LENGTH + 1)),
		).toThrow("agent_instructions must be 20000 characters or fewer");
	});

	it("treats malformed files and non-boolean values as off", () => {
		mkdirSync(dirname(resolveDesktopSettingsPath()), { recursive: true });
		writeFileSync(resolveDesktopSettingsPath(), "{not json", "utf8");
		expect(readDesktopSettings()).toEqual({
			cloudSessionsEnabled: false,
			agentInstructions: DEFAULT_AGENT_INSTRUCTIONS,
		});
		writeFileSync(
			resolveDesktopSettingsPath(),
			JSON.stringify({ cloudSessionsEnabled: "yes" }),
			"utf8",
		);
		expect(readDesktopSettings()).toEqual({
			cloudSessionsEnabled: false,
			agentInstructions: DEFAULT_AGENT_INSTRUCTIONS,
		});
	});
});
