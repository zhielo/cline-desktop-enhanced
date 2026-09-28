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
	mergeDesktopAiInstructions,
	readDesktopSettings,
	resolveDesktopSettingsPath,
	setCloudSessionsEnabled,
	setComputerUseSettings,
	setCustomAiInstructions,
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
	it("defaults cloud sessions to off when no settings file exists", () => {
		expect(readDesktopSettings()).toEqual({
			cloudSessionsEnabled: false,
			customAiInstructions: "",
			computerUseEnabled: false,
			computerUseAllowedApplications: [],
		});
	});

	it("persists the cloud sessions opt-in and reads it back", () => {
		expect(setCloudSessionsEnabled(true)).toEqual({
			cloudSessionsEnabled: true,
			customAiInstructions: "",
			computerUseEnabled: false,
			computerUseAllowedApplications: [],
		});
		expect(readDesktopSettings()).toEqual({
			cloudSessionsEnabled: true,
			customAiInstructions: "",
			computerUseEnabled: false,
			computerUseAllowedApplications: [],
		});
		expect(resolveDesktopSettingsPath().endsWith("code-settings.json")).toBe(
			true,
		);
		expect(
			JSON.parse(readFileSync(resolveDesktopSettingsPath(), "utf8")),
		).toMatchObject({ cloudSessionsEnabled: true, customAiInstructions: "" });
		expect(setCloudSessionsEnabled(false)).toEqual({
			cloudSessionsEnabled: false,
			customAiInstructions: "",
			computerUseEnabled: false,
			computerUseAllowedApplications: [],
		});
		expect(readDesktopSettings()).toEqual({
			cloudSessionsEnabled: false,
			customAiInstructions: "",
			computerUseEnabled: false,
			computerUseAllowedApplications: [],
		});
	});

	it("treats malformed files and non-boolean values as off", () => {
		mkdirSync(dirname(resolveDesktopSettingsPath()), { recursive: true });
		writeFileSync(resolveDesktopSettingsPath(), "{not json", "utf8");
		expect(readDesktopSettings()).toEqual({
			cloudSessionsEnabled: false,
			customAiInstructions: "",
			computerUseEnabled: false,
			computerUseAllowedApplications: [],
		});
		writeFileSync(
			resolveDesktopSettingsPath(),
			JSON.stringify({ cloudSessionsEnabled: "yes" }),
			"utf8",
		);
		expect(readDesktopSettings()).toEqual({
			cloudSessionsEnabled: false,
			customAiInstructions: "",
			computerUseEnabled: false,
			computerUseAllowedApplications: [],
		});
	});
	it("persists and merges custom AI instructions for every new local session", () => {
		expect(setCustomAiInstructions("  Always run focused tests.  ")).toEqual({
			cloudSessionsEnabled: false,
			customAiInstructions: "Always run focused tests.",
			computerUseEnabled: false,
			computerUseAllowedApplications: [],
		});
		expect(readDesktopSettings().customAiInstructions).toBe(
			"Always run focused tests.",
		);
		expect(mergeDesktopAiInstructions("Keep this session concise.")).toBe(
			"Always run focused tests.\n\nKeep this session concise.",
		);
	});

	it("requires an explicit Windows executable allowlist before enabling computer use", () => {
		expect(() =>
			setComputerUseSettings({ enabled: true, allowedApplications: [] }),
		).toThrow("at least one allowlisted application");
		expect(
			setComputerUseSettings({
				enabled: true,
				allowedApplications: [
					"C:\\Program Files\\Example\\Example.exe",
					"c:/Program Files/Example/Example.exe",
				],
			}),
		).toMatchObject({
			computerUseEnabled: true,
			computerUseAllowedApplications: [
				"C:\\Program Files\\Example\\Example.exe",
			],
		});
		expect(() =>
			setComputerUseSettings({
				enabled: true,
				allowedApplications: ["example.exe"],
			}),
		).toThrow("absolute Windows .exe paths");
	});
});
