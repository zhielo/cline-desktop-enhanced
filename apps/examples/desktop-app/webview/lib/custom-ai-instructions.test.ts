// @vitest-environment jsdom

import { beforeEach, describe, expect, it } from "vitest";
import {
	CUSTOM_AI_INSTRUCTIONS_STORAGE_KEY,
	readCustomAiInstructions,
	saveCustomAiInstructions,
	resolveCustomAiInstructionDefaults,
} from "./custom-ai-instructions";

describe("custom AI instructions", () => {
	beforeEach(() => window.localStorage.clear());

	it("returns empty defaults when nothing is stored", () => {
		expect(readCustomAiInstructions()).toEqual({
			profile: "standard",
			instructions: "",
			rules: "",
		});
	});

	it("persists trimmed instructions and rules", () => {
		expect(
			saveCustomAiInstructions({
				profile: "standard",
				instructions: "  Be concise.  ",
				rules: "  Run tests before finishing.  ",
			}),
		).toEqual({
			profile: "standard",
			instructions: "Be concise.",
			rules: "Run tests before finishing.",
		});
		expect(readCustomAiInstructions()).toEqual({
			profile: "standard",
			instructions: "Be concise.",
			rules: "Run tests before finishing.",
		});
		expect(window.localStorage.getItem(CUSTOM_AI_INSTRUCTIONS_STORAGE_KEY)).toBe(
			'{"profile":"standard","instructions":"Be concise.","rules":"Run tests before finishing."}',
		);
	});

	it("ignores malformed stored data", () => {
		window.localStorage.setItem(CUSTOM_AI_INSTRUCTIONS_STORAGE_KEY, "{");
		expect(readCustomAiInstructions()).toEqual({
			profile: "standard",
			instructions: "",
			rules: "",
		});
	});

	it("adds the authorized CTF preset to session defaults", () => {
		const resolved = resolveCustomAiInstructionDefaults({
			profile: "ctf",
			instructions: "Focus on the APK.",
			rules: "Keep a command log.",
		});
		expect(resolved.instructions).toContain("authorized private CTF");
		expect(resolved.instructions).toContain("Focus on the APK.");
		expect(resolved.rules).toContain("Do not target unrelated third parties");
		expect(resolved.rules).toContain("Keep a command log.");
	});
});