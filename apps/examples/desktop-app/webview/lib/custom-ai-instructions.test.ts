// @vitest-environment jsdom

import { beforeEach, describe, expect, it } from "vitest";
import {
	CUSTOM_AI_INSTRUCTIONS_STORAGE_KEY,
	readCustomAiInstructions,
	saveCustomAiInstructions,
} from "./custom-ai-instructions";

describe("custom AI instructions", () => {
	beforeEach(() => window.localStorage.clear());

	it("returns empty defaults when nothing is stored", () => {
		expect(readCustomAiInstructions()).toEqual({
			instructions: "",
			rules: "",
		});
	});

	it("persists trimmed instructions and rules", () => {
		expect(
			saveCustomAiInstructions({
				instructions: "  Be concise.  ",
				rules: "  Run tests before finishing.  ",
			}),
		).toEqual({
			instructions: "Be concise.",
			rules: "Run tests before finishing.",
		});
		expect(readCustomAiInstructions()).toEqual({
			instructions: "Be concise.",
			rules: "Run tests before finishing.",
		});
		expect(window.localStorage.getItem(CUSTOM_AI_INSTRUCTIONS_STORAGE_KEY)).toBe(
			'{"instructions":"Be concise.","rules":"Run tests before finishing."}',
		);
	});

	it("ignores malformed stored data", () => {
		window.localStorage.setItem(CUSTOM_AI_INSTRUCTIONS_STORAGE_KEY, "{");
		expect(readCustomAiInstructions()).toEqual({
			instructions: "",
			rules: "",
		});
	});
});