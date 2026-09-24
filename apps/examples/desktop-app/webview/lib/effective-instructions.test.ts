import { describe, expect, it } from "vitest";
import {
	buildEffectiveInstructionSources,
	redactInstructionText,
} from "./effective-instructions";

describe("effective instructions", () => {
	it("labels session, repository, skill, MCP, and tool sources", () => {
		const sources = buildEffectiveInstructionSources({
			systemPrompt: "Be concise",
			rules: "Run tests",
			workspaceRoot: "/repo",
			inventory: {
				rules: [
					{
						name: "AGENTS.md",
						path: "/repo/AGENTS.md",
						instructions: "Follow conventions",
					},
				],
				skills: [
					{
						name: "review",
						enabled: true,
						path: "/repo/.agents/skills/review/SKILL.md",
					},
				],
				mcp: {
					servers: [
						{ name: "github", disabled: false, transportType: "stdio" },
					],
				},
				tools: [
					{ id: "patch", name: "Patch", enabled: true, source: "builtin" },
				],
			},
		});
		expect(sources.map((source) => source.kind)).toEqual([
			"session",
			"session",
			"repository",
			"skill",
			"mcp",
			"tool",
		]);
	});

	it("redacts common secrets before rendering instruction text", () => {
		expect(redactInstructionText("api_key=abc123 Bearer token.value")).toBe(
			"api_key=[REDACTED] Bearer [REDACTED]",
		);
	});

	it("omits disabled skills, MCP servers, and tools", () => {
		const sources = buildEffectiveInstructionSources({
			inventory: {
				skills: [{ name: "off", enabled: false }],
				mcp: { servers: [{ name: "off", disabled: true }] },
				tools: [{ name: "off", enabled: false }],
			},
		});
		expect(sources).toEqual([]);
	});
});
