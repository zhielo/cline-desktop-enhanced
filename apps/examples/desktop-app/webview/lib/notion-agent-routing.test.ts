import { describe, expect, it } from "vitest";
import { requestsProjectNotionBridge } from "./notion-agent-routing";

describe("requestsProjectNotionBridge", () => {
	it.each([
		"Use my Notion Agent to analyze this local project.",
		'Send this reverse-engineering report to "Local Project Analyst".',
		"Ask the Notion custom agent to review the repository documentation.",
		"Use agent://workspace/analyst to audit this APK project.",
	])("routes explicit combined project and Notion Agent intent: %s", (prompt) => {
		expect(requestsProjectNotionBridge(prompt)).toBe(true);
	});

	it.each([
		"Analyze this local project.",
		"What is a Notion Agent?",
		"Search Notion for the project roadmap.",
		"Use Cline normally to fix this test.",
	])("does not change ordinary chat routing: %s", (prompt) => {
		expect(requestsProjectNotionBridge(prompt)).toBe(false);
	});
});
