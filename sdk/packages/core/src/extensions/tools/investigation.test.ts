import { isHubToolExecutorName } from "@cline/shared";
import { it, expect, vi } from "vitest";
import {
	createInvestigationTools,
	InvestigationSchemas,
} from "./investigation";
import { createDefaultTools } from "./definitions";
import {
	isCoreBuiltinToolAvailable,
	getCoreDefaultEnabledToolIds,
} from "./runtime";
it("tools are host-only, sequential and non-retrying", () => {
	expect(
		createDefaultTools({ executors: {} }).some((t) => t.name === "open_binary"),
	).toBe(false);
	const tools = createInvestigationTools(vi.fn());
	expect(tools.map((t) => t.name)).toEqual(Object.keys(InvestigationSchemas));
	for (const tool of tools) {
		expect(tool.executionMode).toBe("sequential");
		expect(tool.retryable).toBe(false);
		expect(tool.maxRetries).toBe(0);
		expect(isCoreBuiltinToolAvailable(tool.name, "cli")).toBe(false);
		expect(isCoreBuiltinToolAvailable(tool.name, "vscode")).toBe(false);
		expect(getCoreDefaultEnabledToolIds({ mode: "act" })).toContain(tool.name);
	}
});
it("schemas reject cross-session authority and contradictory selectors", () => {
	expect(() =>
		InvestigationSchemas.open_binary.parse({
			target: "owned",
			sessionId: "foreign",
		}),
	).toThrow();
	expect(() =>
		InvestigationSchemas.analyze_function.parse({
			artifactId: "11111111-1111-4111-8111-111111111111",
			engine: "ida",
			selector: { symbol: "f", address: "0x1000" },
		}),
	).toThrow();
	expect(() =>
		InvestigationSchemas.capture_browser_scenario.parse({ action: "start" }),
	).toThrow();
});

it("registers the host executor in the real Hub contribution allowlist", () => {
	expect(isHubToolExecutorName("investigation")).toBe(true);
});

it("disabling reverse engineering also disables host investigation registration", () => {
	expect(
		createDefaultTools({
			executors: { investigation: vi.fn() },
			enableReverseEngineering: false,
		}).some((t) => t.name === "open_binary"),
	).toBe(false);
});

it("network metadata alias shares strict browser schema and rejects self-consent", () => {
 expect(InvestigationSchemas.capture_network_metadata).toBe(InvestigationSchemas.capture_browser_scenario);
 expect(() => InvestigationSchemas.capture_network_metadata.parse({action:"start",browserSessionId:"11111111-1111-4111-8111-111111111111",purpose:"owned",confirmRecord:true})).toThrow();
});
