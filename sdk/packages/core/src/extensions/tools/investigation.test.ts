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
	expect(InvestigationSchemas.capture_network_metadata).toBe(
		InvestigationSchemas.capture_browser_scenario,
	);
	expect(() =>
		InvestigationSchemas.capture_network_metadata.parse({
			action: "start",
			browserSessionId: "11111111-1111-4111-8111-111111111111",
			purpose: "owned",
			confirmRecord: true,
		}),
	).toThrow();
});

it("accepts bounded source and saved-graph reads, not runtime or output authority", () => {
	const base = {
		operation_id: "11111111-1111-4111-8111-111111111111",
		title: "Owned",
		stages: [] as unknown[],
	};
	const parse = (request: unknown) =>
		InvestigationSchemas.plan_batch.parse({
			...base,
			stages: [{ id: "read", request }],
		});
	expect(
		parse({
			operation: "trace_source_symbol",
			target: "owned.ts",
			workflow_query: { symbol: "owned" },
		}),
	).toBeDefined();
	expect(
		parse({
			operation: "advanced_analysis",
			advanced_action: "graph_query",
			target: "saved.json",
			advanced_options: { graph_query: { depth: 2, limit: 20 } },
		}),
	).toBeDefined();
	for (const request of [
		{ operation: "trace_source_symbol", target: "owned.ts" },
		{ operation: "compare_public_api", target: "owned.ts" },
		{ operation: "map_attack_surface", target: "owned.APK" },
		{
			operation: "advanced_analysis",
			advanced_action: "notebook_run",
			target: "saved.json",
		},
		{
			operation: "advanced_analysis",
			advanced_action: "unicorn_emulate",
			target: "saved.bin",
		},
		{
			operation: "advanced_analysis",
			advanced_action: "graph_query",
			target: "saved.json",
			output_file: "new.json",
		},
		{
			operation: "inspect_binary_mitigations",
			target: "owned.exe",
			script_path: "run.py",
		},
		{ operation: "trace_electron_ipc", target: "owned.ts", engine: "ida" },
	])
		expect(() => parse(request)).toThrow();
	expect(() =>
		InvestigationSchemas.run_batch.parse({
			...base,
			continue_independent_reads: true,
		}),
	).toThrow();
});
