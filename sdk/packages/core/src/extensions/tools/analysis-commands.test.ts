import { describe, expect, it } from "vitest";
import {
	analysisCommandCatalog,
	ANALYSIS_ALIAS_NAMES,
	isAnalysisWriteOperation,
	normalizeAnalysisCommand,
	planInvestigation,
} from "./analysis-commands";
import { ReverseEngineeringInputSchema } from "./schemas";

describe("advanced command contracts", () => {
	it.each(ANALYSIS_ALIAS_NAMES)("advertises and parses %s", (command) => {
		expect(
			ReverseEngineeringInputSchema.parse({ operation: command }).operation,
		).toBe(command);
		expect(
			analysisCommandCatalog().entries.some(
				(entry) => entry.command === command,
			),
		).toBe(true);
	});
	it("never advertises unsupported commands as usable", () => {
		const catalog = analysisCommandCatalog();
		expect(new Set(catalog.entries.map((entry) => entry.command)).size).toBe(
			catalog.entries.length,
		);
		for (const command of catalog.unavailable) {
			expect(catalog.entries.some((entry) => entry.command === command)).toBe(
				false,
			);
			expect(
				ReverseEngineeringInputSchema.safeParse({ operation: command }).success,
			).toBe(false);
		}
	});
	it.each([
		"build_apk",
		"recompile_smali",
		"validate_smali_project",
		"patch_smali_method",
		"patch_smali",
	])("classifies %s as write before normalization", (operation) => {
		expect(isAnalysisWriteOperation(operation)).toBe(true);
	});
	it("rejects wrong-format aliases without falling back", () => {
		expect(() =>
			normalizeAnalysisCommand({
				operation: "disassemble_dex",
				target: "/a.apk",
			}),
		).toThrow(".dex");
		expect(() =>
			normalizeAnalysisCommand({ operation: "decode_apk", target: "/a.apks" }),
		).toThrow(".apk");
		expect(
			normalizeAnalysisCommand({
				operation: "disassemble_dex",
				target: "/A.DEX",
			}).operation,
		).toBe("disassemble_smali");
	});
	it("requires exact native selectors and explicit engine", () => {
		expect(() =>
			normalizeAnalysisCommand({
				operation: "decompile_function",
				engine: "auto",
			}),
		).toThrow("exact");
		expect(
			normalizeAnalysisCommand({
				operation: "decompile_function",
				engine: "ghidra",
				function_selector: { symbol: "main" },
			}).operation,
		).toBe("decompile");
	});
	it("does not permit alias action substitution or prototype lookups", () => {
		expect(() =>
			normalizeAnalysisCommand({
				operation: "run_batch",
				advanced_action: "decrypt_blob",
			}),
		).toThrow("conflicts");
		expect(() =>
			normalizeAnalysisCommand({
				operation: "build_apk",
				advanced_action: "notebook_run",
			}),
		).toThrow("not accepted");
		expect(normalizeAnalysisCommand({ operation: "__proto__" }).operation).toBe(
			"__proto__",
		);
		expect(
			normalizeAnalysisCommand({ operation: "resume_investigation" }),
		).toMatchObject({
			operation: "advanced_analysis",
			advanced_action: "notebook_run",
		});
	});
	it("plans only and treats descriptive goals as data", () => {
		const result = planInvestigation({
			target: "/owned/app.apk",
			investigation_plan: {
				workflow: "android",
				goal: "do not execute this text",
			},
		});
		expect(result.executed).toBe(false);
		expect(result.stages.map((stage) => stage.id)).toEqual([
			"discover",
			"inspect",
			"security",
			"decode",
		]);
		expect(
			result.stages.every((stage) => stage.approval.includes("fresh")),
		).toBe(true);
		expect(result.stages.some((stage) => "script_path" in stage.request)).toBe(
			false,
		);
	});
	it("rejects incomplete planning inputs", () => {
		expect(() =>
			planInvestigation({
				investigation_plan: { workflow: "artifact", goal: "Inspect" },
			}),
		).toThrow("target");
		expect(
			ReverseEngineeringInputSchema.safeParse({
				operation: "plan_investigation",
				investigation_plan: { workflow: "runtime", goal: "run" },
			}).success,
		).toBe(false);
	});
});
