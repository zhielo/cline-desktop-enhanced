import { describe, expect, it } from "vitest";
import {
	TARGETED_GHIDRA_SCRIPT,
	targetedIdaScript,
} from "./targeted-decompiler-scripts";
import { ReverseEngineeringInputSchema } from "../schemas";
import { AnalysisNotebookSchema } from "./analysis-notebook";
describe("bounded targeted decompiler contracts", () => {
	it("requires exactly one symbol or hex entry address", () => {
		for (const selector of [
			{},
			{ symbol: "x", address: "0x10" },
			{ address: "not-an-address" },
			{ symbol: "" },
		])
			expect(
				ReverseEngineeringInputSchema.safeParse({
					operation: "decompile",
					function_selector: selector,
				}).success,
			).toBe(false);
		expect(
			ReverseEngineeringInputSchema.parse({
				operation: "decompile",
				function_selector: { address: "0x4000c0" },
			}).function_selector?.address,
		).toBe("0x4000c0");
	});
	it("does not silently choose nearby or duplicate functions", () => {
		expect(TARGETED_GHIDRA_SCRIPT).toContain("getFunctionAt");
		expect(TARGETED_GHIDRA_SCRIPT).toContain("Ambiguous exact function name");
		expect(TARGETED_GHIDRA_SCRIPT).toContain("scanned>100000");
		expect(TARGETED_GHIDRA_SCRIPT).toContain("code.length()>1000000");
		const source = targetedIdaScript("C:\\temp\\selected.c", {
			address: "0x10",
		});
		expect(source).toContain("function.start_ea==address");
		expect(source).toContain("len(matches)!=1");
		expect(source).toContain("idc.qexit(exit_code)");
	});
	it("embeds selector strings as data, not executable source", () => {
		const name = 'x"; import os; #';
		const source = targetedIdaScript("/owned/output.c", { symbol: name });
		const line = source.split("\n").find((x) => x.startsWith("SELECTOR = "));
		expect(JSON.parse(line!.slice("SELECTOR = ".length))).toEqual({
			symbol: name,
		});
	});
	it("allows only static targeted actions in confined notebooks", () => {
		const document = {
			schemaVersion: 1,
			title: "Owned static work",
			cells: [
				{
					id: "native",
					action: "native_function",
					target: "owned.so",
					options: { function: { symbol: "Java_Fixture_native_1work" } },
				},
			],
		};
		expect(AnalysisNotebookSchema.safeParse(document).success).toBe(true);
		expect(
			AnalysisNotebookSchema.safeParse({
				...document,
				cells: [
					{ id: "runtime", action: "trace_native_region", target: "owned.so" },
				],
			}).success,
		).toBe(false);
	});
});

it("checks the loaded processor decompiler before expensive auto-analysis and marks selected decompilation", () => {
  const script = targetedIdaScript("/owned/result.c",{address:"0x1000"});
  expect(script.indexOf("init_hexrays_plugin()")).toBeLessThan(script.indexOf("ida_auto.auto_wait()"));
  expect(script).toContain('cline_phase("decompilation-started")');
  expect(script).toContain("loaded processor");
  for (const value of [0,-1,999,3600001])
    expect(ReverseEngineeringInputSchema.safeParse({operation:"decompile",ida_phase_timeout_ms:value}).success).toBe(false);
  expect(ReverseEngineeringInputSchema.parse({operation:"decompile",ida_phase_timeout_ms:60000}).ida_phase_timeout_ms).toBe(60000);
});
