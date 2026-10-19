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
	const script = targetedIdaScript("/owned/result.c", { address: "0x1000" });
	expect(script.indexOf("init_hexrays_plugin()")).toBeLessThan(
		script.indexOf("ida_auto.auto_wait()"),
	);
	expect(script).toContain('cline_phase("decompilation-started")');
	expect(script).toContain("loaded processor");
	for (const value of [0, -1, 999, 3600001])
		expect(
			ReverseEngineeringInputSchema.safeParse({
				operation: "decompile",
				ida_phase_timeout_ms: value,
			}).success,
		).toBe(false);
	expect(
		ReverseEngineeringInputSchema.parse({
			operation: "decompile",
			ida_phase_timeout_ms: 60000,
		}).ida_phase_timeout_ms,
	).toBe(60000);
});

it("executes the generated IDA adapter against API doubles, not a licensed decompiler", async () => {
	const { mkdtemp, writeFile, readFile, rm } = await import("node:fs/promises");
	const { join } = await import("node:path");
	const { tmpdir } = await import("node:os");
	const { execFile } = await import("node:child_process");
	const { promisify } = await import("node:util");
	const { TargetedIdaEvidenceSchema } = await import(
		"./targeted-native-evidence"
	);
	const root = await mkdtemp(join(tmpdir(), "ida-ctree-fixture-"));
	try {
		const output = join(root, "selected.c");
		const script = targetedIdaScript(output, { address: "0x1000" });
		// Python is used for executing fixed generated code against explicit fake APIs.
		const harness = `import sys, types, runpy\nfrom types import SimpleNamespace as N\nfor name in ['ida_auto','ida_funcs','ida_hexrays','ida_loader','ida_ida','ida_nalt','idautils','idc']:\n sys.modules[name]=types.ModuleType(name)\na=sys.modules['ida_auto'];a.auto_wait=lambda:True\nf=sys.modules['ida_funcs'];f.get_func=lambda address:N(start_ea=address)\nh=sys.modules['ida_hexrays'];h.init_hexrays_plugin=lambda:True\nh.CV_FAST=0;h.cot_call=1;h.cot_obj=2\nclass Code:\n body='body'\n def __str__(self):return 'return owned();'\nh.decompile=lambda address:Code()\nclass Visitor:\n def __init__(self,flags):pass\n def apply_to(self,body,parent):\n  self.visit_expr(N(op=1,ea=0x1010,x=N(op=2,obj_ea=0x2000)))\n  self.visit_expr(N(op=1,ea=0xffffffffffffffff,x=N(op=3)))\n  for i in range(200):\n   if self.visit_expr(N(op=1,ea=0x1020+i,x=N(op=3))):break\nh.ctree_visitor_t=Visitor\nl=sys.modules['ida_loader'];l.DBFL_COMP=1;l.save_database=lambda *args:True\nsys.modules['ida_ida'].inf_get_procname=lambda:'metapc'\nsys.modules['ida_nalt'].get_imagebase=lambda:0x400000\nd=sys.modules['idc'];d.BADADDR=0xffffffffffffffff;d.get_func_name=lambda address:'owned';d.get_type=lambda address:'int owned(void)';d.get_idb_path=lambda:'owned.i64'\nd.qexit=lambda code:sys.exit(code)\nrunpy.run_path(sys.argv[1])\n`;
		const scriptPath = join(root, "adapter.py"),
			harnessPath = join(root, "harness.py");
		await writeFile(scriptPath, script);
		await writeFile(harnessPath, harness);
		const progressPath = join(root, "ida-script-progress.jsonl");
		// This owned fixture needs only Python's standard library. Do not import
		// runner/user site packages or PYTHONPATH while starting the fake API host.
		// Keep the child asynchronous so Vitest's worker heartbeat stays live.
		// The deadline is a hang guard, not an adapter performance assertion.
		await promisify(execFile)(
			process.platform === "win32" ? "python" : "python3",
			["-I", "-S", "-u", harnessPath, scriptPath],
			{
				timeout: 30_000,
				maxBuffer: 1024 * 1024,
				windowsHide: true,
				env: { ...process.env, CLINE_IDA_PROGRESS_PATH: progressPath },
			},
		);
		const phases = (await readFile(progressPath, "utf8"))
			.trim()
			.split("\n")
			.map((line) => JSON.parse(line).phase);
		expect(phases).toEqual([
			"input-loaded",
			"decompiler-initialized",
			"auto-analysis-waiting",
			"analysis-complete",
			"decompilation-started",
			"output-written",
			"database-saving",
			"database-saved",
			"script-exiting",
		]);
		const value = TargetedIdaEvidenceSchema.parse(
			JSON.parse(await readFile(output + ".native.json", "utf8")),
		);
		expect(value.callees).toHaveLength(128);
		expect(value.relationsTruncated).toBe(true);
		expect(value.callees[0]).toMatchObject({
			targetAddressHex: "0x2000",
			resolution: "hex-rays-object-candidate",
		});
		expect(value.callees[1]).toMatchObject({
			siteResolution: "function-entry-fallback",
			resolution: "unknown-expression-target",
		});
		expect(value.callees[1]).not.toHaveProperty("targetAddressHex");
		// A supported cancellation boundary attempts only the owned database,
		// exits nonzero, and never produces successful decompiler artifacts.
		const stopPath = join(root, "stop.json");
		await rm(output);
		await rm(output + ".native.json");
		await writeFile(progressPath, "");
		await writeFile(stopPath, '{"stop":true}');
		await expect(
			promisify(execFile)(
				process.platform === "win32" ? "python" : "python3",
				["-I", "-S", "-u", harnessPath, scriptPath],
				{
					timeout: 30_000,
					maxBuffer: 1024 * 1024,
					windowsHide: true,
					env: {
						...process.env,
						CLINE_IDA_PROGRESS_PATH: progressPath,
						CLINE_IDA_STOP_PATH: stopPath,
					},
				},
			),
		).rejects.toMatchObject({ code: 1 });
		const stopped = (await readFile(progressPath, "utf8"))
			.trim()
			.split("\n")
			.map((line) => JSON.parse(line).phase);
		expect(stopped).toContain("database-saved");
		expect(stopped).toContain("script-failed");
		expect(stopped).not.toContain("decompilation-started");
		await expect(readFile(output)).rejects.toMatchObject({ code: "ENOENT" });
	} finally {
		await rm(root, { recursive: true, force: true });
	}
}, 40_000);

it("allows bounded IDA headroom without extending other engine limits", () => {
	expect(
		ReverseEngineeringInputSchema.safeParse({
			operation: "analyze",
			engine: "ida",
			timeout_ms: 4_500_000,
		}).success,
	).toBe(true);
	for (const engine of ["auto", "ghidra", "jadx"])
		expect(
			ReverseEngineeringInputSchema.safeParse({
				operation: "analyze",
				engine,
				timeout_ms: 4_500_000,
			}).success,
		).toBe(false);
	expect(
		ReverseEngineeringInputSchema.safeParse({
			operation: "analyze",
			engine: "ida",
			timeout_ms: 4_500_001,
		}).success,
	).toBe(false);
	expect(
		ReverseEngineeringInputSchema.safeParse({
			operation: "analyze",
			engine: "ida",
			timeout_ms: 60_000,
		}).success,
	).toBe(true);
});
