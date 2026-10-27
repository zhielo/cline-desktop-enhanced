import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { ReverseEngineeringInputSchema } from "../schemas";
import { setupCapabilityCatalog } from "../setup-capability-catalog";
import { RE_SPECIALIST_WORKER } from "./re-specialist-worker";
import { buildEvidenceGraph } from "./analysis-evidence-graph";
describe("specialist analysis contracts", () => {
	it("ships exactly the reviewed Python worker", async () => {
		expect(RE_SPECIALIST_WORKER).toBe(
			await readFile(
				new URL("../../../../scripts/re-specialist-worker.py", import.meta.url),
				"utf8",
			),
		);
	});
	it("accepts fixed queries and rejects supplied Scala or missing sinks", () => {
		const input = {
			operation: "advanced_analysis",
			advanced_action: "joern_query",
			advanced_options: {
				joern: {
					language: "java",
					query: "source-sink",
					selector: "readInput",
					sink: "execute",
				},
			},
		};
		expect(ReverseEngineeringInputSchema.safeParse(input).success).toBe(true);
		for (const extra of [{ script: "arbitrary" }, { sink: undefined }])
			expect(
				ReverseEngineeringInputSchema.safeParse({
					...input,
					advanced_options: {
						joern: { ...input.advanced_options.joern, ...extra },
					},
				}).success,
			).toBe(false);
	});
	it("bounds symbolic options and excludes supplied programs", () => {
		const input = {
			operation: "advanced_analysis",
			advanced_action: "angr_symbolic",
			advanced_options: { symbolic: { find: 0x100006 } },
		};
		expect(ReverseEngineeringInputSchema.safeParse(input).success).toBe(true);
		for (const options of [
			{ find: 0x200000 },
			{ find: 0x100006, max_states: 1000 },
			{ find: 0x100006, register: "rip" },
			{ find: 0x100006, minimum: 10, maximum: 0 },
			{ find: 0x100006, script: "arbitrary" },
		])
			expect(
				ReverseEngineeringInputSchema.safeParse({
					...input,
					advanced_options: { symbolic: options },
				}).success,
			).toBe(false);
	});
	it("preserves the full-pack gate and excludes emulator execution from static tools", () => {
		const c = setupCapabilityCatalog();
		expect(c.engineRoutes).toHaveLength(11);
		for (const id of ["qiling", "unidbg", "rnidbg"]) {
			expect(c.specialistRoutes.find((x) => x.id === id)).toMatchObject({
				availability: "optional-isolated-profile",
				tool: "reverse_engineer",
				operation: "plan_emulation",
				prepareCommand: "prepare_analysis_task",
				runCommand: "run_dynamic_analysis",
			});
		}
		expect(c.targetExecuted).toBe(false);
		expect(c.providerCalls).toBe(0);
		expect(
			ReverseEngineeringInputSchema.safeParse({
				operation: "advanced_analysis",
				advanced_action: "emulate_windows",
			}).success,
		).toBe(false);
	});
	it("retains candidate flow rather than claiming observed execution", () => {
		const graph = buildEvidenceGraph({
			schemaVersion: 1,
			results: [
				{
					protocol: "cline-advanced-analysis/v1",
					status: "partial",
					engine: "joern",
					engineVersion: "owned",
					input: { sha256: "a".repeat(64), bytes: 10, format: "source" },
					evidence: {
						rows: [
							{
								path: [
									{ code: "input()", line: 1 },
									{ code: "send(x)", line: 2 },
								],
							},
						],
					},
					limitations: ["single-file modeled flow"],
				},
			],
		});
		expect(
			graph.edges.some(
				(e) =>
					e.relation === "data-flow-candidate" && e.confidence === "candidate",
			),
		).toBe(true);
	});
});
