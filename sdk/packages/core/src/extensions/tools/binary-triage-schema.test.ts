import { describe, it, expect } from "vitest";
import {
	BinaryTriageCallSchema,
	BINARY_TRIAGE_OPERATIONS,
} from "./binary-triage-schema";
import { ReverseEngineeringInputSchema } from "./schemas";
import { createReverseEngineeringExecutor } from "./executors/reverse-engineering";
const call = (operation = "inspect_binary") => ({
	operation: "advanced_analysis",
	advanced_action: "binary_triage",
	target: "owned.exe",
	advanced_options: {
		binary_triage: {
			action: "run",
			operation,
			question: "What is this?",
			...(["get_function_disassembly", "find_references"].includes(operation)
				? { address: "0x140001000" }
				: {}),
		},
	},
});
describe("strict desktop binary triage contract", () => {
	it("accepts every fixed operation and disambiguates legacy triage", () => {
		for (const operation of BINARY_TRIAGE_OPERATIONS) {
			expect(BinaryTriageCallSchema.safeParse(call(operation)).success).toBe(
				true,
			);
			expect(
				ReverseEngineeringInputSchema.safeParse(call(operation)).success,
			).toBe(true);
		}
		expect(
			ReverseEngineeringInputSchema.safeParse({
				operation: "advanced_analysis",
				advanced_action: "triage",
				target: "owned.exe",
			}).success,
		).toBe(true);
	});
	it("rejects commands, confirmations, script/rule paths and unrelated options", () => {
		const base = call();
		for (const extra of [
			{ confirmed: true },
			{ sessionId: "spoof" },
			{ script_path: "x.py" },
			{ engine: "ida" },
			{ compare_target: "b" },
			{ operation: "inspect" },
		])
			expect(
				BinaryTriageCallSchema.safeParse({ ...base, ...extra }).success,
			).toBe(false);
		for (const extra of [
			{ command: "!whoami" },
			{ rules: "rules.yar" },
			{ operation: "shell" },
			{ address: "0x1" },
			{ executable: "r2" },
		])
			expect(
				BinaryTriageCallSchema.safeParse({
					...base,
					advanced_options: {
						binary_triage: { ...base.advanced_options.binary_triage, ...extra },
					},
				}).success,
			).toBe(false);
		expect(
			ReverseEngineeringInputSchema.safeParse({
				...base,
				advanced_action: "suite",
			}).success,
		).toBe(false);
	});
	it("saved reads and status never accept a target", () => {
		for (const options of [
			{ action: "status" },
			{
				action: "read",
				receipt_id: "11111111-1111-4111-8111-111111111111",
				limit: 4096,
			},
		]) {
			const x = {
				operation: "advanced_analysis",
				advanced_action: "binary_triage",
				advanced_options: { binary_triage: options },
			};
			expect(BinaryTriageCallSchema.safeParse(x).success).toBe(true);
			expect(
				BinaryTriageCallSchema.safeParse({ ...x, target: "owned.exe" }).success,
			).toBe(false);
		}
	});
	it("headless default never falls back to shell execution", async () => {
		await expect(
			createReverseEngineeringExecutor()(call() as never, {
				agentId: "owned",
				iteration: 0,
			}),
		).rejects.toThrow("owning Cline Desktop host");
	});
});

it("only the dedicated host capability receives binary calls; unrelated operations stay on the original executor", async () => {
	const { createReverseEngineeringTool } = await import("./definitions");
	const { vi } = await import("vitest");
	const ordinary = vi.fn(async () => "ordinary"),
		host = vi.fn(async () => "triage");
	const tool = createReverseEngineeringTool(ordinary, host),
		context = {
			sessionId: "owner",
			agentId: "lead",
			iteration: 0,
			toolCallId: "call",
		};
	expect(await tool.execute(call() as never, context)).toBe("triage");
	expect(ordinary).not.toHaveBeenCalled();
	expect(await tool.execute({ operation: "discover" }, context)).toBe(
		"ordinary",
	);
	expect(host).toHaveBeenCalledTimes(1);
	expect(() =>
		tool.execute({ ...call(), confirmed: true } as never, context),
	).toThrow();
	expect(() =>
		createReverseEngineeringTool(ordinary).execute(call() as never, context),
	).toThrow("host service");
});
