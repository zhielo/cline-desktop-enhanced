import { describe, it, expect } from "bun:test";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, isAbsolute } from "node:path";
import { runAdvancedAnalysis } from "../src/extensions/tools/executors/advanced-analysis";
const python = process.env.CLINE_RE_PYTHON;
if (!python || !isAbsolute(python))
	throw new Error(
		"A reviewed absolute Python with real Z3 is required; this corpus never skips",
	);
function fixture() {
	const x = {
		id: "x",
		space: "register",
		offsetHex: "0",
		bytes: 4,
		constant: false,
	};
	const zero = {
		id: "zero",
		space: "unique",
		offsetHex: "1",
		bytes: 4,
		constant: false,
	};
	const constant = {
		id: "constant0",
		space: "const",
		offsetHex: "0",
		bytes: 4,
		constant: true,
	};
	const cond = {
		id: "cond",
		space: "unique",
		offsetHex: "2",
		bytes: 1,
		constant: false,
	};
	return {
		schemaVersion: 1,
		producer: "ghidra-high-pcode",
		engineVersion: "owned-model-fixture",
		language: "x86:LE:64:default",
		functions: [
			{
				name: "owned",
				entry: "1000",
				entryBlock: "b0",
				status: "recovered",
				pseudocode: "",
				pseudocodeTruncated: false,
				blocks: [{ id: "b0", start: "1000", stop: "1005", successors: [] }],
				pcode: [
					{
						id: "xor",
						address: "1000",
						block: "b0",
						opcode: "INT_XOR",
						output: zero,
						inputs: [x, x],
					},
					{
						id: "equal",
						address: "1002",
						block: "b0",
						opcode: "INT_EQUAL",
						output: cond,
						inputs: [zero, constant],
					},
					{
						id: "branch",
						address: "1004",
						block: "b0",
						opcode: "CBRANCH",
						output: null,
						inputs: [
							{
								id: "target",
								space: "const",
								offsetHex: "1000",
								bytes: 8,
								constant: true,
							},
							cond,
						],
					},
				],
			},
		],
		coverage: {
			consideredFunctions: 1,
			failedFunctions: 0,
			pcodeOperations: 3,
			truncated: false,
			externalAndThunkFunctionsExcluded: true,
		},
	};
}
async function execute(value: unknown) {
	const directory = await mkdtemp(join(tmpdir(), "cline-semantic-corpus-"));
	try {
		const path = join(directory, "program.json");
		await writeFile(path, JSON.stringify(value));
		return await runAdvancedAnalysis({
			action: "native_semantics",
			target: path,
			limit: 8,
			timeoutMs: 10000,
		});
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
}
describe("real Z3 through the fixed p-code SDK worker", () => {
	it("proves x xor x is zero and the modeled branch is always taken", async () => {
		const result = await execute(fixture());
		expect(result.status).toBe("partial");
		expect(result.engine).toBe("z3-pcode");
		expect(result.engineVersion).toBe("5.1.0.0");
		const proofs = result.evidence.proofs as Array<{
			operation: string;
			constantHex?: string;
			equivalence: string;
		}>;
		expect(proofs.find((p) => p.operation === "xor")?.constantHex).toBe("0x0");
		expect(proofs.find((p) => p.operation === "xor")?.equivalence).toBe(
			"model-equivalent",
		);
		expect(
			(result.evidence.branches as Array<{ direction: string }>)[0].direction,
		).toBe("always-taken");
		expect(result.limitations.join(" ")).toContain("not native");
	});
	it("does not claim a memory load is a known constant", async () => {
		const value = fixture();
		value.functions[0].pcode[0].opcode = "LOAD";
		const result = await execute(value);
		expect(result.status).toBe("partial");
		const proof = (
			result.evidence.proofs as Array<{
				operation: string;
				constantHex?: string;
				assumptions: string[];
			}>
		).find((p) => p.operation === "xor")!;
		expect(proof.constantHex).toBeUndefined();
		expect(proof.assumptions).toContain("unmodeled-opcode");
	});
	it("rejects duplicate SSA output definitions before execution", async () => {
		const value = fixture();
		value.functions[0].pcode[1].output = value.functions[0].pcode[0].output;
		await expect(execute(value)).rejects.toThrow();
	});
});
