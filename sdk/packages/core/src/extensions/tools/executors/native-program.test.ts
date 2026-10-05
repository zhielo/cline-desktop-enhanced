import { describe, it, expect, vi, afterEach } from "vitest";
import {
	NativeRecoveryOptionsSchema,
	validateNativeProgram,
	nativeProgramFindings,
	nativeEngineEnvironment,
	nativeProgramInvocation,
	recoverNativeProgram,
} from "./native-program";
function doc() {
	return {
		schemaVersion: 1,
		producer: "ghidra-high-pcode",
		engineVersion: "unit-model",
		language: "x86:LE:64:default",
		functions: [
			{
				name: "owned",
				entry: "1000",
				entryBlock: "b0",
				status: "recovered",
				pseudocode: "return 0;",
				pseudocodeTruncated: false,
				blocks: [{ id: "b0", start: "1000", stop: "1005", successors: [] }],
				pcode: [
					{
						id: "op0",
						address: "1000",
						block: "b0",
						opcode: "COPY",
						output: {
							id: "v0",
							space: "unique",
							offsetHex: "1",
							bytes: 4,
							constant: false,
						},
						inputs: [],
					},
				],
			},
		],
		coverage: {
			consideredFunctions: 1,
			failedFunctions: 0,
			pcodeOperations: 1,
			truncated: false,
			externalAndThunkFunctionsExcluded: true,
		},
	};
}
afterEach(() => vi.unstubAllEnvs());
describe("bounded native program evidence", () => {
	it("retains structural evidence without a native equivalence claim", () => {
		expect(
			nativeProgramFindings(validateNativeProgram(doc()))[0].cfg.equivalence,
		).toBe("not-proven");
	});
	it("rejects caller scripts and unbounded options", () => {
		expect(() =>
			NativeRecoveryOptionsSchema.parse({ script: "caller" }),
		).toThrow();
		expect(() =>
			NativeRecoveryOptionsSchema.parse({ maxPcodeOps: 4097 }),
		).toThrow();
	});
	it("rejects duplicate function identities", () => {
		const d = doc();
		d.functions.push(structuredClone(d.functions[0]));
		expect(() => validateNativeProgram(d)).toThrow();
	});
	it("rejects dangling CFG edges", () => {
		const d = doc();
		d.functions[0].blocks[0].successors.push("b99");
		expect(() => validateNativeProgram(d)).toThrow();
	});
	it("rejects invalid recovered entry blocks", () => {
		const d = doc();
		d.functions[0].entryBlock = "b99";
		expect(() => validateNativeProgram(d)).toThrow();
	});
	it("does not guess an unresolved entry block", () => {
		const d = doc();
		(d.functions[0] as unknown as { entryBlock: null }).entryBlock = null;
		expect(
			nativeProgramFindings(validateNativeProgram(d))[0].cfg.omitted,
		).toContain("entry");
	});
	it("rejects duplicate operations and SSA definitions", () => {
		const d = doc();
		d.functions[0].pcode.push(structuredClone(d.functions[0].pcode[0]));
		d.coverage.pcodeOperations++;
		expect(() => validateNativeProgram(d)).toThrow();
		d.functions[0].pcode[1].id = "different";
		expect(() => validateNativeProgram(d)).toThrow();
	});
	it("rejects dangling p-code blocks and false coverage", () => {
		const d = doc();
		d.functions[0].pcode[0].block = "b99";
		expect(() => validateNativeProgram(d)).toThrow();
		d.functions[0].pcode[0].block = "b0";
		d.coverage.pcodeOperations = 0;
		expect(() => validateNativeProgram(d)).toThrow();
	});
	it("rejects oversized evidence", () => {
		expect(() =>
			validateNativeProgram({ ...doc(), extra: "x".repeat(1048576) }),
		).toThrow("byte budget");
	});
	it("withholds inherited JVM injection flags", () => {
		for (const k of [
			"JAVA_TOOL_OPTIONS",
			"_JAVA_OPTIONS",
			"JDK_JAVA_OPTIONS",
			"CLASSPATH",
		])
			vi.stubEnv(k, "owned-unit-value");
		const e = nativeEngineEnvironment();
		for (const k of [
			"JAVA_TOOL_OPTIONS",
			"_JAVA_OPTIONS",
			"JDK_JAVA_OPTIONS",
			"CLASSPATH",
		])
			expect(e[k]).toBeUndefined();
	});
	it("rejects relative engines and batch metacharacters", () => {
		expect(() => nativeProgramInvocation("engine", [])).toThrow("absolute");
		expect(() =>
			nativeProgramInvocation("/reviewed/engine.bat", ["a&b"], "win32"),
		).toThrow("Unsafe");
	});
	it("blocks unavailable engines", async () => {
		expect((await recoverNativeProgram(undefined, "/missing")).status).toBe(
			"blocked",
		);
	});
	it("honors cancellation before reading artifacts", async () => {
		const a = new AbortController();
		a.abort();
		expect(
			(
				await recoverNativeProgram(
					"/reviewed/engine",
					"/missing",
					{},
					1000,
					a.signal,
				)
			).status,
		).toBe("cancelled");
	});
});
