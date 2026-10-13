import { it, expect } from "vitest";
import { decodeIL } from "./il";
import { modelManagedStack } from "./managed-stack";
const run = (hex: string) =>
	modelManagedStack(decodeIL(Buffer.from(hex, "hex")));
it("models Int32 arithmetic, wraparound and local/argument dataflow", () => {
	expect(run("1f141f16582a")).toMatchObject({
		status: "completed",
		returnValue: { kind: "int32", value: 42 },
	});
	expect(run("20ffffff7f17582a")).toMatchObject({
		status: "completed",
		returnValue: { kind: "int32", value: -2147483648 },
	});
	expect(run("020a0617582a")).toMatchObject({
		status: "completed",
		returnValue: {
			kind: "expression",
			operation: "add",
			left: { kind: "argument", index: 0 },
			right: { kind: "int32", value: 1 },
		},
	});
});
it("does not manufacture complete semantics for calls, branches, EH or invalid stack", () => {
	for (const hex of [
		"582a",
		"062a",
		"2b00172a",
		"28010000062a",
		"17172a",
		"1718",
		"fe132a",
		"217fffffffffffffff2a",
	])
		expect(run(hex).status, hex).toBe("partial");
});
