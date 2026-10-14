import { it, expect } from "vitest";
import { TargetedNativeEvidenceSchema } from "./targeted-native-evidence";
const fixture = {
	schemaVersion: 1,
	addressHex: "0x1000",
	name: "owned",
	signature: "int owned(int x)",
	pseudocode: "return x + 7;",
	architecture: "x86:LE:64:default",
	image: { preferredBaseHex: "0x0", addressSpace: "ghidra-program-virtual" },
	callees: [
		{
			fromAddressHex: "0x1010",
			kind: "indirect",
			resolution: "unknown-memory-register-or-ambiguous-phi",
		},
	],
	relationsTruncated: false,
	coverage: "selected-function-decompiler-and-bounded-high-pcode-not-runtime",
};
it("preserves unknown indirect calls rather than filling fake callees", () => {
	expect(
		TargetedNativeEvidenceSchema.parse(fixture).callees[0],
	).not.toHaveProperty("targetAddressHex");
});
it("requires bounded addresses and internally consistent target resolution", () => {
	for (const callees of [
		[{ ...fixture.callees[0], targetAddressHex: "0x1234" }],
		[
			{
				...fixture.callees[0],
				resolution: "bounded-high-pcode-constant-candidate",
			},
		],
		[{ ...fixture.callees[0], fromAddressHex: "0x10000000000000000" }],
	])
		expect(() =>
			TargetedNativeEvidenceSchema.parse({ ...fixture, callees }),
		).toThrow();
});

it("IDA preserves unresolved ctree calls and distinguishes address spaces", async () => {
	const { TargetedIdaEvidenceSchema, SelectedNativeEvidenceSchema } =
		await import("./targeted-native-evidence");
	const value = {
		...fixture,
		image: {
			preferredBaseHex: "0x400000",
			addressSpace: "ida-database-virtual",
		},
		callees: [
			{
				fromAddressHex: "0x1000",
				siteResolution: "function-entry-fallback",
				kind: "indirect",
				resolution: "unknown-expression-target",
			},
		],
		coverage: "selected-function-decompiler-and-bounded-ctree-not-runtime",
	};
	expect(SelectedNativeEvidenceSchema.parse(value)).toEqual(value);
	expect(() =>
		TargetedIdaEvidenceSchema.parse({
			...value,
			callees: [{ ...value.callees[0], targetAddressHex: "0x1234" }],
		}),
	).toThrow();
	expect(() =>
		TargetedIdaEvidenceSchema.parse({ ...value, image: fixture.image }),
	).toThrow();
});
