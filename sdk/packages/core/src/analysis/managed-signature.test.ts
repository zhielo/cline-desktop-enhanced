import { expect, it } from "vitest";
import { inspectManagedSignature } from "./managed-signature";
it("inspects primitive methods/fields, byrefs, arrays and generic variables without CLR", () => {
	expect(
		inspectManagedSignature(Buffer.from("0002080808", "hex")),
	).toMatchObject({
		status: "completed",
		display: "int32 (int32, int32)",
		parameterCount: 2,
	});
	expect(inspectManagedSignature(Buffer.from("060e", "hex"))).toMatchObject({
		status: "completed",
		display: "string",
	});
	expect(
		inspectManagedSignature(Buffer.from("3001021e0010081d0e", "hex")),
	).toMatchObject({
		status: "completed",
		genericArity: 1,
		display: "!!0 (int32&, string[])",
	});
	expect(inspectManagedSignature(Buffer.from("00001205", "hex"))).toMatchObject(
		{
			status: "completed",
			display: "class:TypeRef#1 ()",
		},
	);
});
it("leaves malformed/unsupported/oversized signatures unresolved with exact provenance", () => {
	for (const hex of [
		"",
		"00020808",
		"00010101",
		"800001",
		"400001",
		"000912",
		"00001203",
		"00000100",
		"1000800001",
		"000015",
		"050008",
		"100001",
		"00001d1008",
		"061008",
		"0616",
	]) {
		const b = Buffer.from(hex, "hex"),
			r = inspectManagedSignature(b);
		expect(r.status, hex).toBe("partial");
		expect(r).not.toHaveProperty("display");
		expect(r.sha256).toMatch(/^[a-f0-9]{64}$/);
	}
	expect(inspectManagedSignature(Buffer.alloc(257)).status).toBe("partial");
	expect(
		inspectManagedSignature(Buffer.from("00001d1d1d1d1d08", "hex")).status,
	).toBe("partial");
});

it("rejects field/method kind confusion instead of displaying an invalid declaration", () => {
	expect(
		inspectManagedSignature(Buffer.from("0608", "hex"), "method").status,
	).toBe("partial");
	expect(
		inspectManagedSignature(Buffer.from("000008", "hex"), "field").status,
	).toBe("partial");
});

it("decodes bounded generic instantiations, custom modifiers, shaped arrays and function pointers", () => {
	for (const [hex, display] of [
		["0615120502080e", "class:TypeRef#1<int32, string>"],
		["061f0508", "modreq(TypeRef#1) int32"],
		["06200508", "modopt(TypeRef#1) int32"],
		["06140802010302007f", "int32[rank=2;sizes=3;lower=0,-1]"],
		["061b0002080808", "fnptr[cc=0;arity=0] int32 (int32, int32)"],
		["061b05020808410e", "fnptr[cc=5;arity=0] int32 (int32, ..., string)"],
	])
		expect(inspectManagedSignature(Buffer.from(hex, "hex"))).toMatchObject({
			status: "completed",
			display,
		});
});
it("rejects invalid generic, array and function-pointer structures without guessing", () => {
	for (const hex of [
		"061515050108",
		"0615120500",
		"061512030108",
		"061408000000",
		"0614080102000000",
		"061b0001084108",
		"061b800008",
		"0614080100018000",
	])
		expect(inspectManagedSignature(Buffer.from(hex, "hex")).status, hex).toBe(
			"partial",
		);
});
