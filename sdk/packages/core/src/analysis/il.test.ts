import { expect, it } from "vitest";
import { decodeIL } from "./il";
it("decodes short/long branches and switch relative to the operand end", () => {
	expect(decodeIL(Buffer.from("162d02172a182a", "hex")).edges).toContainEqual({
		source: 1,
		target: 5,
		kind: "branch",
	});
	expect(decodeIL(Buffer.from("38000000002a", "hex")).edges).toContainEqual({
		source: 0,
		target: 5,
		kind: "branch",
	});
	const b = Buffer.alloc(10);
	b[0] = 0x45;
	b.writeUInt32LE(1, 1);
	b[9] = 0x2a;
	expect(decodeIL(b).edges).toContainEqual({
		source: 0,
		target: 9,
		kind: "switch",
	});
});
it("preserves int64 exactly and keeps tokens without invoking CLR", () => {
	const b = Buffer.alloc(10);
	b[0] = 0x21;
	b.writeBigInt64LE(9007199254740993n, 1);
	b[9] = 0x2a;
	expect(decodeIL(b).instructions[0].operand).toBe("9007199254740993");
	expect(
		decodeIL(Buffer.from("28010000062a", "hex")).instructions[0].token,
	).toBe("0x06000001");
});
it("fails closed without guessed edges for truncation, reserved opcodes, budgets and invalid targets", () => {
	for (const hex of ["20", "fe", "2b7f", "2bff", "fe13", "2b02fe13172a"]) {
		const r = decodeIL(Buffer.from(hex, "hex"));
		expect(r.status).toBe("invalid");
		expect(r.edges).toEqual([]);
	}
	expect(decodeIL(Buffer.from("ff2a", "hex")).status).toBe("partial");
	expect(decodeIL(Buffer.from("172a", "hex"), 1).edges).toEqual([]);
	const b = Buffer.alloc(5);
	b[0] = 0x45;
	b.writeUInt32LE(33, 1);
	expect(decodeIL(b).status).toBe("partial");
});
it("permits branches to a prefix bundle start but not its interior", () => {
	expect(decodeIL(Buffer.from("2b00fe13172a", "hex")).status).toBe("completed");
	expect(decodeIL(Buffer.from("2b02fe13172a", "hex")).status).toBe("invalid");
});
