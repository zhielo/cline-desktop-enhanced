import { expect, it } from "vitest";
import { decodeIL } from "./il";
import { inspectExceptionSections } from "./managed-exceptions";
const fixture = (fat = false) => {
	const b = Buffer.alloc(64),
		start = 16,
		width = fat ? 24 : 12;
	b[start] = 1 | (fat ? 64 : 0);
	b[start + 1] = 4 + width;
	const o = start + 4;
	if (fat) {
		b.writeUInt32LE(2, o);
		b.writeUInt32LE(0, o + 4);
		b.writeUInt32LE(2, o + 8);
		b.writeUInt32LE(2, o + 12);
		b.writeUInt32LE(1, o + 16);
	} else {
		b.writeUInt16LE(2, o);
		b.writeUInt16LE(0, o + 2);
		b[o + 4] = 2;
		b.writeUInt16LE(2, o + 5);
		b[o + 7] = 1;
	}
	return b;
};
const inspect = (b: Buffer) =>
	inspectExceptionSections(
		b,
		0x2000,
		15,
		3,
		decodeIL(Buffer.from("00172a", "hex")),
		(o, n) => {
			if (o < 0 || o + n > b.length) throw Error("unmapped section");
			return o;
		},
	);
it("reads small/fat clauses and preserves entry byte hashes without claiming dispatch", () => {
	for (const fat of [false, true]) {
		const r = inspect(fixture(fat));
		expect(r.status).toBe("completed");
		expect(r.regions[0]).toMatchObject({
			kind: "finally",
			tryOffset: 0,
			tryLength: 2,
			handlerOffset: 2,
			handlerLength: 1,
		});
		expect(r.regions[0].sha256).toMatch(/^[a-f0-9]{64}$/);
	}
});
it("fails closed for bad headers/flags/ranges/tokens/truncation and incomplete instructions", () => {
	for (const change of [
		(b: Buffer) => (b[16] = 2),
		(b: Buffer) => (b[17] = 15),
		(b: Buffer) => (b[18] = 1),
		(b: Buffer) => b.writeUInt16LE(8, 20),
		(b: Buffer) => (b[24] = 0),
		(b: Buffer) => b.writeUInt16LE(0, 25),
		(b: Buffer) => b.writeUInt32LE(99, 28),
	]) {
		const b = fixture();
		change(b);
		const r = inspect(b);
		expect(r.status).toBe("partial");
		expect(r.regions).toEqual([]);
	}
	expect(inspect(fixture().subarray(0, 26)).status).toBe("partial");
	expect(
		inspectExceptionSections(
			fixture(),
			0x2000,
			15,
			1,
			decodeIL(Buffer.from("ff", "hex")),
			(o) => o,
		).status,
	).toBe("partial");
});
it("retains catch/filter declarations only when tokens and entry boundaries are syntactically valid", () => {
	const c = fixture();
	c.writeUInt16LE(0, 20);
	c.writeUInt32LE(0x01000001, 28);
	expect(inspect(c).regions[0].catchTypeToken).toBe("0x01000001");
	c.writeUInt32LE(0x06000001, 28);
	expect(inspect(c).regions).toEqual([]);
	const f = fixture();
	f.writeUInt16LE(1, 20);
	f.writeUInt32LE(1, 28);
	expect(inspect(f).regions[0].filterOffset).toBe(1);
	f.writeUInt32LE(2, 28);
	expect(inspect(f).regions).toEqual([]);
});

it("discards earlier clauses when a chained section is invalid or mapping is inconsistent", () => {
	const b = fixture();
	b[16] |= 128;
	b[32] = 2;
	b[33] = 4;
	expect(inspect(b).regions).toEqual([]);
	expect(
		inspectExceptionSections(
			fixture(),
			0x2000,
			15,
			3,
			decodeIL(Buffer.from("00172a", "hex")),
			(o, n) => (n === 4 ? o : o + 1),
		).status,
	).toBe("partial");
	expect(
		inspectExceptionSections(
			fixture(),
			0x2000,
			15,
			3,
			decodeIL(Buffer.from("00172a", "hex")),
			() => 1000,
		).regions,
	).toEqual([]);
});
