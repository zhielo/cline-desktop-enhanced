import { expect, it } from "vitest";
import { inspectManagedPE } from "./dotnet";
import { analyzeSources } from "./parser";
import { byteDigest, ResultSchema } from "./contracts";
/** Owned minimal PE32/CLI image: one declared type and tiny IL method (ldc.i4.1;ret). */
function fixture() {
	const b = Buffer.alloc(2048),
		u16 = (o: number, n: number) => b.writeUInt16LE(n, o),
		u32 = (o: number, n: number) => b.writeUInt32LE(n, o);
	u16(0, 0x5a4d);
	u32(0x3c, 0x80);
	u32(0x80, 0x4550);
	u16(0x86, 1);
	u16(0x94, 224);
	const opt = 0x98;
	u16(opt, 0x10b);
	u32(opt + 96 + 112, 0x2000);
	u32(opt + 96 + 116, 72);
	const sec = opt + 224;
	u32(sec + 12, 0x2000);
	u32(sec + 16, 1536);
	u32(sec + 20, 512);
	u32(512, 72);
	u32(520, 0x2080);
	u32(524, 512);
	const md = 640;
	u32(md, 0x424a5342);
	u32(md + 12, 4);
	b.write("v4\0\0", md + 16);
	u16(md + 22, 2);
	u32(md + 24, 80);
	u32(md + 28, 128);
	b.write("#~\0", md + 32);
	u32(md + 36, 208);
	u32(md + 40, 64);
	b.write("#Strings\0", md + 44);
	const t = md + 80;
	b.writeBigUInt64LE((1n << 2n) | (1n << 6n), t + 8);
	u32(t + 24, 1);
	u32(t + 28, 1);
	const type = t + 32;
	u32(type, 1);
	u16(type + 4, 1);
	u16(type + 6, 7);
	u16(type + 10, 1);
	u16(type + 12, 1);
	const m = type + 14;
	u32(m, 0x2300);
	u16(m + 4, 0);
	u16(m + 6, 0x16);
	u16(m + 8, 13);
	u16(m + 12, 1);
	b.write("\0Owned\0Tests\0Run\0", md + 208);
	b[1280] = 10;
	b[1281] = 0x17;
	b[1282] = 0x2a;
	return b;
}
it("inspects owned type/method metadata and bounded IL bytes without loading CLR", () => {
	const b = fixture(),
		r = inspectManagedPE(b);
	expect(r.records.map((x) => x.kind)).toEqual([
		"managed-type",
		"managed-method",
		"managed-il",
	]);
	expect(JSON.parse(r.records[2].value).hex).toBe("172a");
	expect(JSON.parse(r.records[1].value).name).toBe("Run");
	const result = analyzeSources([
		{
			path: "owned.dll",
			source: "",
			binary: b,
			bytes: b.length,
			sha256: byteDigest(b),
		},
	]);
	expect(() => ResultSchema.parse(result)).not.toThrow();
	expect(result.facts.every((f) => f.location.sha256 === byteDigest(b))).toBe(
		true,
	);
});
it("fails closed on malformed headers, streams, row counts and unmapped RVA", () => {
	for (const [offset, value] of [
		[0x3c, 999999],
		[640 + 24, 999999],
		[720 + 24, 100001],
		[512 + 8, 999999],
	]) {
		const b = fixture();
		b.writeUInt32LE(value, offset);
		expect(() => inspectManagedPE(b)).toThrow();
	}
	for (const n of [0, 1, 16, 100, 700])
		expect(() => inspectManagedPE(fixture().subarray(0, n))).toThrow();
});
it("limits method bytes and record coverage rather than inventing IL semantics", () => {
	const r = inspectManagedPE(fixture(), 1);
	expect(r.records).toHaveLength(1);
	expect(r.limitations).toContain("Managed record budget reached");
	expect(r.limitations[0]).toContain("no CLR execution");
});
