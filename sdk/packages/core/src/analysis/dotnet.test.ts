import {
	OWNED_MANAGED_BASE64,
	OWNED_MANAGED_SHA256,
} from "../../scripts/owned-managed-fixture.mjs";
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
	expect(r.records.slice(0, 3).map((x) => x.kind)).toEqual([
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

it("decodes a real owned Roslyn assembly without executing it", () => {
	// Source: Add(a,b)=>a+b; Branch(x)=>x>3?Add(x,2):7; Endpoint()=>owned URL;
	// Choose switch(0..3); Wide()=>9007199254740993L. SDK 8.0.100 csc, deterministic, optimized.
	const b = Buffer.from(OWNED_MANAGED_BASE64, "base64");
	expect(byteDigest(b)).toBe(OWNED_MANAGED_SHA256);
	const r = inspectManagedPE(b),
		details = r.records
			.filter((x) => x.kind === "managed-il-instruction")
			.map((x) => JSON.parse(x.value));
	expect(
		details.some((x) => x.opcode === "call" && x.resolution?.name === "Add"),
	).toBe(true);
	expect(
		details.some(
			(x) =>
				x.opcode === "ldstr" &&
				x.resolution?.preview === "https://owned.invalid/managed",
		),
	).toBe(true);
	expect(
		details.some(
			(x) => x.opcode === "ldc.i8" && x.operand === "9007199254740993",
		),
	).toBe(true);
	expect(details.some((x) => x.opcode === "switch")).toBe(true);
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
	expect(result.edges.some((x) => x.kind === "managed-flow")).toBe(true);
});

it("retains owned method declaring type and exact bounded signature", () => {
	const b = Buffer.from(OWNED_MANAGED_BASE64, "base64"),
		r = inspectManagedPE(b);
	const add = r.records
		.filter((x) => x.kind === "managed-method")
		.map((x) => JSON.parse(x.value))
		.find((x) => x.name === "Add");
	expect(add.declaringType).toMatchObject({
		name: "Fixture",
		namespace: "ClineOwned",
	});
	expect(add.signature).toMatchObject({
		status: "completed",
		display: "int32 (int32, int32)",
		parameterCount: 2,
	});
	const result = analyzeSources([
		{
			path: "owned.dll",
			source: "",
			binary: b,
			bytes: b.length,
			sha256: byteDigest(b),
		},
	]);
	expect(
		result.facts.some(
			(f) =>
				f.kind === "managed-method" &&
				JSON.parse(f.value).record.name === "Add",
		),
	).toBe(true);
	expect(() => ResultSchema.parse(result)).not.toThrow();
});

it("does not guess owners or signatures when owned metadata is corrupted", () => {
	const original = Buffer.from(OWNED_MANAGED_BASE64, "base64"),
		r = inspectManagedPE(original);
	const type = r.records.find(
		(x) => x.kind === "managed-type" && JSON.parse(x.value).name === "Fixture",
	);
	expect(type).toBeDefined();
	const invalidOwner = Buffer.from(original);
	invalidOwner.writeUInt16LE(0, type!.offset + 12);
	const method = inspectManagedPE(invalidOwner).records.find(
		(x) => x.kind === "managed-method" && JSON.parse(x.value).name === "Add",
	);
	expect(JSON.parse(method!.value).declaringType).toBe(
		"unknown:invalid-or-pointer-indirected-method-lists",
	);
	const md = original.indexOf(Buffer.from("BSJB")),
		blobName = original.indexOf(Buffer.from("#Blob\0")),
		blob = md + original.readUInt32LE(blobName - 8),
		length = original.readUInt32LE(blobName - 4);
	const signature = original.indexOf(Buffer.from("050002080808", "hex"), blob);
	expect(signature).toBeGreaterThanOrEqual(blob);
	expect(signature + 6).toBeLessThanOrEqual(blob + length);
	const invalidSignature = Buffer.from(original);
	invalidSignature[signature] = 0xe0;
	const damaged = inspectManagedPE(invalidSignature).records.find(
		(x) => x.kind === "managed-method" && JSON.parse(x.value).name === "Add",
	);
	expect(JSON.parse(damaged!.value).signature.status).toBe("partial");
	expect(JSON.parse(damaged!.value).signature).not.toHaveProperty("display");
});
