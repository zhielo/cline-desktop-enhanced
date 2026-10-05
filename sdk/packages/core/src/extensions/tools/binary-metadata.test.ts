import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createBinaryMetadataTool, parseBinaryHeaders, UnsupportedBinaryVariant } from "./binary-metadata";

function elf(bits: 32 | 64, little: boolean): Buffer {
	const data = Buffer.alloc(256);
	data.write("\x7fELF", 0, "ascii"); data[4] = bits === 64 ? 2 : 1; data[5] = little ? 1 : 2; data[6] = 1;
	const u16 = (at: number, value: number) => little ? data.writeUInt16LE(value, at) : data.writeUInt16BE(value, at);
	const u32 = (at: number, value: number) => little ? data.writeUInt32LE(value, at) : data.writeUInt32BE(value, at);
	const u64 = (at: number, value: number) => little ? data.writeBigUInt64LE(BigInt(value), at) : data.writeBigUInt64BE(BigInt(value), at);
	u16(16, 3); u16(18, 183); u32(20, 1);
	if (bits === 64) { u64(24, 0x1000); u64(32, 64); u16(54, 56); u16(56, 1); u32(64, 1); u32(68, 5); u64(72, 0); u64(80, 0x1000); u64(96, 256); u64(104, 512); }
	else { u32(24, 0x1000); u32(28, 52); u16(42, 32); u16(44, 1); u32(52, 1); u32(56, 0); u32(60, 0x1000); u32(68, 256); u32(72, 512); u32(76, 5); }
	return data;
}
function pe(bits: 32 | 64): Buffer {
	const data = Buffer.alloc(1_024); data.write("MZ"); data.writeUInt32LE(64, 60); data.writeUInt32LE(0x4550, 64); data.writeUInt16LE(0x8664, 68); data.writeUInt16LE(1, 70);
	const optionalSize = bits === 64 ? 112 : 96; data.writeUInt16LE(optionalSize, 84); data.writeUInt16LE(bits === 64 ? 0x20b : 0x10b, 88); data.writeUInt32LE(0x1000, 104);
	if (bits === 64) data.writeBigUInt64LE(BigInt("5368709120"), 112); else data.writeUInt32LE(0x400000, 116);
	const section = 88 + optionalSize; data.write(".text", section); data.writeUInt32LE(512, section + 8); data.writeUInt32LE(0x1000, section + 12); data.writeUInt32LE(256, section + 16); data.writeUInt32LE(512, section + 20); data.writeUInt32LE(0x60000020, section + 36);
	return data;
}
function mach(bits: 32 | 64, little: boolean): Buffer {
	const data = Buffer.alloc(256);
	const u32 = (at: number, value: number) => little ? data.writeUInt32LE(value, at) : data.writeUInt32BE(value, at);
	const u64 = (at: number, value: number) => little ? data.writeBigUInt64LE(BigInt(value), at) : data.writeBigUInt64BE(BigInt(value), at);
	u32(0, bits === 64 ? 0xfeedfacf : 0xfeedface); u32(4, 0x100000c); u32(12, 2); u32(16, 1); u32(20, bits === 64 ? 72 : 56);
	const at = bits === 64 ? 32 : 28; u32(at, bits === 64 ? 0x19 : 1); u32(at + 4, bits === 64 ? 72 : 56); data.write("__TEXT", at + 8);
	if (bits === 64) { u64(at + 24, 0x1000); u64(at + 32, 512); u64(at + 40, 0); u64(at + 48, 256); u32(at + 60, 5); }
	else { u32(at + 24, 0x1000); u32(at + 28, 512); u32(at + 32, 0); u32(at + 36, 256); u32(at + 44, 5); }
	return data;
}

describe("bounded binary header parser", () => {
	for (const bits of [32, 64] as const) for (const little of [true, false]) {
		it(`parses ELF${bits} ${little ? "LE" : "BE"} declared segments`, () => {
			const result = parseBinaryHeaders(elf(bits, little));
			expect(result).toMatchObject({ format: "elf", bits, machine: 183, runtimeAddressesObserved: false, segments: [{ file_size: "0x100", memory_size: "0x200", virtual_address: "0x1000" }] });
		});
		it(`parses thin Mach-O ${bits} ${little ? "LE" : "BE"}`, () => {
			const result = parseBinaryHeaders(mach(bits, little));
			expect(result).toMatchObject({ format: "mach_o", bits, segments: [{ virtual_address: "0x1000", file_size: "0x100" }] });
			expect(result.entryVirtualAddress).toBeNull();
		});
	}
	for (const bits of [32, 64] as const) it(`parses PE${bits} declared section extents`, () => {
		const result = parseBinaryHeaders(pe(bits));
		expect(result).toMatchObject({ format: "pe", bits, segments: [{ file_offset: "0x200", file_size: "0x100", memory_size: "0x200" }] });
		expect(result.imageBase).toBe(bits === 64 ? "0x140000000" : "0x400000");
	});
	it("rejects truncated and oversized tables without trusting exit codes", () => {
		expect(() => parseBinaryHeaders(elf(64, true).subarray(0, 40))).toThrow("Truncated");
		const data = elf(64, true); data.writeUInt16LE(65535, 56);
		expect(() => parseBinaryHeaders(data)).toThrow(UnsupportedBinaryVariant);
	});
	it("rejects segment file extents outside the artifact", () => {
		const data = elf(64, true); data.writeBigUInt64LE(BigInt(4096), 96);
		expect(() => parseBinaryHeaders(data)).toThrow("file extent");
	});
	it("reports universal Mach-O as unsupported rather than inventing an architecture", () => {
		const data = Buffer.alloc(8); data.writeUInt32BE(0xcafebabe);
		expect(() => parseBinaryHeaders(data)).toThrow(UnsupportedBinaryVariant);
	});
	it("rejects corrupt Mach-O command sizes", () => {
		const data = mach(64, true); data.writeUInt32LE(0, 36);
		expect(() => parseBinaryHeaders(data)).toThrow("command size");
	});
});

describe("binary metadata workspace boundary", () => {
	const context = { agentId: "metadata-test", iteration: 1 };
	it("reads a real fixture and returns a hash without target execution", async () => {
		const root = await mkdtemp(join(tmpdir(), "binary-metadata-"));
		try {
			await writeFile(join(root, "sample.elf"), elf(64, true));
			const result = await createBinaryMetadataTool(root).execute({ path: "sample.elf" }, context);
			expect(result).toMatchObject({ status: "parsed", sizeBytes: 256, targetExecuted: false, sha256: expect.stringMatching(/^[a-f0-9]{64}$/) });
		} finally { await rm(root, { recursive: true, force: true }); }
	});
	it("rejects absolute paths, directories and caller-granted authority", async () => {
		const root = await mkdtemp(join(tmpdir(), "binary-metadata-"));
		try {
			const tool = createBinaryMetadataTool(root);
			await expect(tool.execute({ path: root }, context)).rejects.toThrow("relative");
			await expect(tool.execute({ path: "." }, context)).rejects.toThrow("regular");
			await expect(tool.execute({ path: ".", confirm_read: true } as never, context)).rejects.toThrow();
		} finally { await rm(root, { recursive: true, force: true }); }
	});
	it("rejects traversal and outside-workspace symlinks", async () => {
		const parent = await mkdtemp(join(tmpdir(), "binary-scope-"));
		const root = join(parent, "workspace");
		const { mkdir } = await import("node:fs/promises"); await mkdir(root);
		try {
			await writeFile(join(parent, "outside.elf"), elf(64, true));
			const tool = createBinaryMetadataTool(root);
			await expect(tool.execute({ path: "../outside.elf" }, context)).rejects.toThrow("workspace");
			if (process.platform !== "win32") {
				await symlink(join(parent, "outside.elf"), join(root, "linked.elf"));
				await expect(tool.execute({ path: "linked.elf" }, context)).rejects.toThrow("workspace");
			}
		} finally { await rm(parent, { recursive: true, force: true }); }
	});
	it("honors pre-cancellation before filesystem access", async () => {
		const controller = new AbortController(); controller.abort(new Error("stop"));
		await expect(createBinaryMetadataTool("/nonexistent").execute({ path: "x" }, { ...context, signal: controller.signal })).rejects.toThrow("stop");
	});
});
