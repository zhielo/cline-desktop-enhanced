import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, realpath, stat } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { createTool, validateWithZod, zodToJsonSchema } from "@cline/shared";
import { z } from "zod";

const InputSchema = z.strictObject({ path: z.string().min(1).max(4_096).refine((value) => !value.includes("\0"), "NUL is not allowed") });
const MAX_FILE_BYTES = 32 * 1024 * 1024;
const ADDRESS_END = BigInt("18446744073709551616");
const hex = (value: bigint) => `0x${value.toString(16)}`;
export class UnsupportedBinaryVariant extends Error {}
export interface BinarySegment {
	id: string;
	file_offset: string;
	virtual_address: string;
	file_size: string;
	memory_size: string;
	flags: number;
}
export interface BinaryHeaderMetadata {
	format: "elf" | "pe" | "mach_o";
	bits: 32 | 64;
	endian: "little" | "big";
	machine: number;
	fileType: number;
	entryVirtualAddress: string | null;
	imageBase: string | null;
	segments: BinarySegment[];
	mappingBasis: "declared_file_headers";
	runtimeAddressesObserved: false;
	coverage: "headers_and_declared_segments";
	limitations: string[];
}

/** Bounded parser, no external executable or target code invocation. */
export function parseBinaryHeaders(data: Buffer): BinaryHeaderMetadata {
	function bounds(offset: number, size: number) {
		if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) || offset < 0 || size < 0 || offset > data.length - size) throw new Error("Truncated or invalid binary range");
	}
	function numberOffset(value: bigint): number {
		if (value > BigInt(data.length)) throw new Error("Binary table offset exceeds file");
		return Number(value);
	}
	let little = true;
	function u16(offset: number) { bounds(offset, 2); return little ? data.readUInt16LE(offset) : data.readUInt16BE(offset); }
	function u32(offset: number) { bounds(offset, 4); return little ? data.readUInt32LE(offset) : data.readUInt32BE(offset); }
	function u64(offset: number) { bounds(offset, 8); return little ? data.readBigUInt64LE(offset) : data.readBigUInt64BE(offset); }
	function label(offset: number, size: number): string { bounds(offset, size); return data.subarray(offset, offset + size).toString("ascii").split("\0")[0].replace(/[^\x20-\x7e]/g, "?"); }
	function segment(id: string, offset: bigint, va: bigint, fileSize: bigint, memorySize: bigint, flags: number): BinarySegment {
		if (offset + fileSize > BigInt(data.length)) throw new Error("Segment file extent exceeds file");
		if (fileSize > memorySize || va + memorySize > ADDRESS_END) throw new Error("Invalid segment memory extent");
		return { id, file_offset: hex(offset), virtual_address: hex(va), file_size: hex(fileSize), memory_size: hex(memorySize), flags };
	}
	const common = {
		mappingBasis: "declared_file_headers" as const,
		runtimeAddressesObserved: false as const,
		coverage: "headers_and_declared_segments" as const,
		limitations: ["Imports, exports, relocations and section contents are not decoded in this checkpoint.", "Declared addresses are not observed runtime or ASLR mappings."],
	};
	bounds(0, 4);
	if (data[0] === 0x7f && data.subarray(1, 4).toString("ascii") === "ELF") {
		bounds(0, 16);
		const bits = data[4] === 1 ? 32 : data[4] === 2 ? 64 : undefined;
		if (!bits || ![1, 2].includes(data[5]) || data[6] !== 1) throw new UnsupportedBinaryVariant("Unsupported ELF class, byte order or version");
		little = data[5] === 1;
		bounds(0, bits === 64 ? 64 : 52);
		if (u32(20) !== 1) throw new UnsupportedBinaryVariant("Unsupported ELF header version");
		const stride = u16(bits === 64 ? 54 : 42);
		const count = u16(bits === 64 ? 56 : 44);
		if (count > 128) throw new UnsupportedBinaryVariant("ELF extended numbering or more than 128 program headers is unsupported");
		const table = numberOffset(bits === 64 ? u64(32) : BigInt(u32(28)));
		if (count && stride < (bits === 64 ? 56 : 32)) throw new Error("Invalid ELF program-header size");
		bounds(table, count * stride);
		const segments: BinarySegment[] = [];
		for (let index = 0; index < count; index++) {
			const at = table + index * stride;
			if (u32(at) !== 1) continue;
			segments.push(bits === 64
				? segment(`load-${index}`, u64(at + 8), u64(at + 16), u64(at + 32), u64(at + 40), u32(at + 4))
				: segment(`load-${index}`, BigInt(u32(at + 4)), BigInt(u32(at + 8)), BigInt(u32(at + 16)), BigInt(u32(at + 20)), u32(at + 24)));
		}
		return { ...common, format: "elf", bits, endian: little ? "little" : "big", machine: u16(18), fileType: u16(16), entryVirtualAddress: hex(bits === 64 ? u64(24) : BigInt(u32(24))), imageBase: null, segments };
	}
	if (data[0] === 0x4d && data[1] === 0x5a) {
		bounds(0, 64);
		const pe = u32(60);
		bounds(pe, 24);
		if (u32(pe) !== 0x4550) throw new Error("Invalid PE signature");
		const count = u16(pe + 6);
		if (count > 128) throw new UnsupportedBinaryVariant("More than 128 PE sections is unsupported");
		const optionalSize = u16(pe + 20);
		const optional = pe + 24;
		bounds(optional, optionalSize);
		const magic = u16(optional);
		const bits = magic === 0x10b ? 32 : magic === 0x20b ? 64 : undefined;
		if (!bits) throw new UnsupportedBinaryVariant("Unsupported PE optional-header variant");
		if (optionalSize < (bits === 64 ? 112 : 96)) throw new Error("Truncated PE optional header");
		const base = bits === 64 ? u64(optional + 24) : BigInt(u32(optional + 28));
		const entry = base + BigInt(u32(optional + 16));
		if (entry >= ADDRESS_END) throw new Error("PE entry address overflows unsigned 64-bit range");
		const table = optional + optionalSize;
		bounds(table, count * 40);
		const segments: BinarySegment[] = [];
		for (let index = 0; index < count; index++) {
			const at = table + index * 40;
			const fileSize = BigInt(u32(at + 16));
			const virtualSize = BigInt(u32(at + 8));
			segments.push(segment(`section-${index}:${label(at, 8)}`, BigInt(u32(at + 20)), base + BigInt(u32(at + 12)), fileSize, virtualSize > fileSize ? virtualSize : fileSize, u32(at + 36)));
		}
		return { ...common, limitations: [...common.limitations, "PE segment spans use max(VirtualSize, SizeOfRawData), not observed loader alignment or committed memory."], format: "pe", bits, endian: "little", machine: u16(pe + 4), fileType: u16(pe + 22), entryVirtualAddress: hex(entry), imageBase: hex(base), segments };
	}
	const magic = data.readUInt32BE(0);
	if ([0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca].includes(magic)) throw new UnsupportedBinaryVariant("Universal/fat Mach-O requires a separately selected architecture and is unsupported here");
	if ([0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe].includes(magic)) {
		little = magic === 0xcefaedfe || magic === 0xcffaedfe;
		const bits = magic === 0xfeedfacf || magic === 0xcffaedfe ? 64 : 32;
		const header = bits === 64 ? 32 : 28;
		bounds(0, header);
		const count = u32(16);
		const size = u32(20);
		if (count > 512 || size > 1024 * 1024) throw new UnsupportedBinaryVariant("Mach-O load-command limits exceeded");
		bounds(header, size);
		let at = header;
		const segments: BinarySegment[] = [];
		for (let index = 0; index < count; index++) {
			if (at > header + size - 8) throw new Error("Truncated Mach-O command");
			const command = u32(at);
			const commandSize = u32(at + 4);
			if (commandSize < 8 || commandSize % 4 !== 0 || commandSize > header + size - at) throw new Error("Invalid Mach-O command size");
			if (command === 1 || command === 0x19) {
				if ((command === 0x19) !== (bits === 64)) throw new Error("Mach-O segment class does not match header");
				const minimum = bits === 64 ? 72 : 56;
				if (commandSize < minimum) throw new Error("Truncated Mach-O segment command");
				if (segments.length >= 128) throw new UnsupportedBinaryVariant("More than 128 Mach-O segments is unsupported");
				const sectionCount = u32(at + (bits === 64 ? 64 : 48));
				if (sectionCount > 512 || minimum + sectionCount * (bits === 64 ? 80 : 68) > commandSize) throw new Error("Invalid Mach-O section table extent");
				segments.push(bits === 64
					? segment(`segment-${index}:${label(at + 8, 16)}`, u64(at + 40), u64(at + 24), u64(at + 48), u64(at + 32), u32(at + 60))
					: segment(`segment-${index}:${label(at + 8, 16)}`, BigInt(u32(at + 32)), BigInt(u32(at + 24)), BigInt(u32(at + 36)), BigInt(u32(at + 28)), u32(at + 44)));
			}
			at += commandSize;
		}
		if (at !== header + size) throw new Error("Mach-O command count and total size disagree");
		return { ...common, limitations: [...common.limitations, "Mach-O entry/thread-state commands and universal/fat containers are not decoded."], format: "mach_o", bits, endian: little ? "little" : "big", machine: u32(4), fileType: u32(12), entryVirtualAddress: null, imageBase: null, segments };
	}
	throw new UnsupportedBinaryVariant("Unrecognized executable format");
}

function inside(root: string, target: string): boolean {
	const path = relative(root, target);
	return path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path);
}

export function createBinaryMetadataTool(cwd: string) {
	return createTool<z.input<typeof InputSchema>, unknown>({
		name: "binary_metadata",
		description: "Read bounded ELF, PE or thin Mach-O headers and declared load segments from one regular file inside the host-selected workspace, without executing the target or calling external engines. Relative paths only; outside-workspace symlinks, non-regular files, changing files and files above 32 MiB are rejected. Returns a SHA256 receipt, string-encoded 64-bit addresses and explicit limited coverage. Imports/exports/relocations, section contents, runtime mappings and universal Mach-O are not decoded. Use address_translate with the returned segments and an explicit image base where applicable; static declarations are not observed ASLR evidence.",
		inputSchema: zodToJsonSchema(InputSchema),
		timeoutMs: 5_000,
		retryable: false,
		maxRetries: 0,
		execute: async (input, context) => {
			const started = performance.now();
			const checkpoint = () => {
				if (context.signal?.aborted) throw context.signal.reason;
				if (performance.now() - started >= 5_000) throw new Error("Binary metadata deadline exceeded; kernel I/O termination is not guaranteed");
			};
			checkpoint();
			const parsed = validateWithZod(InputSchema, input);
			if (isAbsolute(parsed.path) || /^[A-Za-z]:|^\\\\/.test(parsed.path)) throw new Error("A workspace-relative path is required");
			const root = await realpath(cwd);
			checkpoint();
			const target = await realpath(resolve(root, parsed.path));
			if (!inside(root, target)) throw new Error("Path leaves the selected workspace");
			checkpoint();
			const flags = constants.O_RDONLY | (process.platform === "win32" ? 0 : constants.O_NOFOLLOW | constants.O_NONBLOCK);
			const handle = await open(target, flags);
			try {
				checkpoint();
				const before = await handle.stat({ bigint: true });
				if (!before.isFile() || before.size > BigInt(MAX_FILE_BYTES)) throw new Error("Only regular files up to 32 MiB are supported");
				const confirmed = await realpath(target);
				const pathStat = await stat(confirmed, { bigint: true });
				if (confirmed !== target || !inside(root, confirmed) || pathStat.ino !== before.ino || pathStat.dev !== before.dev) throw new Error("File identity changed before reading");
				const data = Buffer.alloc(Number(before.size));
				let offset = 0;
				while (offset < data.length) {
					checkpoint();
					const { bytesRead } = await handle.read(data, offset, Math.min(65_536, data.length - offset), offset);
					if (bytesRead === 0) throw new Error("File changed or truncated during reading");
					offset += bytesRead;
				}
				checkpoint();
				const after = await handle.stat({ bigint: true });
				if (before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw new Error("File changed during metadata capture");
				const receipt = { parserVersion: "cline-binary-headers/v1", path: relative(root, target), sizeBytes: data.length, sha256: createHash("sha256").update(data).digest("hex"), targetExecuted: false };
				try {
					const metadata = parseBinaryHeaders(data);
					checkpoint();
					return { ...receipt, status: "parsed", metadata };
				} catch (error) {
					if (error instanceof UnsupportedBinaryVariant) return { ...receipt, status: "unsupported", reason: error.message, metadata: null };
					throw error;
				}
			} finally {
				await handle.close();
			}
		},
	});
}
