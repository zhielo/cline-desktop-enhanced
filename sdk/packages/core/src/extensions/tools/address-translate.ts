import { createTool, validateWithZod, zodToJsonSchema } from "@cline/shared";
import { z } from "zod";

const UInt64 = z.string().regex(/^(?:0[xX][0-9a-fA-F]{1,16}|[0-9]{1,20})$/);
const InputSchema = z.strictObject({
	input_kind: z.enum(["file_offset", "va", "rva"]),
	address: UInt64,
	image_base: UInt64.optional(),
	segments: z.array(z.strictObject({
		id: z.string().min(1).max(128),
		file_offset: UInt64,
		virtual_address: UInt64,
		file_size: UInt64,
		memory_size: UInt64,
	})).min(1).max(128),
});
// Constructors preserve precision while supporting the desktop's TS emit target.
const ADDRESS_END = BigInt("18446744073709551616");
const MAX_ADDRESS = ADDRESS_END - BigInt(1);
function integer(value: string): bigint {
	const parsed = BigInt(value);
	if (parsed > MAX_ADDRESS) throw new Error("Value exceeds unsigned 64-bit range");
	return parsed;
}
function hex(value: bigint): string { return `0x${value.toString(16)}`; }
export type AddressTranslateInput = z.input<typeof InputSchema>;
export interface AddressTranslation {
	segmentId: string;
	virtualAddress: string;
	fileOffset: string | null;
	rva: string | null;
	backing: "file_backed" | "zero_filled";
}
export interface AddressTranslateResult {
	protocol: "cline-address-translation/v1";
	status: "mapped" | "ambiguous" | "unmapped";
	mappingBasis: "user_supplied_segments";
	inputProvenanceVerified: false;
	imageBaseObserved: false;
	matches: AddressTranslation[];
	totalMatches: number;
	truncated: boolean;
}

/** Pure arithmetic adapter: never reads or executes a binary or guesses ASLR. */
export function createAddressTranslateTool() {
	return createTool<AddressTranslateInput, AddressTranslateResult>({
		name: "address_translate",
		description: "Translate unsigned 64-bit file offsets, virtual addresses and RVAs using an explicitly supplied segment table. Segment virtual_address is an absolute VA; memory_size is the mapped size and must cover file_size. Ranges are half-open. RVA input requires an explicit image_base. Report overlaps, unmapped values and zero-filled memory; never invent file offsets for zero-filled ranges. Arithmetic is BigInt-safe, but the supplied table and image base are not independently verified binary or ASLR evidence. No target execution, software discovery or permission grant occurs.",
		inputSchema: zodToJsonSchema(InputSchema),
		timeoutMs: 5_000,
		retryable: false,
		maxRetries: 0,
		execute: async (input, context) => {
			if (context.signal?.aborted) throw context.signal.reason;
			const parsed = validateWithZod(InputSchema, input);
			const supplied = integer(parsed.address);
			const base = parsed.image_base === undefined ? undefined : integer(parsed.image_base);
			if (parsed.input_kind === "rva" && base === undefined) throw new Error("RVA translation requires image_base");
			const address = parsed.input_kind === "rva" ? supplied + (base ?? BigInt(0)) : supplied;
			if (address > MAX_ADDRESS) throw new Error("RVA plus image_base overflows unsigned 64-bit VA");
			const ids = new Set<string>();
			const matches: AddressTranslation[] = [];
			let totalMatches = 0;
			for (const segment of parsed.segments) {
				if (context.signal?.aborted) throw context.signal.reason;
				if (ids.has(segment.id)) throw new Error("Segment IDs must be unique");
				ids.add(segment.id);
				const fileStart = integer(segment.file_offset);
				const virtualStart = integer(segment.virtual_address);
				const fileSize = integer(segment.file_size);
				const memorySize = integer(segment.memory_size);
				if (fileSize > memorySize) throw new Error("file_size exceeds mapped memory_size");
				if (fileStart + fileSize > ADDRESS_END || virtualStart + memorySize > ADDRESS_END) throw new Error("Segment range overflows unsigned 64-bit address space");
				let va: bigint;
				let offset: bigint | null;
				if (parsed.input_kind === "file_offset") {
					if (address < fileStart || address >= fileStart + fileSize) continue;
					va = virtualStart + address - fileStart;
					offset = address;
				} else {
					if (address < virtualStart || address >= virtualStart + memorySize) continue;
					va = address;
					const delta = address - virtualStart;
					offset = delta < fileSize ? fileStart + delta : null;
				}
				totalMatches++;
				if (matches.length < 16) {
					matches.push({ segmentId: segment.id, virtualAddress: hex(va), fileOffset: offset === null ? null : hex(offset), rva: base !== undefined && va >= base ? hex(va - base) : null, backing: offset === null ? "zero_filled" : "file_backed" });
				}
			}
			return {
				protocol: "cline-address-translation/v1",
				status: totalMatches === 0 ? "unmapped" : totalMatches > 1 ? "ambiguous" : "mapped",
				mappingBasis: "user_supplied_segments",
				inputProvenanceVerified: false,
				imageBaseObserved: false,
				matches,
				totalMatches,
				truncated: totalMatches > matches.length,
			};
		},
	});
}
