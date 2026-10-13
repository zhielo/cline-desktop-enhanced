import { inspectManagedSignature } from "./managed-signature";
import { inspectExceptionSections } from "./managed-exceptions";
import { modelManagedStack } from "./managed-stack";
import { decodeIL } from "./il";
import { byteDigest } from "./contracts";
/** Bounded ECMA-335 PE metadata and method-body inspection. No CLR load/execute. */
export type ManagedRecord = {
	kind:
		| "managed-type"
		| "managed-method"
		| "managed-il"
		| "managed-il-instruction"
		| "managed-control-flow"
		| "managed-exception-region"
		| "managed-exception-unresolved"
		| "managed-stack-model";
	value: string;
	offset: number;
};
const coded: Record<string, [number, number[]]> = {
	TypeDefOrRef: [2, [2, 1, 27]],
	HasConstant: [2, [4, 8, 23]],
	HasCustomAttribute: [
		5,
		[
			6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42,
			44, 43,
		],
	],
	HasFieldMarshal: [1, [4, 8]],
	HasDeclSecurity: [2, [2, 6, 32]],
	MemberRefParent: [3, [2, 1, 26, 6, 27]],
	HasSemantics: [1, [20, 23]],
	MethodDefOrRef: [1, [6, 10]],
	MemberForwarded: [1, [4, 6]],
	Implementation: [2, [38, 35, 39]],
	CustomAttributeType: [3, [6, 10]],
	ResolutionScope: [2, [0, 26, 35, 1]],
	TypeOrMethodDef: [1, [2, 6]],
};
const schema = [
	"u2 s g g g",
	"CResolutionScope s s",
	"u4 s s CTypeDefOrRef T4 T6",
	"T4",
	"u2 s b",
	"T6",
	"u4 u2 u2 s b T8",
	"T8",
	"u2 u2 s",
	"T2 CTypeDefOrRef",
	"CMemberRefParent s b",
	"u2 CHasConstant b",
	"CHasCustomAttribute CCustomAttributeType b",
	"CHasFieldMarshal b",
	"u2 CHasDeclSecurity b",
	"u2 u4 T2",
	"u4 T4",
	"b",
	"T2 T20",
	"T20",
	"u2 s CTypeDefOrRef",
	"T2 T23",
	"T23",
	"u2 s b",
	"u2 T6 CHasSemantics",
	"T2 CMethodDefOrRef CMethodDefOrRef",
	"s",
	"b",
	"u2 CMemberForwarded s T26",
	"u4 T4",
	"u4 u4",
	"u4",
	"u4 u2 u2 u2 u2 u4 b s s",
	"u4",
	"u4 u4 u4",
	"u2 u2 u2 u2 u4 b s s b",
	"u4 T35",
	"u4 u4 u4 T35",
	"u4 s b",
	"u4 u4 s s CImplementation",
	"u4 u4 s CImplementation",
	"T2 T2",
	"u2 u2 CTypeOrMethodDef s",
	"CMethodDefOrRef b",
	"T42 CTypeDefOrRef",
];
export function inspectManagedPE(
	bytes: Uint8Array,
	budget = 256,
): { records: ManagedRecord[]; limitations: string[] } {
	const b = Buffer.from(bytes);
	const bounds = (o: number, n: number) => {
		if (!Number.isSafeInteger(o) || o < 0 || n < 0 || o + n > b.length)
			throw new Error("Truncated managed PE range");
	};
	const u16 = (o: number) => {
			bounds(o, 2);
			return b.readUInt16LE(o);
		},
		u32 = (o: number) => {
			bounds(o, 4);
			return b.readUInt32LE(o);
		};
	if (u16(0) !== 0x5a4d) throw new Error("Not a PE image");
	const pe = u32(0x3c);
	if (u32(pe) !== 0x4550) throw new Error("Invalid PE signature");
	const n = u16(pe + 6),
		opt = pe + 24,
		optSize = u16(pe + 20),
		magic = u16(opt),
		dir = magic === 0x10b ? opt + 96 : magic === 0x20b ? opt + 112 : 0;
	if (!dir || n > 96 || optSize < dir - opt + 15 * 8)
		throw new Error("Unsupported PE headers");
	bounds(opt, optSize);
	const sections = Array.from({ length: n }, (_, i) => {
		const o = opt + optSize + i * 40;
		bounds(o, 40);
		return { rva: u32(o + 12), size: u32(o + 16), raw: u32(o + 20) };
	});
	const rva = (address: number, size: number) => {
		const matches = sections.filter(
			(s) => address >= s.rva && address + size <= s.rva + s.size,
		);
		if (matches.length !== 1) throw new Error("Unmapped/ambiguous managed RVA");
		const o = matches[0].raw + address - matches[0].rva;
		bounds(o, size);
		return o;
	};
	if (u32(dir + 14 * 8 + 4) < 72) throw new Error("CLI directory is truncated");
	const cli = rva(u32(dir + 14 * 8), 72);
	if (u32(cli) < 72) throw new Error("Invalid CLI header");
	const md = rva(u32(cli + 8), u32(cli + 12)),
		mdSize = u32(cli + 12);
	if (u32(md) !== 0x424a5342) throw new Error("Invalid CLR metadata signature");
	const within = (o: number, size: number) => {
		bounds(o, size);
		if (o < md || o + size > md + mdSize)
			throw new Error("Metadata stream escapes declared root");
	};
	const vlen = u32(md + 12);
	if (vlen > 1024) throw new Error("Metadata version budget");
	let cursor = md + 16 + ((vlen + 3) & ~3);
	within(cursor, 4);
	const count = u16(cursor + 2);
	cursor += 4;
	if (count > 16) throw new Error("Metadata stream budget");
	const streams = new Map<string, { offset: number; size: number }>();
	for (let i = 0; i < count; i++) {
		within(cursor, 8);
		const offset = md + u32(cursor),
			size = u32(cursor + 4);
		within(offset, size);
		let end = cursor + 8;
		while (end < cursor + 40 && end < md + mdSize && b[end] !== 0) end++;
		within(end, 1);
		if (b[end] !== 0) throw new Error("Invalid stream name");
		const name = b.subarray(cursor + 8, end).toString("ascii");
		if (streams.has(name)) throw new Error("Duplicate metadata stream");
		streams.set(name, { offset, size });
		cursor = cursor + 8 + ((end - (cursor + 8) + 1 + 3) & ~3);
	}
	const ranges = [...streams.values()].sort((a, b) => a.offset - b.offset);
	for (let i = 0; i < ranges.length; i++) {
		if (
			ranges[i].offset < cursor ||
			(i > 0 && ranges[i].offset < ranges[i - 1].offset + ranges[i - 1].size)
		)
			throw new Error("Overlapping metadata streams");
	}
	const strings = streams.get("#Strings"),
		tables = streams.get("#~");
	if (!strings || !tables)
		throw new Error("Unsupported metadata heaps/tables; #~ required");
	const str = (index: number) => {
		if (index >= strings.size)
			throw new Error("String heap index outside range");
		let end = strings.offset + index;
		while (
			end < strings.offset + strings.size &&
			b[end] !== 0 &&
			end - strings.offset - index <= 256
		)
			end++;
		if (b[end] !== 0 || end >= strings.offset + strings.size)
			throw new Error("Unbounded metadata string");
		return b.subarray(strings.offset + index, end).toString("utf8");
	};
	within(tables.offset, 24);
	const heap = b[tables.offset + 6],
		valid = b.readBigUInt64LE(tables.offset + 8),
		rows = Array<number>(64).fill(0);
	let rowCursor = tables.offset + 24;
	for (let i = 0; i < 64; i++)
		if (valid & (BigInt(1) << BigInt(i))) {
			within(rowCursor, 4);
			rows[i] = u32(rowCursor);
			rowCursor += 4;
			if (i > 44 || rows[i] > 100000)
				throw new Error("Unsupported metadata table/row budget");
		}
	const width = (col: string): number =>
		col === "u2"
			? 2
			: col === "u4"
				? 4
				: col === "s"
					? heap & 1
						? 4
						: 2
					: col === "g"
						? heap & 2
							? 4
							: 2
						: col === "b"
							? heap & 4
								? 4
								: 2
							: col.startsWith("T")
								? rows[Number(col.slice(1))] >= 65536
									? 4
									: 2
								: (() => {
										const [bits, t] = coded[col.slice(1)];
										return Math.max(...t.map((i) => rows[i])) >=
											2 ** (16 - bits)
											? 4
											: 2;
									})();
	const offsets: number[] = [],
		widths: number[] = [];
	for (let i = 0; i < 45; i++) {
		offsets[i] = rowCursor;
		widths[i] = schema[i].split(" ").reduce((s, c) => s + width(c), 0);
		rowCursor += rows[i] * widths[i];
		if (rowCursor > tables.offset + tables.size)
			throw new Error("Metadata rows exceed table stream");
	}
	const values = (table: number, index: number) => {
		if (!schema[table] || index < 0 || index >= rows[table])
			throw new Error("Metadata token row outside table");
		let o = offsets[table] + index * widths[table];
		return schema[table].split(" ").map((c) => {
			const w = width(c),
				v = w === 2 ? u16(o) : u32(o);
			o += w;
			return v;
		});
	};
	const userString = (index: number) => {
		const heap = streams.get("#US");
		if (!heap || index < 1 || index >= heap.size)
			throw new Error("User-string heap index outside range");
		let at = heap.offset + index;
		const end = heap.offset + heap.size;
		const read = () => {
			if (at >= end) throw new Error("Truncated user-string length");
			return b[at++];
		};
		const first = read();
		let length: number;
		if (first < 128) length = first;
		else if ((first & 192) === 128) length = ((first & 63) << 8) | read();
		else if ((first & 224) === 192)
			length =
				(first & 31) * 16777216 + (read() << 16) + (read() << 8) + read();
		else throw new Error("Reserved compressed user-string length");
		if (!length || length > 4097 || length % 2 !== 1 || at + length > end)
			throw new Error("Invalid/budgeted user-string bytes");
		const bytes = b.subarray(at, at + length - 1);
		const value = bytes.toString("utf16le");
		return {
			kind: "user-string",
			preview: value.slice(0, 160),
			truncated: value.length > 160,
			sha256: byteDigest(bytes),
		};
	};
	const signature = (
		index: number,
		expected: "method" | "field" | "member" = "member",
	) => {
		const heap = streams.get("#Blob");
		try {
			if (!heap || index < 1 || index >= heap.size)
				throw new Error("Signature heap index outside range");
			let at = heap.offset + index;
			const end = heap.offset + heap.size;
			const read = () => {
				if (at >= end) throw new Error("Truncated signature blob length");
				return b[at++];
			};
			const first = read();
			let length: number;
			if (first < 128) length = first;
			else if ((first & 192) === 128) {
				length = ((first & 63) << 8) | read();
				if (length < 128) throw new Error("Noncanonical blob length");
			} else if ((first & 224) === 192) {
				length =
					(first & 31) * 16777216 + (read() << 16) + (read() << 8) + read();
				if (length < 16384) throw new Error("Noncanonical blob length");
			} else throw new Error("Reserved signature blob length");
			if (length > 256 || at + length > end)
				throw new Error("Signature blob range/budget exceeded");
			return inspectManagedSignature(b.subarray(at, at + length), expected);
		} catch (e) {
			return {
				status: "partial",
				reason: e instanceof Error ? e.message : "Unsupported signature heap",
			};
		}
	};
	const ownerStarts: number[] = [];
	let ownersValid = !rows[5];
	for (let i = 0; i < rows[2]; i++) {
		const first = values(2, i)[5];
		if (
			first < 1 ||
			first > rows[6] + 1 ||
			(i > 0 && first < ownerStarts[i - 1])
		)
			ownersValid = false;
		ownerStarts.push(first);
	}
	const declaringType = (methodRow: number) => {
		if (!ownersValid)
			return "unknown:invalid-or-pointer-indirected-method-lists";
		let lo = 0,
			hi = ownerStarts.length;
		while (lo < hi) {
			const mid = Math.floor((lo + hi) / 2);
			if (ownerStarts[mid] <= methodRow) lo = mid + 1;
			else hi = mid;
		}
		if (!lo) return "unknown:unowned-method-row";
		const row = lo - 1,
			v = values(2, row),
			name = str(v[1]),
			namespace = str(v[2]);
		return {
			token: `0x${(0x02000001 + row).toString(16)}`,
			name: name.slice(0, 60),
			namespace: namespace.slice(0, 60),
			namesTruncated: name.length > 60 || namespace.length > 60,
		};
	};
	const resolveToken = (token: string) => {
		const n = Number.parseInt(token.slice(2), 16),
			table = n >>> 24,
			index = (n & 0xffffff) - 1;
		try {
			if (table === 0x70) return userString(n & 0xffffff);
			if (![1, 2, 4, 6, 10].includes(table))
				return { kind: "unresolved-token", token };
			const v = values(table, index);
			return {
				kind: "metadata-declaration",
				table,
				name: str(v[table === 6 ? 3 : 1]).slice(0, 80),
				namesTruncated:
					str(v[table === 6 ? 3 : 1]).length > 80 ||
					((table === 1 || table === 2) && str(v[2]).length > 120),
				...(table === 6
					? {
							declaringType: declaringType(index + 1),
							signature: signature(v[4], "method"),
						}
					: {}),
				...(table === 4 || table === 10
					? { signature: signature(v[2], table === 4 ? "field" : "member") }
					: {}),
				...(table === 10 ? { parentCodedIndex: v[0] } : {}),
				...(table === 1 || table === 2
					? { namespace: str(v[2]).slice(0, 120) }
					: {}),
			};
		} catch {
			return {
				kind: "unresolved-token",
				token,
				reason: "Invalid, unsupported or budgeted heap/table reference",
			};
		}
	};
	const records: ManagedRecord[] = [],
		limitations = [
			"Static metadata declarations, bounded decoded IL and normal-flow candidates only; no CLR execution, decompilation, obfuscation recovery or behavioral proof.",
		];
	const add = (r: ManagedRecord) => {
		if (records.length < budget) records.push(r);
		else if (!limitations.includes("Managed record budget reached"))
			limitations.push("Managed record budget reached");
	};
	for (let i = 0; i < Math.min(rows[2], budget); i++) {
		const v = values(2, i);
		add({
			kind: "managed-type",
			offset: offsets[2] + i * widths[2],
			value: JSON.stringify({
				token: `0x${(0x02000001 + i).toString(16)}`,
				name: str(v[1]),
				namespace: str(v[2]),
				flags: v[0],
			}),
		});
	}
	for (let i = 0; i < Math.min(rows[6], budget); i++) {
		const v = values(6, i),
			token = `0x${(0x06000001 + i).toString(16)}`;
		add({
			kind: "managed-method",
			offset: offsets[6] + i * widths[6],
			value: JSON.stringify({
				token,
				name: str(v[3]),
				rva: v[0],
				flags: v[2],
				implementationFlags: v[1],
				declaringType: declaringType(i + 1),
				signature: signature(v[4], "method"),
			}),
		});
	}
	for (let i = 0; i < Math.min(rows[6], budget); i++) {
		if (records.length >= budget) {
			if (!limitations.includes("Managed record budget reached"))
				limitations.push("Managed record budget reached");
			break;
		}
		const v = values(6, i),
			token = `0x${(0x06000001 + i).toString(16)}`;
		if (!v[0] || v[1] & 3) continue;
		try {
			const body = rva(v[0], 1),
				tag = b[body] & 3;
			let header: number, length: number;
			if (tag === 2) {
				header = 1;
				length = b[body] >> 2;
			} else if (tag === 3) {
				header = (u16(body) >> 12) * 4;
				if (header < 12 || header > 60)
					throw new Error("Unsupported IL header");
				rva(v[0], header);
				length = u32(body + 4);
			} else throw new Error("Unsupported IL body");
			if (length > 4096) throw new Error("IL byte budget exceeded");
			rva(v[0], header + length);
			add({
				kind: "managed-il",
				offset: body + header,
				value: JSON.stringify({
					methodToken: token,
					byteLength: length,
					hex: b
						.subarray(body + header, body + header + Math.min(length, 256))
						.toString("hex"),
					truncated: length > 256,
				}),
			});
			const decoded = decodeIL(
				b.subarray(body + header, body + header + length),
			);
			const stackModel =
				tag === 3 && u16(body) & 8
					? {
							status: "partial",
							reason:
								"Exception-bearing method has no straight-line semantic summary",
						}
					: modelManagedStack(decoded);
			add({
				kind: "managed-stack-model",
				offset: body + header,
				value: JSON.stringify({ methodToken: token, ...stackModel }),
			});
			for (const instruction of decoded.instructions) {
				const { bytes, operand, ...detail } = instruction;
				add({
					kind: "managed-il-instruction",
					offset: body + header + instruction.offset,
					value: JSON.stringify({
						methodToken: token,
						...detail,
						bytes: bytes.slice(0, 128),
						bytesTruncated: bytes.length > 128,
						...(Array.isArray(operand)
							? {}
							: operand !== undefined
								? { operand }
								: {}),
						...(instruction.token
							? { resolution: resolveToken(instruction.token) }
							: {}),
					}),
				});
			}
			for (const edge of decoded.edges)
				add({
					kind: "managed-control-flow",
					offset: body + header + edge.source,
					value: JSON.stringify({ methodToken: token, ...edge }),
				});
			limitations.push(
				...decoded.limitations.map((note) => `Method ${token}: ${note}`),
			);
			if (tag === 3 && u16(body) & 8) {
				const eh = inspectExceptionSections(
					b,
					v[0],
					header + length,
					length,
					decoded,
					(relative, size) => rva(v[0] + relative, size),
				);
				for (const region of eh.regions)
					add({
						kind: "managed-exception-region",
						offset: region.offset,
						value: JSON.stringify({
							methodToken: token,
							...region,
							...(region.catchTypeToken
								? { catchType: resolveToken(region.catchTypeToken) }
								: {}),
						}),
					});
				if (eh.status !== "completed")
					add({
						kind: "managed-exception-unresolved",
						offset: body,
						value: JSON.stringify({
							methodToken: token,
							reason: eh.limitations[0],
						}),
					});
				limitations.push(
					...eh.limitations.map((note) => `Method ${token}: ${note}`),
				);
			}
		} catch (e) {
			limitations.push(
				`Method ${token}: ${e instanceof Error ? e.message : "unsupported IL"}`,
			);
		}
	}
	if (rows[2] > budget || rows[6] > budget)
		limitations.push("Managed row coverage is partial");
	return { records, limitations: limitations.slice(0, 80) };
}
