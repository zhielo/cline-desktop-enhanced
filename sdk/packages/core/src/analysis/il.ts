/** Bounded ECMA-335 instruction decoding. No CLR, JIT, reflection or target execution. */
type Operand =
	| "none"
	| "var8"
	| "var16"
	| "i8"
	| "i32"
	| "i64"
	| "r32"
	| "r64"
	| "token"
	| "branch8"
	| "branch32"
	| "switch";
type Flow =
	| "next"
	| "branch"
	| "conditional"
	| "switch"
	| "return"
	| "call"
	| "prefix";
type Opcode = { name: string; operand: Operand; flow: Flow };
const ops = new Map<number, Opcode>();
const put = (
	code: number,
	name: string,
	operand: Operand = "none",
	flow: Flow = "next",
) => ops.set(code, { name, operand, flow });
const range = (
	code: number,
	names: string,
	operand: Operand = "none",
	flow: Flow = "next",
) =>
	names.split(" ").forEach((n, i) => {
		put(code + i, n, operand, flow);
	});
range(
	0,
	"nop break ldarg.0 ldarg.1 ldarg.2 ldarg.3 ldloc.0 ldloc.1 ldloc.2 ldloc.3 stloc.0 stloc.1 stloc.2 stloc.3",
);
range(0x0e, "ldarg.s ldarga.s starg.s ldloc.s ldloca.s stloc.s", "var8");
range(
	0x14,
	"ldnull ldc.i4.m1 ldc.i4.0 ldc.i4.1 ldc.i4.2 ldc.i4.3 ldc.i4.4 ldc.i4.5 ldc.i4.6 ldc.i4.7 ldc.i4.8",
);
put(0x1f, "ldc.i4.s", "i8");
put(0x20, "ldc.i4", "i32");
put(0x21, "ldc.i8", "i64");
put(0x22, "ldc.r4", "r32");
put(0x23, "ldc.r8", "r64");
range(0x25, "dup pop");
put(0x27, "jmp", "token", "return");
put(0x28, "call", "token", "call");
put(0x29, "calli", "token", "call");
put(0x2a, "ret", "none", "return");
put(0x2b, "br.s", "branch8", "branch");
range(
	0x2c,
	"brfalse.s brtrue.s beq.s bge.s bgt.s ble.s blt.s bne.un.s bge.un.s bgt.un.s ble.un.s blt.un.s",
	"branch8",
	"conditional",
);
put(0x38, "br", "branch32", "branch");
range(
	0x39,
	"brfalse brtrue beq bge bgt ble blt bne.un bge.un bgt.un ble.un blt.un",
	"branch32",
	"conditional",
);
put(0x45, "switch", "switch", "switch");
range(
	0x46,
	"ldind.i1 ldind.u1 ldind.i2 ldind.u2 ldind.i4 ldind.u4 ldind.i8 ldind.i ldind.r4 ldind.r8 ldind.ref stind.ref stind.i1 stind.i2 stind.i4 stind.i8 stind.r4 stind.r8 add sub mul div div.un rem rem.un and or xor shl shr shr.un neg not conv.i1 conv.i2 conv.i4 conv.i8 conv.r4 conv.r8 conv.u4 conv.u8",
);
put(0x6f, "callvirt", "token", "call");
range(0x70, "cpobj ldobj ldstr newobj castclass isinst", "token");
put(0x73, "newobj", "token", "call");
put(0x76, "conv.r.un");
put(0x79, "unbox", "token");
put(0x7a, "throw", "none", "return");
range(0x7b, "ldfld ldflda stfld ldsfld ldsflda stsfld stobj", "token");
range(
	0x82,
	"conv.ovf.i1.un conv.ovf.i2.un conv.ovf.i4.un conv.ovf.i8.un conv.ovf.u1.un conv.ovf.u2.un conv.ovf.u4.un conv.ovf.u8.un conv.ovf.i.un conv.ovf.u.un",
);
range(0x8c, "box newarr", "token");
put(0x8e, "ldlen");
put(0x8f, "ldelema", "token");
range(
	0x90,
	"ldelem.i1 ldelem.u1 ldelem.i2 ldelem.u2 ldelem.i4 ldelem.u4 ldelem.i8 ldelem.i ldelem.r4 ldelem.r8 ldelem.ref stelem.i stelem.i1 stelem.i2 stelem.i4 stelem.i8 stelem.r4 stelem.r8 stelem.ref",
);
range(0xa3, "ldelem stelem unbox.any", "token");
range(
	0xb3,
	"conv.ovf.i1 conv.ovf.u1 conv.ovf.i2 conv.ovf.u2 conv.ovf.i4 conv.ovf.u4 conv.ovf.i8 conv.ovf.u8",
);
put(0xc2, "refanyval", "token");
put(0xc3, "ckfinite");
put(0xc6, "mkrefany", "token");
put(0xd0, "ldtoken", "token");
range(
	0xd1,
	"conv.u2 conv.u1 conv.i conv.ovf.i conv.ovf.u add.ovf add.ovf.un mul.ovf mul.ovf.un sub.ovf sub.ovf.un",
);
put(0xdc, "endfinally", "none", "return");
put(0xdd, "leave", "branch32", "branch");
put(0xde, "leave.s", "branch8", "branch");
range(0xdf, "stind.i conv.u");
range(0xfe00, "arglist ceq cgt cgt.un clt clt.un");
range(0xfe06, "ldftn ldvirtftn", "token");
range(0xfe09, "ldarg ldarga starg ldloc ldloca stloc", "var16");
put(0xfe0f, "localloc");
put(0xfe11, "endfilter", "none", "return");
put(0xfe12, "unaligned.", "var8", "prefix");
put(0xfe13, "volatile.", "none", "prefix");
put(0xfe14, "tail.", "none", "prefix");
put(0xfe15, "initobj", "token");
put(0xfe16, "constrained.", "token", "prefix");
range(0xfe17, "cpblk initblk");
put(0xfe19, "no.", "var8", "prefix");
put(0xfe1a, "rethrow", "none", "return");
put(0xfe1c, "sizeof", "token");
put(0xfe1d, "refanytype");
put(0xfe1e, "readonly.", "none", "prefix");
export type ILInstruction = {
	offset: number;
	size: number;
	opcode: string;
	bytes: string;
	operand?: number | string | number[];
	token?: string;
	targets?: number[];
	flow: Flow;
};
export type ILDecoded = {
	status: "completed" | "partial" | "invalid";
	instructions: ILInstruction[];
	edges: Array<{
		source: number;
		target: number;
		kind: "fallthrough" | "branch" | "switch";
	}>;
	limitations: string[];
};
export function decodeIL(input: Uint8Array, limit = 512): ILDecoded {
	const b = Buffer.from(input),
		instructions: ILInstruction[] = [],
		starts = new Set<number>();
	let offset = 0,
		bundle: number | undefined;
	const result = (status: ILDecoded["status"], note: string): ILDecoded => ({
		status,
		instructions,
		edges: [],
		limitations: [
			note,
			"Normal IL control-flow candidates only; exception edges, stack/type verification, reachability and execution are not established.",
		],
	});
	try {
		if (
			b.length > 4096 ||
			!Number.isSafeInteger(limit) ||
			limit < 1 ||
			limit > 512
		)
			return result("partial", "IL byte/instruction budget exceeded");
		const need = (n: number) => {
			if (offset + n > b.length) throw new Error("Truncated IL operand");
		};
		while (offset < b.length) {
			if (instructions.length >= limit)
				return result(
					"partial",
					"IL instruction budget reached; remaining bytes were not decoded",
				);
			const at = offset;
			need(1);
			let code = b[offset++];
			if (code === 0xfe) {
				need(1);
				code = 0xfe00 | b[offset++];
			}
			const op = ops.get(code);
			if (!op)
				return result(
					"partial",
					`Unsupported/reserved IL opcode at ${at}; no byte resynchronization attempted`,
				);
			if (bundle === undefined) bundle = at;
			let operand: ILInstruction["operand"],
				token: string | undefined,
				targets: number[] | undefined;
			switch (op.operand) {
				case "var8":
					need(1);
					operand = b[offset++];
					break;
				case "i8":
					need(1);
					operand = b.readInt8(offset++);
					break;
				case "var16":
					need(2);
					operand = b.readUInt16LE(offset);
					offset += 2;
					break;
				case "i32":
				case "branch32":
					need(4);
					operand = b.readInt32LE(offset);
					offset += 4;
					break;
				case "branch8":
					need(1);
					operand = b.readInt8(offset++);
					break;
				case "token":
					need(4);
					operand = b.readUInt32LE(offset);
					token = `0x${operand.toString(16).padStart(8, "0")}`;
					offset += 4;
					break;
				case "i64":
					need(8);
					operand = b.readBigInt64LE(offset).toString();
					offset += 8;
					break;
				case "r32":
				case "r64": {
					const size = op.operand === "r32" ? 4 : 8;
					need(size);
					const value =
						size === 4 ? b.readFloatLE(offset) : b.readDoubleLE(offset);
					operand = Number.isFinite(value) ? value : String(value);
					offset += size;
					break;
				}
				case "switch": {
					need(4);
					const count = b.readUInt32LE(offset);
					offset += 4;
					if (count > 32)
						return result("partial", "IL switch target budget exceeded");
					need(count * 4);
					const base = offset + count * 4;
					targets = Array.from(
						{ length: count },
						(_, i) => base + b.readInt32LE(offset + i * 4),
					);
					offset = base;
					operand = targets;
					break;
				}
			}
			if (op.operand === "branch8" || op.operand === "branch32")
				targets = [offset + (operand as number)];
			instructions.push({
				offset: at,
				size: offset - at,
				opcode: op.name,
				bytes: b.subarray(at, offset).toString("hex"),
				...(operand !== undefined ? { operand } : {}),
				...(token ? { token } : {}),
				...(targets ? { targets } : {}),
				flow: op.flow,
			});
			if (op.flow !== "prefix") {
				starts.add(bundle);
				bundle = undefined;
			}
		}
		if (bundle !== undefined) return result("invalid", "Dangling IL prefix");
		for (const i of instructions)
			for (const t of i.targets ?? [])
				if (!starts.has(t))
					return result(
						"invalid",
						`IL branch target ${t} is outside a decoded instruction bundle boundary`,
					);
		const edges: ILDecoded["edges"] = [];
		for (const i of instructions) {
			if (
				i.flow === "branch" ||
				i.flow === "conditional" ||
				i.flow === "switch"
			)
				for (const target of i.targets ?? [])
					edges.push({
						source: i.offset,
						target,
						kind: i.flow === "switch" ? "switch" : "branch",
					});
			if (
				!["return", "branch"].includes(i.flow) &&
				i.offset + i.size < b.length
			)
				edges.push({
					source: i.offset,
					target: i.offset + i.size,
					kind: "fallthrough",
				});
		}
		return {
			status: "completed",
			instructions,
			edges,
			limitations: [
				"Normal IL flow candidates only; exception dispatch, stack/type verification, reachability and execution are not established.",
			],
		};
	} catch (e) {
		return result("invalid", e instanceof Error ? e.message : "Malformed IL");
	}
}
