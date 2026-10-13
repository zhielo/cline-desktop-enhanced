import { byteDigest } from "./contracts";
/** Static, bounded signature display; never reflection, CLR loading or type resolution. */
export function inspectManagedSignature(
	input: Uint8Array,
	expected: "method" | "field" | "member" = "member",
) {
	const b = Buffer.from(input),
		provenance = {
			sha256: byteDigest(b),
			byteLength: b.length,
			hex: b.subarray(0, 32).toString("hex"),
			truncated: b.length > 32,
		};
	let at = 0,
		nodes = 0,
		fieldMode = false;
	const byte = () => {
		if (at >= b.length) throw new Error("Truncated signature");
		return b[at++];
	};
	const compressed = () => {
		const first = byte();
		if (first < 128) return first;
		if ((first & 192) === 128) {
			const n = ((first & 63) << 8) | byte();
			if (n < 128) throw new Error("Noncanonical compressed integer");
			return n;
		}
		if ((first & 224) === 192) {
			const n =
				(first & 31) * 16777216 + (byte() << 16) + (byte() << 8) + byte();
			if (n < 16384) throw new Error("Noncanonical compressed integer");
			return n;
		}
		throw new Error("Reserved compressed integer");
	};
	const signedCompressed = () => {
		const first = byte();
		let raw: number, bits: number;
		if (first < 128) {
			raw = first;
			bits = 6;
		} else if ((first & 192) === 128) {
			raw = ((first & 63) << 8) | byte();
			bits = 13;
		} else if ((first & 224) === 192) {
			raw = (first & 31) * 16777216 + (byte() << 16) + (byte() << 8) + byte();
			bits = 28;
		} else throw new Error("Reserved signed compressed integer");
		const value = Math.floor(raw / 2) - (raw & 1 ? 2 ** bits : 0);
		if (
			(bits > 6 && value >= -64 && value <= 63) ||
			(bits > 13 && value >= -8192 && value <= 8191)
		)
			throw new Error("Noncanonical signed compressed integer");
		return value;
	};
	const reference = () => {
		const token = compressed(),
			tag = token & 3,
			row = token >>> 2;
		if (!row || tag === 3)
			throw new Error("Invalid TypeDefOrRef signature token");
		return `${["TypeDef", "TypeRef", "TypeSpec"][tag]}#${row}`;
	};
	const primitives: Record<number, string> = {
		1: "void",
		2: "bool",
		3: "char",
		4: "int8",
		5: "uint8",
		6: "int16",
		7: "uint16",
		8: "int32",
		9: "uint32",
		10: "int64",
		11: "uint64",
		12: "float32",
		13: "float64",
		14: "string",
		22: "typedref",
		24: "native-int",
		25: "native-uint",
		28: "object",
	};
	const type = (depth = 0, allowVoid = false): string => {
		if (++nodes > 64 || depth > 4)
			throw new Error("Signature type budget exceeded");
		const code = byte();
		if (primitives[code]) {
			if (code === 22 && (fieldMode || depth > 0))
				throw new Error("Invalid nested/field typedref");
			if (code === 1 && !allowVoid) throw new Error("Void parameter/element");
			return primitives[code];
		}
		if (code === 15) return `${type(depth + 1, true)}*`;
		if (code === 16 && (depth > 0 || fieldMode))
			throw new Error("Nested byref is unsupported/invalid");
		if (code === 16) return `${type(depth + 1)}&`;
		if (code === 29) return `${type(depth + 1)}[]`;
		if (code === 19 || code === 30)
			return `${code === 19 ? "!" : "!!"}${compressed()}`;
		if (code === 17 || code === 18)
			return `${code === 17 ? "valuetype" : "class"}:${reference()}`;
		if (code === 31 || code === 32) {
			const token = reference();
			return `${code === 31 ? "modreq" : "modopt"}(${token}) ${type(depth + 1, allowVoid)}`;
		}
		if (code === 21) {
			const category = byte();
			if (category !== 17 && category !== 18)
				throw new Error("Invalid genericinst category");
			const token = reference(),
				count = compressed();
			if (count < 1 || count > 16) throw new Error("Generic argument budget");
			const arguments_: string[] = [];
			for (let i = 0; i < count; i++) arguments_.push(type(depth + 1));
			return `${category === 17 ? "valuetype" : "class"}:${token}<${arguments_.join(", ")}>`;
		}
		if (code === 20) {
			const element = type(depth + 1),
				rank = compressed();
			if (rank < 1 || rank > 8) throw new Error("Array rank budget");
			const sizesCount = compressed();
			if (sizesCount > rank) throw new Error("Array sizes exceed rank");
			const sizes: number[] = [];
			for (let i = 0; i < sizesCount; i++) sizes.push(compressed());
			const lowerCount = compressed();
			if (lowerCount > rank) throw new Error("Array lower bounds exceed rank");
			const lower: number[] = [];
			for (let i = 0; i < lowerCount; i++) lower.push(signedCompressed());
			return `${element}[rank=${rank};sizes=${sizes.join(",")};lower=${lower.join(",")}]`;
		}
		if (code === 27) {
			const flags = byte(),
				convention = flags & 15;
			if (
				flags & 128 ||
				(flags & 64 && !(flags & 32)) ||
				convention > 5 ||
				(flags & 16 && convention !== 0 && convention !== 5)
			)
				throw new Error("Invalid function-pointer convention");
			const arity = flags & 16 ? compressed() : 0;
			if (arity > 32 || (flags & 16 && !arity))
				throw new Error("Function-pointer generic budget");
			const count = compressed();
			if (count > 8) throw new Error("Function-pointer parameter budget");
			const result = type(depth + 1, true),
				parameters: string[] = [];
			let sentinel = false;
			for (let i = 0; i < count; i++) {
				if (b[at] === 65) {
					if (convention !== 5 || sentinel)
						throw new Error("Invalid vararg sentinel");
					byte();
					sentinel = true;
					parameters.push("...");
				}
				parameters.push(type(depth + 1));
			}
			return `fnptr[cc=${flags};arity=${arity}] ${result} (${parameters.join(", ")})`;
		}
		throw new Error(`Unsupported signature element 0x${code.toString(16)}`);
	};
	try {
		if (b.length > 256) throw new Error("Signature byte budget exceeded");
		const flags = byte();
		let display: string,
			parameterCount: number | undefined,
			genericArity: number | undefined;
		if (flags === 6) {
			if (expected === "method")
				throw new Error("Field signature in method row");
			fieldMode = true;
			display = type();
		} else {
			if (expected === "field")
				throw new Error("Method signature in field row");
			if ((flags & 15) !== 0 || flags & 128 || (flags & 64 && !(flags & 32)))
				throw new Error("Unsupported/invalid calling convention");
			genericArity = flags & 16 ? compressed() : 0;
			if (flags & 16 && genericArity === 0)
				throw new Error("Empty generic arity");
			if (genericArity > 32) throw new Error("Generic arity budget exceeded");
			parameterCount = compressed();
			if (parameterCount > 8) throw new Error("Parameter budget exceeded");
			const result = type(0, true),
				parameters = [];
			for (let i = 0; i < parameterCount; i++) parameters.push(type());
			display = `${result} (${parameters.join(", ")})`;
		}
		if (at !== b.length)
			throw new Error("Trailing/unsupported signature bytes");
		if (display.length > 240)
			throw new Error("Signature display budget exceeded");
		return {
			status: "completed" as const,
			...provenance,
			display,
			callingConvention: flags,
			scope: "syntax-only-unresolved-type-references",
			...(parameterCount !== undefined ? { parameterCount, genericArity } : {}),
		};
	} catch (e) {
		return {
			status: "partial" as const,
			...provenance,
			reason: e instanceof Error ? e.message : "Malformed signature",
		};
	}
}
