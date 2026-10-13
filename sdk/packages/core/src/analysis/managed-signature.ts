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
		if (code === 17 || code === 18) {
			const token = compressed(),
				tag = token & 3,
				row = token >>> 2;
			if (!row || tag === 3)
				throw new Error("Invalid TypeDefOrRef signature token");
			return `${code === 17 ? "valuetype" : "class"}:${["TypeDef", "TypeRef", "TypeSpec"][tag]}#${row}`;
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
