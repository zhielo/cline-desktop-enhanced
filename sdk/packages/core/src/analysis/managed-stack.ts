import type { ILDecoded } from "./il";
/** Bounded straight-line Int32/local/argument model. Unsupported instructions invalidate the summary. */
export function modelManagedStack(decoded: ILDecoded) {
	type Value =
		| { kind: "int32"; value: number }
		| { kind: "argument"; index: number }
		| { kind: "expression"; operation: string; left: Value; right?: Value };
	const weight = new Map<Value, number>();
	const cost = (v: Value) => weight.get(v) ?? 45;
	const stack: Value[] = [],
		locals = new Map<number, Value>();
	let nodes = 0;
	const limitations = [
		"Straight-line unchecked Int32 model only. No CLR execution, type/stack verification, branches, calls, exception dispatch, aliasing, managed memory or whole-function equivalence.",
	];
	const unknown = (reason: string) => ({
		status: "partial" as const,
		reason,
		limitations,
	});
	const pop = () => {
		const value = stack.pop();
		if (!value) throw new Error("Stack underflow");
		return value;
	};
	try {
		if (decoded.status !== "completed") return unknown("IL decode incomplete");
		for (const [at, i] of decoded.instructions.entries()) {
			if (++nodes > 128) return unknown("Stack expression budget");
			const op = i.opcode;
			if (op === "nop") continue;
			if (op.startsWith("ldc.i4")) {
				const tail = op.slice(7);
				let value: number;
				if (op === "ldc.i4" || op === "ldc.i4.s") value = Number(i.operand);
				else if (tail === "m1") value = -1;
				else value = Number(tail);
				if (
					!Number.isInteger(value) ||
					value < -2147483648 ||
					value > 2147483647
				)
					return unknown("Invalid Int32 constant");
				stack.push({ kind: "int32", value });
			} else if (
				/^ldarg\.[0-3]$/.test(op) ||
				op === "ldarg" ||
				op === "ldarg.s"
			) {
				const index = /^ldarg\.[0-3]$/.test(op)
					? Number(op.slice(-1))
					: Number(i.operand);
				if (!Number.isInteger(index) || index < 0 || index > 64)
					return unknown("Argument model budget");
				stack.push({ kind: "argument", index });
			} else if (
				/^ldloc\.[0-3]$/.test(op) ||
				op === "ldloc" ||
				op === "ldloc.s"
			) {
				const index = /^ldloc\.[0-3]$/.test(op)
						? Number(op.slice(-1))
						: Number(i.operand),
					value = locals.get(index);
				if (!value) return unknown("Uninitialized/unmodeled local");
				stack.push(value);
			} else if (
				/^stloc\.[0-3]$/.test(op) ||
				op === "stloc" ||
				op === "stloc.s"
			) {
				const index = /^stloc\.[0-3]$/.test(op)
					? Number(op.slice(-1))
					: Number(i.operand);
				if (!Number.isInteger(index) || index < 0 || index > 64)
					return unknown("Local model budget");
				locals.set(index, pop());
			} else if (op === "dup") {
				const value = pop();
				stack.push(value, value);
			} else if (op === "pop") pop();
			else if (["add", "sub", "mul", "xor", "and", "or"].includes(op)) {
				const right = pop(),
					left = pop();
				if (left.kind === "int32" && right.kind === "int32") {
					const a = left.value,
						b = right.value;
					const value =
						op === "add"
							? (a + b) | 0
							: op === "sub"
								? (a - b) | 0
								: op === "mul"
									? Math.imul(a, b)
									: op === "xor"
										? a ^ b
										: op === "and"
											? a & b
											: a | b;
					stack.push({ kind: "int32", value });
				} else {
					const size = 70 + cost(left) + cost(right);
					if (size > 512) return unknown("Stack expression expansion budget");
					const value: Value = {
						kind: "expression",
						operation: op,
						left,
						right,
					};
					weight.set(value, size);
					stack.push(value);
				}
			} else if (op === "neg" || op === "not") {
				const left = pop();
				if (left.kind === "int32")
					stack.push({
						kind: "int32",
						value: op === "neg" ? -left.value | 0 : ~left.value,
					});
				else {
					const size = 60 + cost(left);
					if (size > 512) return unknown("Stack expression expansion budget");
					const value: Value = { kind: "expression", operation: op, left };
					weight.set(value, size);
					stack.push(value);
				}
			} else if (op === "ret") {
				if (at !== decoded.instructions.length - 1 || stack.length > 1)
					return unknown("Non-terminal/invalid modeled return");
				const result = {
					status: "completed" as const,
					returnValue: stack.length ? pop() : { kind: "void" },
					modeledInstructions: at + 1,
					limitations,
				};
				if (JSON.stringify(result).length > 850)
					return unknown("Stack summary display budget");
				return result;
			} else return unknown(`Unsupported semantic instruction: ${op}`);
			if (stack.length > 64) return unknown("Stack depth budget");
		}
		return unknown("No terminal return");
	} catch (e) {
		return unknown(e instanceof Error ? e.message : "Invalid stack model");
	}
}
