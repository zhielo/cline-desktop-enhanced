import { z } from "zod";
const Address = z.number().int().min(0x100000).max(0x10ffff);
export const SymbolicOptionsSchema = z
	.object({
		entry: Address.default(0x100000),
		find: Address,
		avoid: z.array(Address).max(16).default([]),
		register: z.enum(["rdi", "rsi", "rdx", "rcx", "r8", "r9"]).default("rdi"),
		minimum: z.number().int().min(0).max(0xffffffff).default(0),
		maximum: z.number().int().min(0).max(0xffffffff).default(255),
		max_steps: z.number().int().min(1).max(1024).default(128),
		max_states: z.number().int().min(1).max(128).default(32),
	})
	.strict()
	.refine(
		(v) => v.minimum <= v.maximum && !v.avoid.includes(v.find),
		"Conflicting symbolic bounds or target",
	);
const Identifier = z.string().regex(/^[A-Za-z_$][A-Za-z0-9_.$]{0,127}$/);
export const JoernOptionsSchema = z
	.object({
		language: z.enum(["javascript", "java"]),
		query: z.enum(["callers", "references", "source-sink"]),
		selector: Identifier,
		sink: Identifier.optional(),
		input_basis: z.enum(["source", "decompiler-output"]).default("source"),
	})
	.strict()
	.refine(
		(v) => v.query !== "source-sink" || !!v.sink,
		"source-sink requires an exact sink",
	);
export const SpecialistReadinessSchema = z
	.object({ engine: z.enum(["angr", "joern"]) })
	.strict();
