import { lstat, readFile } from "node:fs/promises";
import { z } from "zod";
const Address = z.string().regex(/^0x[a-f0-9]{1,16}$/);
const ValueFlowFields = {
	sources: z
		.array(
			z.discriminatedUnion("kind", [
				z
					.object({
						kind: z.literal("constant"),
						valueHex: Address,
						bytes: z.number().int().min(1).max(8),
					})
					.strict(),
				z
					.object({
						kind: z.literal("parameter"),
						parameterIndex: z.number().int().min(0).max(65535),
					})
					.strict(),
				z
					.object({ kind: z.literal("call-return"), fromAddressHex: Address })
					.strict(),
			]),
		)
		.max(32),
	frontiers: z.array(z.string().min(1).max(120)).max(16),
	visited: z.number().int().nonnegative().max(256),
	coverage: z.literal(
		"bounded-selected-function-def-use-dependencies-not-value-equivalence",
	),
};
export const NativeValueFlowSchema = z.object(ValueFlowFields).strict();
export const TargetedNativeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(1),
		addressHex: Address,
		name: z.string().max(4096),
		signature: z.string().max(16384),
		pseudocode: z.string().max(1000000),
		architecture: z.string().max(256),
		image: z
			.object({
				preferredBaseHex: Address,
				addressSpace: z.literal("ghidra-program-virtual"),
			})
			.strict(),
		callees: z
			.array(
				z
					.object({
						fromAddressHex: Address,
						kind: z.enum(["direct", "indirect"]),
						targetAddressHex: Address.optional(),
						argumentFlows: z
							.array(
								z
									.object({
										...ValueFlowFields,
										index: z.number().int().min(0).max(15),
									})
									.strict(),
							)
							.max(16)
							.optional(),
						argumentsTruncated: z.boolean().optional(),
						resolution: z.enum([
							"bounded-high-pcode-constant-candidate",
							"unknown-memory-register-or-ambiguous-phi",
						]),
					})
					.strict()
					.refine(
						(v) =>
							(v.resolution === "bounded-high-pcode-constant-candidate") ===
							Boolean(v.targetAddressHex),
						"Target/resolution mismatch",
					),
			)
			.max(128),
		relationsTruncated: z.boolean(),
		returnFlows: z
			.array(
				z
					.object({
						fromAddressHex: Address,
						flow: NativeValueFlowSchema.optional(),
						voidOrUnavailable: z.literal(true).optional(),
					})
					.strict()
					.refine(
						(v) => !!v.flow !== !!v.voidOrUnavailable,
						"Return flow or unavailable marker required",
					),
			)
			.max(64)
			.optional(),
		coverage: z.literal(
			"selected-function-decompiler-and-bounded-high-pcode-not-runtime",
		),
	})
	.strict();
/** IDA ctree candidates are deliberately distinct from Ghidra high-pcode evidence. */
export const TargetedIdaEvidenceSchema = z
	.object({
		schemaVersion: z.literal(1),
		addressHex: Address,
		name: z.string().max(4096),
		signature: z.string().max(16384),
		pseudocode: z.string().max(1000000),
		architecture: z.string().max(256),
		image: z
			.object({
				preferredBaseHex: Address,
				addressSpace: z.literal("ida-database-virtual"),
			})
			.strict(),
		callees: z
			.array(
				z
					.object({
						fromAddressHex: Address,
						siteResolution: z.enum(["ctree-ea", "function-entry-fallback"]),
						kind: z.enum(["direct", "indirect"]),
						targetAddressHex: Address.optional(),
						resolution: z.enum([
							"hex-rays-object-candidate",
							"unknown-expression-target",
						]),
					})
					.strict()
					.refine(
						(v) =>
							(v.resolution === "hex-rays-object-candidate") ===
								Boolean(v.targetAddressHex) &&
							(v.kind === "direct") === Boolean(v.targetAddressHex),
						"Target/resolution/kind mismatch",
					),
			)
			.max(128),
		relationsTruncated: z.boolean(),
		coverage: z.literal(
			"selected-function-decompiler-and-bounded-ctree-not-runtime",
		),
	})
	.strict();
export const SelectedNativeEvidenceSchema = z.union([
	TargetedNativeEvidenceSchema,
	TargetedIdaEvidenceSchema,
]);
export async function loadTargetedNativeEvidence(
	outputPath: string,
	engine: "ghidra" | "ida",
) {
	const file = `${outputPath}.native.json`,
		stat = await lstat(file);
	if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 2 * 1024 * 1024)
		throw new Error("Selected native evidence range/type budget");
	const bytes = await readFile(file);
	if (bytes.length > 2 * 1024 * 1024)
		throw new Error("Selected native evidence grew beyond budget");
	return (
		engine === "ida" ? TargetedIdaEvidenceSchema : TargetedNativeEvidenceSchema
	).parse(JSON.parse(bytes.toString("utf8")));
}
