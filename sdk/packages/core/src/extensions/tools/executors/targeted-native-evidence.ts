import { lstat, readFile } from "node:fs/promises";
import { z } from "zod";
const Address = z.string().regex(/^0x[a-f0-9]{1,16}$/);
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
		coverage: z.literal(
			"selected-function-decompiler-and-bounded-high-pcode-not-runtime",
		),
	})
	.strict();
export async function loadTargetedNativeEvidence(outputPath: string) {
	const file = `${outputPath}.native.json`,
		stat = await lstat(file);
	if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 2 * 1024 * 1024)
		throw new Error("Selected native evidence range/type budget");
	const bytes = await readFile(file);
	if (bytes.length > 2 * 1024 * 1024)
		throw new Error("Selected native evidence grew beyond budget");
	return TargetedNativeEvidenceSchema.parse(JSON.parse(bytes.toString("utf8")));
}
