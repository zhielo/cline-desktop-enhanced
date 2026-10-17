import { z } from "zod";
const Hash = z.string().regex(/^[a-f0-9]{64}$/);
const Hex = z
	.string()
	.regex(/^(?:[a-fA-F0-9]{2})+$/)
	.max(131072);
const BytePatchSchema = z
	.object({
		offset: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
		expected_hex: Hex,
		replacement_hex: Hex,
	})
	.strict();
const LiteralEditSchema = z
	.object({
		start: z.number().int().nonnegative().max(1048576),
		expected: z.string().min(1).max(65536),
		replacement: z.string().min(1).max(65536),
	})
	.strict();
export const CandidateSchema = z
	.object({
		expected_sha256: Hash,
		preview_sha256: Hash.optional(),
		byte_patch: BytePatchSchema.optional(),
		byte_patches: z.array(BytePatchSchema).min(1).max(32).optional(),
		literal: LiteralEditSchema.optional(),
		literals: z.array(LiteralEditSchema).min(1).max(32).optional(),
		managed: z
			.object({
				method_token: z.string().regex(/^0x06[0-9a-f]{6}$/),
				instruction_offset: z.number().int().nonnegative().max(4096),
				expected_value: z.number().int().min(-2147483648).max(2147483647),
				replacement_value: z.number().int().min(-2147483648).max(2147483647),
			})
			.strict()
			.optional(),
		jvm: z
			.object({
				method_name: z.string().min(1).max(500),
				descriptor: z.string().min(1).max(500),
				expected_value: z.number().int().min(-1).max(5),
				replacement_value: z.number().int().min(-1).max(5),
			})
			.strict()
			.optional(),
	})
	.strict();
export const SourceSinkSchema = z
	.object({
		source_ids: z.array(z.string().min(1).max(160)).min(1).max(16),
		sink_ids: z.array(z.string().min(1).max(160)).min(1).max(16),
		stop_ids: z.array(z.string().min(1).max(160)).max(32).default([]),
		relation: z
			.enum(["data-flow", "declared-relationships"])
			.default("data-flow"),
		max_depth: z.number().int().min(1).max(12).default(6),
		max_states: z.number().int().min(1).max(4000).default(1000),
		max_edge_visits: z.number().int().min(1).max(20000).default(4000),
	})
	.strict();

export const CANDIDATE_COMMANDS = [
	"preview_binary_patch",
	"patch_binary",
	"preview_ast_transform",
	"apply_ast_transform",
	"preview_dotnet_constant",
	"patch_dotnet_constant",
	"preview_jvm_constant",
	"patch_jvm_constant",
] as const;
export const CandidateBatchSchema = z
	.object({
		schemaVersion: z.literal(1),
		stages: z
			.array(
				z
					.object({
						id: z.string().regex(/^[A-Za-z0-9_-]{1,50}$/),
						operation: z.enum([
							"patch_binary",
							"apply_ast_transform",
							"patch_dotnet_constant",
							"patch_jvm_constant",
						]),
						target: z.string().min(1).max(4096),
						output_file: z.string().min(1).max(4096),
						candidate: CandidateSchema,
					})
					.strict(),
			)
			.min(1)
			.max(8),
	})
	.strict();
export const EvidenceTraceSchema = z
	.object({
		start_id: z.string().min(1).max(160),
		end_id: z.string().min(1).max(160).optional(),
		max_depth: z.number().int().min(1).max(12).default(6),
		max_nodes: z.number().int().min(1).max(500).default(100),
		max_edges: z.number().int().min(1).max(1000).default(200),
	})
	.strict();
export const ManagedMethodSchema = z
	.object({ method_token: z.string().regex(/^0x06[0-9a-f]{6}$/) })
	.strict();
export const JvmMethodSchema = z
	.object({
		method_name: z.string().min(1).max(500),
		descriptor: z.string().min(1).max(500),
	})
	.strict();
