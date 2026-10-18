import { z } from "zod";
/** These commands have fixed implementations, not model-generated shell recipes. */
export const INVESTIGATION_COMMANDS = [
	"identify_artifact",
	"map_dotnet_interop",
	"map_attack_surface",
	"trace_electron_ipc",
	"audit_preload_bridge",
	"trace_source_symbol",
	"explain_behavior",
	"compare_public_api",
	"inspect_dependency_risk",
	"verify_hypothesis",
	"compare_versions",
	"find_android_entrypoints",
	"trace_android_method",
	"diff_android_resources",
	"resolve_native_symbol",
	"decompile_function_bundle",
	"trace_native_calls",
	"compare_native_functions",
	"inspect_binary_mitigations",
	"explain_decompiler_disagreement",
	"annotate_analysis_project",
	"build_android_candidate",
	"preview_android_candidate",
	"verify_android_candidate",
	"plan_runtime_observation",
	"validate_candidate",
	"review_candidate_changes",
	"preview_batch",
] as const;
export const WorkflowQuerySchema = z
	.object({
		symbol: z.string().min(1).max(1000).optional(),
		max_results: z.number().int().min(1).max(200).default(100),
		max_depth: z.number().int().min(0).max(8).default(4),
	})
	.strict();
export const HypothesisSchema = z
	.object({
		statement: z.string().min(1).max(1000),
		kind: z.enum(["declared-node", "declared-edge"]),
		node_id: z.string().min(1).max(80),
		target_id: z.string().min(1).max(80).optional(),
		relation: z.string().min(1).max(80).optional(),
		expected: z.boolean(),
	})
	.strict()
	.superRefine((v, c) => {
		if (v.kind === "declared-edge" && (!v.target_id || !v.relation))
			c.addIssue({
				code: "custom",
				message: "Declared edge requires exact target_id and relation",
			});
		if (v.kind === "declared-node" && (v.target_id || v.relation))
			c.addIssue({
				code: "custom",
				message: "Node hypothesis does not accept edge fields",
			});
	});

export const DependencyEvidenceOptionsSchema = z
	.object({
		lockfile: z.string().min(1).max(4096),
		lockfile_sha256: z.string().regex(/^[a-f0-9]{64}$/),
		advisory_snapshot: z
			.object({
				path: z.string().min(1).max(4096),
				sha256: z.string().regex(/^[a-f0-9]{64}$/),
			})
			.strict()
			.optional(),
	})
	.strict();

export const EvidenceArchiveOptionsSchema = z
	.object({
		manifest_sha256: z.string().regex(/^[a-f0-9]{64}$/),
	})
	.strict();
export const EvidenceArchiveManifestSchema = z
	.object({
		schemaVersion: z.literal(1),
		title: z.string().min(1).max(120),
		entries: z
			.array(
				z
					.object({
						id: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
						path: z.string().min(1).max(1024),
						sha256: z.string().regex(/^[a-f0-9]{64}$/),
						kind: z.enum(["finding", "receipt", "log", "limitations"]),
						format: z.enum(["json", "text"]),
					})
					.strict(),
			)
			.min(1)
			.max(32),
	})
	.strict();

/** Checks are explicitly selected, never inferred from an untrusted filename. */
export const CandidateValidationSchema = z
	.object({
		expected_sha256: z.string().regex(/^[a-f0-9]{64}$/),
		kind: z.enum(["javascript", "typescript", "dex", "apk"]),
	})
	.strict();
export const CandidateReviewSchema = z
	.object({
		manifest_sha256: z.string().regex(/^[a-f0-9]{64}$/),
		scope: z.enum(["recipe", "project-files", "project-inventory"]).optional(),
	})
	.strict();

/** Fixed static traversal only; budgets are approved with the exact request. */
export const ArtifactDiscoveryOptionsSchema = z
	.object({
		max_depth: z.number().int().min(0).max(4).default(3),
		max_artifacts: z.number().int().min(1).max(500).default(200),
	})
	.strict();

/** Fresh static adapters; imported graph tracing stays a separate explicit mode. */
export const CrossLanguageOptionsSchema = z.discriminatedUnion("kind", [
	z
		.object({
			kind: z.literal("android-jni"),
			method: z
				.object({
					class_descriptor: z
						.string()
						.regex(/^L[^\s;]+;$/)
						.max(4096),
					name: z.string().min(1).max(4096),
					descriptor: z
						.string()
						.regex(/^\(.*\).+$/)
						.max(4096),
				})
				.strict(),
			native_artifact: z.string().min(1).max(1024).optional(),
			max_candidates: z.number().int().min(1).max(64).default(16),
			native_calls: z
				.object({
					max_depth: z.number().int().min(0).max(4).default(2),
					max_functions: z.number().int().min(1).max(32).default(16),
					max_edges: z.number().int().min(1).max(256).default(128),
					max_total_bytes: z.number().int().min(1).max(65536).default(32768),
				})
				.strict()
				.default({
					max_depth: 2,
					max_functions: 16,
					max_edges: 128,
					max_total_bytes: 32768,
				}),
		})
		.strict(),
	z
		.object({
			kind: z.literal("electron-ipc"),
			channel: z.string().min(1).max(256),
			max_depth: z.number().int().min(0).max(8).default(4),
			max_nodes: z.number().int().min(1).max(200).default(100),
			max_edges: z.number().int().min(1).max(400).default(200),
		})
		.strict(),
]);

export const VersionComparisonSchema = z
	.object({
		kind: z.literal("project"),
		max_results: z.number().int().min(1).max(200).default(100),
	})
	.strict();
