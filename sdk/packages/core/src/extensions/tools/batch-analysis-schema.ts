import { z } from "zod";
import { SourceFlowSchema } from "./advanced-candidates-schema";

/** Deliberately narrower than reverse_engineering. No scripts, output paths,
 * subprocess engines, runtime, nested notebooks or model-supplied authority. */
const Target = z.string().min(1).max(4096);
/** Named data output only. Never interpret paths or executable instructions from reports. */
export const BatchReportRefSchema = z
	.object({
		stage_id: z.string().regex(/^[A-Za-z0-9_-]{1,50}$/),
		output: z.literal("evidence-graph"),
	})
	.strict();
export function batchReportRef(value: unknown) {
	const parsed = BatchReportRefSchema.safeParse(value);
	return parsed.success ? parsed.data : undefined;
}
const Limit = z.number().int().min(1).max(500).default(100);
export const BATCH_SOURCE_OPERATIONS = [
	"trace_electron_ipc",
	"trace_data_flow",
	"audit_preload_bridge",
	"trace_source_symbol",
	"explain_behavior",
	"map_attack_surface",
	"compare_public_api",
	"map_dotnet_interop",
	"inspect_binary_mitigations",
	"compare_versions",
] as const;
export const BATCH_GRAPH_ACTIONS = [
	"graph_build",
	"graph_query",
	"cfg_analyze",
	"trace_slice",
	"trace_taint",
] as const;
export const BatchStaticRequestSchema = z.union([
	z
		.object({
			operation: z.enum(["inspect", "scan_strings", "compare_apks"]),
			target: Target,
			compare_target: Target.optional(),
			max_results: Limit,
			min_string_length: z.number().int().min(4).max(1024).default(6),
		})
		.strict()
		.refine(
			(v) => v.operation !== "compare_apks" || !!v.compare_target,
			"Comparison requires compare_target",
		),
	z
		.object({
			operation: z.enum(BATCH_SOURCE_OPERATIONS),
			source_flow: SourceFlowSchema.optional(),
			target: Target,
			compare_target: Target.optional(),
			max_results: Limit,
			workflow_query: z
				.object({
					symbol: z.string().min(1).max(4096).optional(),
					max_results: z.number().int().min(1).max(200).default(100),
					max_depth: z.number().int().min(0).max(8).default(4),
				})
				.strict()
				.optional(),
		})
		.strict()
		.superRefine((v, c) => {
			if ((v.operation === "trace_data_flow") !== !!v.source_flow)
				c.addIssue({
					code: "custom",
					path: ["source_flow"],
					message:
						"Fresh batch source flow requires source_flow and is restricted to trace_data_flow",
				});
			if (
				v.operation === "map_attack_surface" &&
				v.target.toLowerCase().endsWith(".apk")
			)
				c.addIssue({
					code: "custom",
					path: ["target"],
					message:
						"APK attack surface uses a separate approved engine workflow",
				});
			if (
				["compare_public_api", "compare_versions"].includes(v.operation) &&
				!v.compare_target
			)
				c.addIssue({
					code: "custom",
					path: ["compare_target"],
					message: "Comparison requires compare_target",
				});
			if (
				["trace_source_symbol", "explain_behavior"].includes(v.operation) &&
				!v.workflow_query?.symbol
			)
				c.addIssue({
					code: "custom",
					path: ["workflow_query"],
					message: "Exact symbol required",
				});
		}),
	z
		.object({
			operation: z.literal("advanced_analysis"),
			target: z.union([Target, BatchReportRefSchema]),
			advanced_action: z.enum(BATCH_GRAPH_ACTIONS),
			max_results: Limit,
			advanced_options: z
				.object({
					graph_query: z
						.object({
							kind: z
								.enum([
									"artifact",
									"dex-class",
									"dex-method",
									"native-symbol",
									"archive-member",
									"unresolved-call",
								])
								.optional(),
							text: z.string().max(512).optional(),
							startId: z.string().max(80).optional(),
							depth: z.number().int().min(0).max(8).optional(),
							limit: z.number().int().min(1).max(500).optional(),
						})
						.strict()
						.optional(),
				})
				.strict()
				.optional(),
		})
		.strict()
		.refine(
			(v) => !v.advanced_options || v.advanced_action === "graph_query",
			"Graph query options are accepted only by graph_query",
		)
		.refine(
			(v) =>
				typeof v.target === "string" || v.advanced_action === "graph_query",
			"An evidence-graph reference can only feed graph_query",
		),
]);
/** Receipts originate from the strict schema above. Recheck the operation on
 * resume as well as implementation, input and retained-result fingerprints. */
export function isBatchStaticOperation(
	request: Record<string, unknown>,
): boolean {
	if (
		request.script_path ||
		request.output_file ||
		request.report_output_file ||
		request.managed_worker ||
		(request.engine && request.engine !== "auto")
	)
		return false;
	if (
		request.operation === "map_attack_surface" &&
		String(request.target).toLowerCase().endsWith(".apk")
	)
		return false;
	return (
		[
			"inspect",
			"scan_strings",
			"compare_apks",
			...BATCH_SOURCE_OPERATIONS,
		].includes(String(request.operation)) ||
		(request.operation === "advanced_analysis" &&
			(BATCH_GRAPH_ACTIONS as readonly string[]).includes(
				String(request.advanced_action),
			))
	);
}
