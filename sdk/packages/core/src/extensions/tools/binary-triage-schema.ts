import { z } from "zod";

export const BINARY_TRIAGE_OPERATIONS = [
	"inspect_binary",
	"list_functions",
	"get_function_disassembly",
	"find_references",
	"scan_yara",
	"identify_capabilities",
	"extract_strings",
] as const;
const Execute = z
	.object({
		action: z.literal("run"),
		operation: z.enum(BINARY_TRIAGE_OPERATIONS),
		question: z.string().trim().min(1).max(500),
		address: z
			.string()
			.regex(/^0x[0-9a-fA-F]{1,13}$/)
			.optional(),
	})
	.strict()
	.refine(
		(v) =>
			["get_function_disassembly", "find_references"].includes(v.operation) ===
			(v.address !== undefined),
		"Exact hexadecimal address is required only for selected-address operations",
	);
export const BinaryTriageOptionsSchema = z.union([
	Execute,
	z.object({ action: z.literal("status") }).strict(),
	z
		.object({
			action: z.literal("read"),
			receipt_id: z.string().uuid(),
			offset: z.number().int().min(0).max(2_000_000).optional(),
			limit: z.number().int().min(1).max(4096).optional(),
		})
		.strict(),
]);
/** Strict host route: never accept model-confirmed flags, executables, rules or arbitrary commands. */
export const BinaryTriageCallSchema = z
	.object({
		operation: z.literal("advanced_analysis"),
		advanced_action: z.literal("binary_triage"),
		// Inert defaults injected by the shared reverse-engineering schema.
		engine: z.literal("auto").optional(),
		report_format: z.literal("json").optional(),
		discovery_depth: z.literal("fast").optional(),
		target: z
			.string()
			.min(1)
			.max(4096)
			.refine((v) => !/[\0\r\n]/.test(v))
			.optional(),
		advanced_options: z
			.object({ binary_triage: BinaryTriageOptionsSchema })
			.strict(),
	})
	.strict()
	.refine(
		(v) =>
			(v.advanced_options.binary_triage.action === "run") ===
			(v.target !== undefined),
		"Only triage execution requires a target; saved reads and status accept none",
	);
export type BinaryTriageCall = z.infer<typeof BinaryTriageCallSchema>;
