import { z } from "zod";
export const NativeFunctionStateSchema = z
	.object({
		name: z.string().max(4096),
		comment: z.string().max(8192),
		prototype: z.string().max(8192),
	})
	.strict();
export const NativeProjectEditSchema = z
	.object({
		mode: z.enum(["preview", "candidate", "rollback"]),
		expected_state: NativeFunctionStateSchema.optional(),
		expected_head_sha256: z
			.string()
			.regex(/^[a-f0-9]{64}$/)
			.nullable()
			.optional(),
		changes: z
			.object({
				name: z
					.string()
					.regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/)
					.optional(),
				comment: z.string().max(4096).optional(),
				prototype: z
					.string()
					.min(1)
					.max(4096)
					.regex(/^[^\r\n{}#;]+;?$/)
					.optional(),
			})
			.strict()
			.refine(
				(x) => Object.keys(x).length > 0,
				"At least one reviewed edit is required",
			)
			.optional(),
		confirm_candidate_write: z.boolean().optional(),
		confirm_pointer_rollback: z.boolean().optional(),
	})
	.strict()
	.superRefine((x, c) => {
		if (
			x.mode === "candidate" &&
			(!x.expected_state ||
				!x.changes ||
				x.expected_head_sha256 === undefined ||
				x.confirm_candidate_write !== true)
		)
			c.addIssue({
				code: z.ZodIssueCode.custom,
				message:
					"Candidate edits require exact before-state/head and explicit candidate-write acknowledgement",
			});
		if (
			x.mode === "rollback" &&
			(x.expected_head_sha256 === undefined ||
				x.expected_head_sha256 === null ||
				x.confirm_pointer_rollback !== true ||
				x.changes ||
				x.expected_state)
		)
			c.addIssue({
				code: z.ZodIssueCode.custom,
				message:
					"Rollback requires exact current head and explicit pointer-rollback acknowledgement, not edit data",
			});
		if (
			x.mode === "preview" &&
			(x.changes ||
				x.expected_state ||
				x.confirm_candidate_write === true ||
				x.confirm_pointer_rollback === true)
		)
			c.addIssue({
				code: z.ZodIssueCode.custom,
				message: "Preview accepts no mutations or edit acknowledgement",
			});
	});
export type NativeProjectEdit = z.infer<typeof NativeProjectEditSchema>;
