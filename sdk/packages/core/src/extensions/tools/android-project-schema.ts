import { z } from "zod";
import { SmaliPatchSchema } from "./analysis-commands";

export const AndroidProjectPatchSchema = z
	.object({
		expected_project_sha256: z
			.string()
			.regex(/^[a-f0-9]{64}$/)
			.optional(),
		patches: z
			.array(
				z
					.object({
						path: z.string().min(1).max(1024),
						patch: SmaliPatchSchema.omit({ preview_sha256: true }),
					})
					.strict(),
			)
			.min(1)
			.max(32),
		preview_sha256: z
			.string()
			.regex(/^[a-f0-9]{64}$/)
			.optional(),
	})
	.strict();
