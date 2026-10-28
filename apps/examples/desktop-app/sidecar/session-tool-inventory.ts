import { z } from "zod";
const evidence = z
	.object({
		version: z.literal(1),
		capturedAt: z.string().datetime(),
		runId: z.string().max(256).optional(),
		iteration: z.number().int().nonnegative(),
		toolNames: z.array(z.string().max(256)).max(256),
		toolCount: z.number().int().nonnegative(),
		modelToolNames: z.array(z.string().max(256)).max(256),
		modelToolCount: z.number().int().nonnegative(),
		truncated: z.boolean(),
	})
	.refine(
		(v) =>
			v.toolNames.length <= v.toolCount &&
			v.modelToolNames.length <= v.modelToolCount &&
			(v.truncated ||
				(v.toolNames.length === v.toolCount &&
					v.modelToolNames.length === v.modelToolCount)),
	);
const exposure = z.object({
	status: z.enum(["last-request", "stale"]),
	evidence,
	revision: z.number().int().nonnegative(),
	providerId: z.string().max(512),
	modelId: z.string().max(512),
});
export function projectSessionToolInventory(sessionId: string, value: unknown) {
	const parsed = exposure.safeParse(value);
	return {
		sessionId,
		...(parsed.success ? parsed.data : { status: "unavailable" as const }),
		scope:
			"Last core model-adapter handoff after request hooks. Not proof of provider receipt or current model settings.",
		authorization:
			"Not granted. Installation, target compatibility, Analysis mode and per-request approvals remain separate.",
	};
}
export type SessionToolInventory = ReturnType<
	typeof projectSessionToolInventory
>;
