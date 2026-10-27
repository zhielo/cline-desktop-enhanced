import { HybridContextSchema } from "../../analysis/hybrid";
import { z } from "zod";
/** Fixed additive profiles; never a download, user hook or execution approval. */
export const EMULATION_PROFILE_SHA256 =
	"4734e7c6711344a030f139f2a097cdb7dade30c7acec95dc0044c93d7435bec9";
export const EMULATION_ENGINES = ["qiling", "unidbg", "rnidbg"] as const;
export const EMULATION_PROFILE_ARCHITECTURES = {
	qiling: ["x86_64", "arm32", "arm64"],
	unidbg: ["arm32", "arm64"],
	rnidbg: ["arm64"],
} as const;
export function supportsEmulationArchitecture(
	engine: string,
	architecture: string,
) {
	return (
		Object.hasOwn(EMULATION_PROFILE_ARCHITECTURES, engine) &&
		(
			EMULATION_PROFILE_ARCHITECTURES[
				engine as keyof typeof EMULATION_PROFILE_ARCHITECTURES
			] as readonly string[]
		).includes(architecture)
	);
}

const Int32 = z.number().int().min(-2147483648).max(2147483647);
export const EmulationScenarioSchema = z.discriminatedUnion("kind", [
	z
		.object({
			kind: z.literal("entry"),
			expectedExit: z.number().int().min(0).max(255).optional(),
		})
		.strict(),
	z.object({ kind: z.literal("initialize") }).strict(),
	z
		.object({
			kind: z.literal("jni-int32"),
			className: z
				.string()
				.max(200)
				.regex(/^[A-Za-z][A-Za-z0-9]*(\/[A-Za-z][A-Za-z0-9]*)*$/),
			methodName: z.string().regex(/^[A-Za-z][A-Za-z0-9]{0,79}$/),
			argument: Int32,
			expectedReturn: Int32.optional(),
		})
		.strict(),
]);
export const EmulationOptionsShape = {
	engine: z.enum(EMULATION_ENGINES),
	architecture: z.enum(["x86_64", "arm32", "arm64"]),
	scenario: EmulationScenarioSchema,
	instruction_limit: z.number().int().min(1).max(100000).default(10000),
};
export function validateEmulationProfile(
	v: { engine: string; architecture: string; scenario: { kind: string } },
	c: z.RefinementCtx,
) {
	if (
		!supportsEmulationArchitecture(v.engine, v.architecture) ||
		(v.engine === "qiling" && v.scenario.kind !== "entry") ||
		(v.engine !== "qiling" &&
			(v.scenario.kind === "entry" ||
				!["arm32", "arm64"].includes(v.architecture))) ||
		(v.engine === "rnidbg" && v.architecture !== "arm64")
	)
		c.addIssue({
			code: "custom",
			message: "Unsupported engine, architecture or scenario; no fallback",
		});
}
export const EmulationOptionsSchema = z
	.object(EmulationOptionsShape)
	.strict()
	.superRefine(validateEmulationProfile);
export const EmulationPlanSchema = z
	.object({
		...EmulationOptionsShape,
		expected_sha256: z.string().regex(/^[a-f0-9]{64}$/),
	})
	.strict()
	.superRefine(validateEmulationProfile);

const RuntimeHash = z.string().regex(/^[a-f0-9]{64}$/);
export const EmulationRuntimeSchema = z
	.object({
		operation: z.literal("emulate_profile"),
		target: z.string().min(1).max(4096),
		...EmulationOptionsShape,
		timeout_ms: z.number().int().min(1000).max(120000).default(60000),
		// Match bounded opaque desktop session identifiers, not just UUIDs.
		// This is identity syntax only; the trusted host still checks the exact
		// attached owner, workspace, permission profile and current mode.
		owner_session_id: z
			.string()
			.min(1)
			.max(128)
			.regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/),
		analysis_mode: z.enum(["runtime", "hybrid"]),
		hybrid: HybridContextSchema.optional(),
		worker_endpoint: z.string().url().optional(),
		worker_id: z.string().min(1).max(128).optional(),
		worker_key_sha256: RuntimeHash.optional(),
		worker_runtime_sha256: RuntimeHash.optional(),
		worker_profile_sha256: RuntimeHash.optional(),
	})
	.strict()
	.superRefine((v, c) => {
		validateEmulationProfile(v, c);
		if ((v.analysis_mode === "hybrid") !== !!v.hybrid)
			c.addIssue({
				code: "custom",
				message:
					"Hybrid requires exact static basis; Runtime accepts no Hybrid context",
			});
	});
