import { z } from "zod";
export const BUNDLE_RECOVERY_REVISION =
	"d0067ba34a39ea47dd7e11bb2e6169bc0938cc3f";
const Hash = z.string().regex(/^[a-f0-9]{64}$/);
export const BundleRecoveryRequestSchema = z
	.object({ expectedSha256: Hash })
	.strict();
export const BundleExportRequestSchema = z
	.object({ receiptId: z.string().uuid(), reportHash: Hash })
	.strict();
export const BundleRecoveryReportSchema = z
	.object({
		protocol: z.literal("cline-bundle-recovery/1"),
		engine: z.literal("cline-literal-factory/1"),
		upstreamRevision: z.literal(BUNDLE_RECOVERY_REVISION),
		sourceSha256: Hash,
		modules: z
			.array(
				z
					.object({
						id: Hash,
						bundler: z.enum(["webpack", "rspack", "esbuild"]),
						runtime: z.string().max(4096),
						moduleKey: z.string().max(4096),
						startByte: z.number().int().nonnegative(),
						endByte: z.number().int().nonnegative(),
						sha256: Hash,
						sourceBase64: z.string().max(1400000),
					})
					.strict(),
			)
			.max(128),
		omitted: z.number().int().nonnegative(),
		truncated: z.boolean(),
		targetExecuted: z.literal(false),
		limitations: z.array(z.string().max(1000)).max(12),
	})
	.strict();
