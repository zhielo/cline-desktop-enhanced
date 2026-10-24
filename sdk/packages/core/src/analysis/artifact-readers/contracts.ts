import { z } from "zod";
export const ArtifactReaderKindSchema = z.enum([
	"go",
	"rust",
	"pyinstaller",
	"il2cpp",
]);
export const ArtifactReaderRequestSchema = z
	.object({
		reader: ArtifactReaderKindSchema,
		expectedSha256: z.string().regex(/^[a-f0-9]{64}$/),
	})
	.strict();
export const ArtifactMetadataReportSchema = z
	.object({
		protocol: z.literal("cline-artifact-metadata/1"),
		reader: ArtifactReaderKindSchema,
		inputSha256: z.string().regex(/^[a-f0-9]{64}$/),
		upstreamRevision: z.literal("f9fabdfcb2c241b18fec0acb5c3b4a14f76f4805"),
		records: z
			.array(
				z
					.object({
						path: z.string().max(1024),
						valueJson: z.string().max(8192),
					})
					.strict(),
			)
			.max(2048),
		visited: z.number().int().nonnegative().max(50000),
		omitted: z.number().int().nonnegative(),
		truncated: z.boolean(),
		targetExecuted: z.literal(false),
		limitations: z.array(z.string().max(1000)).max(20),
	})
	.strict();
