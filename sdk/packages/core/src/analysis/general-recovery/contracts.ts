import { z } from "zod";
export const WAKARU_VERSION = "1.14.0";
export const WAKARU_REVISION = "8219bf5016a063d7fb215101a8c45d5959ec733f";
export const WAKARU_PINS = {
	linux: {
		file: "wakaru",
		sha256: "664fa06782a61eda7ed15885134b52525fd565dd77607e642062ceb6cd927c38",
		archiveSha256:
			"db0e620034723195ab426e94d00d55dbd8fd0106a928ada2563f1103196d09fa",
	},
	win32: {
		file: "wakaru.exe",
		sha256: "fc3f8df191bb22710bcd34ef7d12f85369c9062ee565f78790cdc99822420064",
		archiveSha256:
			"4f5b9c3851f46fa3fcc72b986db37fa9ee9968dcb9b46bdb4afa2349ba6c876e",
	},
} as const;
const Hash = z.string().regex(/^[a-f0-9]{64}$/);
const Range = z
	.object({
		startByte: z.number().int().nonnegative(),
		endByte: z.number().int().positive(),
		sha256: Hash,
	})
	.strict();
export const GeneralRecoveryReportSchema = z
	.object({
		protocol: z.literal("cline-general-recovery/1"),
		engine: z.literal("wakaru/1.14.0"),
		upstreamRevision: z.literal(WAKARU_REVISION),
		engineSha256: Hash,
		resourceBoundary: z.discriminatedUnion("kind", [
			z
				.object({
					kind: z.literal("windows-job-object-suspended-launch"),
					memoryBytes: z.literal(2147483648),
					maxProcesses: z.literal(4),
					supervisorDeadlineMs: z.literal(45000),
				})
				.strict(),
			z
				.object({
					kind: z.literal("linux-prlimit-process-group"),
					addressSpaceBytes: z.literal(2147483648),
					cpuSoftSeconds: z.literal(45),
					cpuHardSeconds: z.literal(46),
					fileBytes: z.literal(67108864),
					hostDeadlineMs: z.literal(50000),
					supervisorDeadlineMs: z.literal(45000),
				})
				.strict(),
		]),
		sourceSha256: Hash,
		omitted: z.literal(0),
		truncated: z.literal(false),
		detectedFormats: z.array(z.string().max(100)).max(32),
		safety: z.string().max(100),
		strategy: z.string().max(100),
		modules: z
			.array(
				z
					.object({
						filename: z.string().min(1).max(512),
						status: z.string().max(100),
						sha256: Hash,
						sourceBase64: z.string().max(1400000),
						ranges: z.array(Range).min(1).max(256),
						contextRanges: z.array(Range).max(256),
						extraction: z.string().max(100),
						sourceMap: z
							.object({ sha256: Hash, contentBase64: z.string().max(1400000) })
							.strict()
							.optional(),
					})
					.strict(),
			)
			.max(128),
		warnings: z
			.array(
				z
					.object({
						filename: z.string().max(512).optional(),
						kind: z.string().max(100),
						isError: z.boolean(),
						message: z.string().max(4000),
					})
					.strict(),
			)
			.max(128),
		targetExecuted: z.literal(false),
		verifiedBehavior: z.literal(false),
		limitations: z.array(z.string().max(1000)).max(12),
	})
	.strict();
export type GeneralRecoveryReport = z.infer<typeof GeneralRecoveryReportSchema>;
