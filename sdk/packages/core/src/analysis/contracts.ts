import { createHash } from "node:crypto";
import { z } from "zod";
import { electronFuseReportSchema } from "./semantic-engine/upstream/src/domain/electron/electronFuses";
import { AcquisitionSchema } from "./acquisition";

import { ANALYSIS_PROFILE } from "./profile";
export { ANALYSIS_PROFILE } from "./profile";
export const AnalysisModeSchema = z.enum([
	"off",
	"static",
	"runtime",
	"hybrid",
]);
export type AnalysisMode = z.infer<typeof AnalysisModeSchema>;
export const AnalysisInputSchema = z
	.object({
		target: z.string().min(1).max(4096),
		compareTarget: z.string().min(1).max(4096).optional(),
		semanticGraph: z.boolean().optional(),
		applicationGraph: z.boolean().optional(),
		electronFuses: z.boolean().optional(),
	})
	.strict()
	.superRefine((v, ctx) => {
		if (
			v.electronFuses &&
			(v.semanticGraph || v.applicationGraph || v.compareTarget !== undefined)
		)
			ctx.addIssue({
				code: "custom",
				message:
					"Electron fuse inspection requires one executable and cannot combine graphs or comparison",
				path: ["electronFuses"],
			});
		if (v.applicationGraph && !v.semanticGraph)
			ctx.addIssue({
				code: "custom",
				message: "applicationGraph requires semanticGraph: true",
				path: ["applicationGraph"],
			});
	});
export type AnalysisInput = z.infer<typeof AnalysisInputSchema>;
export const LIMITS = {
	files: 128,
	entries: 4096,
	depth: 8,
	sourceBytes: 1024 * 1024,
	totalBytes: 8 * 1024 * 1024,
	archiveBytes: 32 * 1024 * 1024,
	nodes: 200_000,
	facts: 8000,
	outputBytes: 4 * 1024 * 1024,
	timeoutMs: 60_000,
} as const;
export function canonical(value: unknown): string {
	const normalize = (v: unknown): unknown =>
		Array.isArray(v)
			? v.map(normalize)
			: v && typeof v === "object"
				? Object.fromEntries(
						Object.entries(v)
							.filter(([, x]) => x !== undefined)
							.sort(([a], [b]) => a.localeCompare(b))
							.map(([k, x]) => [k, normalize(x)]),
					)
				: v;
	return JSON.stringify(normalize(value));
}
export const digest = (value: unknown) =>
	createHash("sha256").update(canonical(value)).digest("hex");
export const byteDigest = (value: Uint8Array) =>
	createHash("sha256").update(value).digest("hex");
export const LocationSchema = z
	.object({
		path: z.string().max(4096),
		sha256: z.string().regex(/^[a-f0-9]{64}$/),
		line: z.number().int().positive(),
		column: z.number().int().positive(),
	})
	.strict();
export const FactSchema = z
	.object({
		id: z.string().regex(/^ev_[a-f0-9]{64}$/),
		kind: z.enum([
			"module",
			"import",
			"export",
			"function",
			"ipc-send",
			"ipc-handler",
			"preload-api",
			"endpoint",
			"native-addon",
			"dynamic",
			"entrypoint",
			"call",
			"configuration",
			"semantic-function",
			"resolved-call",
			"resolved-endpoint",
			"source-map-location",
			"module-value",
			"managed-type",
			"managed-method",
			"managed-il",
			"preload-member",
			"preload-unresolved",
			"preload-call",
			"native-boundary",
			"managed-il-instruction",
			"managed-control-flow",
			"managed-exception-region",
			"managed-exception-unresolved",
			"managed-stack-model",
		]),
		value: z.string().max(1000),
		confidence: z.enum(["observed", "derived", "inferred"]),
		authority: z.literal("shipped-artifact"),
		location: LocationSchema,
		limitations: z.array(z.string().max(1000)).max(20),
	})
	.strict();
export type AnalysisFact = z.infer<typeof FactSchema>;
export const ResultSchema = z
	.object({
		profile: z.literal(ANALYSIS_PROFILE),
		parserVersion: z.string().max(80),
		status: z.enum(["completed", "partial"]),
		artifacts: z
			.array(
				z
					.object({
						path: z.string().max(4096),
						sha256: z.string().regex(/^[a-f0-9]{64}$/),
						bytes: z.number().int().nonnegative(),
						role: z.string().max(80),
					})
					.strict(),
			)
			.max(LIMITS.files),
		facts: z.array(FactSchema).max(LIMITS.facts),
		edges: z
			.array(
				z
					.object({
						source: z.string(),
						target: z.string(),
						kind: z.enum([
							"imports",
							"ipc-candidate",
							"data-flow",
							"calls",
							"managed-flow",
							"managed-exception-candidate",
							"preload-candidate",
							"native-boundary-candidate",
						]),
						confidence: z.literal("derived"),
						limitations: z.array(z.string()),
					})
					.strict(),
			)
			.max(LIMITS.facts),
		limitations: z.array(z.string().max(1000)).max(100),
		counters: z
			.object({ entries: z.number(), bytes: z.number(), nodes: z.number() })
			.strict(),
		comparison: z
			.object({
				added: z.array(z.string()),
				removed: z.array(z.string()),
				changed: z.array(z.string()),
				findings: z
					.array(
						FactSchema.extend({
							change: z.enum(["added", "removed"]),
						}).strict(),
					)
					.max(LIMITS.facts)
					.optional(),
				limitations: z.array(z.string()),
			})
			.strict()
			.optional(),
		electronFuses: electronFuseReportSchema.optional(),
		acquisition: AcquisitionSchema.optional(),
		applicationGraph: z
			.object({
				profile: z.literal("cline-application/1"),
				upstreamRevision: z.string().regex(/^[a-f0-9]{40}$/),
				graphId: z.string().max(100),
				graphHash: z.string().regex(/^[a-f0-9]{64}$/),
				semanticGraphHash: z.string().regex(/^[a-f0-9]{64}$/),
				rootManifestHash: z.string().regex(/^[a-f0-9]{64}$/),
				sources: z
					.array(
						z
							.object({
								path: z.string().min(1).max(4096),
								sha256: z.string().regex(/^[a-f0-9]{64}$/),
								bytes: z.number().int().nonnegative().max(LIMITS.sourceBytes),
							})
							.strict(),
					)
					.max(LIMITS.files),
				nodes: z.number().int().nonnegative(),
				edges: z.number().int().nonnegative(),
				coverage: z.unknown(),
				scope: z.literal("admitted-application-sources"),
				limitations: z.array(z.string().max(1000)).max(20),
			})
			.strict()
			.optional(),
		semanticGraph: z
			.object({
				profile: z.enum(["cline-semantic/1", "cline-semantic/2"]),
				upstreamRevision: z.string().regex(/^[a-f0-9]{40}$/),
				graphId: z.string().max(100),
				graphHash: z.string().regex(/^[a-f0-9]{64}$/),
				nodes: z.number().int().nonnegative(),
				relations: z.number().int().nonnegative(),
				unknowns: z.number().int().nonnegative(),
				fingerprints: z.number().int().nonnegative(),
				coverage: z.unknown(),
				scope: z.enum([
					"file-local-semantics",
					"application-bound-file-semantics",
				]),
				limitations: z.array(z.string().max(1000)).max(20),
			})
			.strict()
			.optional(),
	})
	.strict()
	.superRefine((result, ctx) => {
		if (!result.acquisition) return;
		const artifacts = new Map(result.artifacts.map((a) => [a.path, a]));
		if (
			artifacts.size !== result.artifacts.length ||
			result.acquisition.sources.length !== artifacts.size ||
			result.acquisition.sources.some((s) => {
				const a = artifacts.get(s.path);
				return !a || a.sha256 !== s.sha256 || a.bytes !== s.bytes;
			})
		)
			ctx.addIssue({
				code: "custom",
				message: "Acquisition/artifact projection mismatch",
			});
	});
export type AnalysisResult = z.infer<typeof ResultSchema>;
export type AnalysisReceipt = {
	id: string;
	sessionId: string;
	workspace: string;
	profile: string;
	input: AnalysisInput;
	requestHash: string;
	createdAt: string;
	completedAt?: string;
	status:
		| "running"
		| "completed"
		| "partial"
		| "failed"
		| "cancelled"
		| "timed-out"
		| "termination-unconfirmed";
	pid?: number;
	ownership?: import("./recovery").AnalysisOwnership;
	exitCode?: number | null;
	signal?: string | null;
	result?: AnalysisResult;
	resultHash?: string;
	error?: string;
};
