import { digest } from "@cline/core";
import { z } from "zod";
import type { CandidateOutcome } from "../shared/candidate-outcome";

const Hash = z.string().regex(/^[a-f0-9]{64}$/);
const Root = z
	.string()
	.regex(/^smali(?:_classes[2-9][0-9]*|_classes1[0-9]+)?$/);
const BuildReceipt = z
	.object({
		protocol: z.literal("cline-android-project-candidate/v1"),
		schemaVersion: z.literal(1),
		operation: z.literal("build_android_candidate"),
		effect: z.literal("candidate-write"),
		status: z.enum(["completed", "blocked", "failed", "cancelled"]),
		projectSha256: Hash,
		previewSha256: Hash,
		outputFile: z.string().min(1).max(4096),
		published: z.boolean(),
		observedExecution: z.literal(false),
		cleanup: z.enum([
			"deferred-unconfirmed-engine-termination",
			"private-workspace-removal-scheduled",
		]),
		cleanupWarnings: z.array(z.string().max(8192)).max(8),
		smaliRoots: z.array(Root).min(1).max(32),
		stages: z
			.array(
				z.object({
					id: z.string().max(128),
					result: z.record(z.string(), z.unknown()),
				}),
			)
			.max(65),
		limitations: z.array(z.string().max(4000)).max(40),
		outputSha256: Hash.optional(),
		sourceUnchanged: z.boolean().optional(),
		candidateProjectSha256: Hash.optional(),
		validation: z.string().max(200).optional(),
		signingStatus: z.literal("new-unsigned-artifact").optional(),
	})
	.passthrough();

type Basis = { operation: string; request: Record<string, unknown> };
/** Read model only: never opens a file, approves a stage, signs or runs an APK. */
export function summarizeAndroidCandidateBuild(
	plan: Basis,
	result: unknown,
): CandidateOutcome | undefined {
	if (
		plan.operation !== "build_android_candidate" ||
		!plan.request.android_project_patch
	)
		return undefined;
	const base: CandidateOutcome = {
		version: "candidate-outcome/v1",
		operation: "build_android_candidate",
		evidence: "unavailable",
		scope: "android-project-build",
		checks: [],
		limitations: [
			"Retained build metadata only; not current file freshness, authenticated producer evidence, behavioral equivalence or approval.",
			"Unsigned candidate only. Signature verification, install, device execution and ART compatibility remain separate; no automatic follow-up or replay.",
			"Private workspace removal is scheduled by the producer; this summary does not independently confirm filesystem cleanup.",
		],
	};
	try {
		const r = BuildReceipt.parse(result);
		const config = z
			.object({
				expected_project_sha256: Hash,
				preview_sha256: Hash,
				patches: z
					.array(
						z
							.object({
								path: z.string(),
								patch: z.object({ expected_sha256: Hash }).passthrough(),
							})
							.passthrough(),
					)
					.min(1)
					.max(32),
			})
			.passthrough()
			.parse(plan.request.android_project_patch);
		if (
			r.projectSha256 !== config.expected_project_sha256 ||
			r.previewSha256 !== config.preview_sha256 ||
			r.outputFile !== plan.request.output_file
		)
			throw Error("Prepared request mismatch");
		if (new Set(r.smaliRoots).size !== r.smaliRoots.length)
			throw Error("Duplicate roots");
		const expected = [
			...config.patches.map((_, i) => `patch-${i}`),
			...r.smaliRoots.map((root) => `assemble-${root}`),
			"rebuild-apk",
		];
		if (r.stages.some((s, i) => s.id !== expected[i]))
			throw Error("Unknown, reordered or duplicate stage");
		const checks = r.stages.map((s, index) => {
			const clean =
				s.result.cancelled !== true &&
				s.result.timedOut !== true &&
				s.result.outputDrainTimedOut !== true;
			const passed =
				clean &&
				(s.id.startsWith("patch-")
					? s.result.status === "completed" &&
						Hash.safeParse(s.result.inputSha256).success &&
						Hash.safeParse(s.result.candidateSha256).success &&
						s.result.inputSha256 ===
							config.patches[index]?.patch.expected_sha256 &&
						s.result.path === config.patches[index]?.path
					: s.result.succeeded === true &&
						(s.result.exitCode === undefined || s.result.exitCode === 0) &&
						(s.result.status === undefined ||
							s.result.status === "completed" ||
							s.result.status === "success"));
			return { id: s.id, status: passed ? "completed" : "blocked" };
		});
		if (r.status === "completed") {
			const built = r.stages.at(-1)?.result;
			if (
				!r.published ||
				!r.sourceUnchanged ||
				!r.outputSha256 ||
				!r.candidateProjectSha256 ||
				r.signingStatus !== "new-unsigned-artifact" ||
				r.validation !==
					"all-smali-roots-assembled; bounded-apk-structure-checked" ||
				checks.length !== expected.length ||
				checks.some((c) => c.status !== "completed") ||
				built?.outputSha256 !== r.outputSha256 ||
				typeof built.outputValidation !== "string" ||
				!built.outputValidation.startsWith("bounded-structure-checked")
			)
				throw Error("Incomplete build evidence");
		} else if (r.published || r.outputSha256)
			throw Error("Publication without completed build");
		return {
			...base,
			evidence:
				r.status === "failed"
					? "failed"
					: r.status !== "completed" ||
							r.cleanupWarnings.length ||
							r.cleanup !== "private-workspace-removal-scheduled"
						? "partial"
						: "bounded-checks-passed",
			inputSha256: r.projectSha256,
			receiptSha256: digest(result),
			checks,
			...(r.outputSha256
				? {
						outputSha256: r.outputSha256,
						publication: "new-unsigned-candidate" as const,
					}
				: {}),
			limitations: [
				...base.limitations,
				...r.limitations.slice(0, 12).map((s) => s.slice(0, 1000)),
				...(r.cleanupWarnings.length
					? [
							"Producer reported cleanup warnings; inspect the original result. No raw paths or diagnostics are retained in this summary.",
						]
					: []),
			],
		};
	} catch {
		return {
			...base,
			limitations: [
				...base.limitations,
				"Build receipt identity, stage set or publication evidence could not be verified. No passing outcome is inferred.",
			],
		};
	}
}
