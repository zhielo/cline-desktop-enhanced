import { summarizeAndroidCandidateBuild } from "./candidate-build-outcome";
import { digest } from "@cline/core";
import { z } from "zod";
import type { CandidateOutcome } from "../shared/candidate-outcome";

const Hash = z.string().regex(/^[a-f0-9]{64}$/);
const Receipt = z
	.object({
		protocol: z.literal("cline-candidate-verification/v1"),
		operation: z.enum(["validate_candidate", "review_candidate_changes"]),
		effect: z.literal("read"),
		status: z.enum(["completed", "failed", "partial"]),
		inputSha256: Hash,
		inputBytes: z
			.number()
			.int()
			.min(0)
			.max(16 * 1024 * 1024),
		checks: z
			.array(
				z
					.object({
						id: z.string().min(1).max(120),
						status: z.enum(["completed", "failed", "partial", "blocked"]),
					})
					.passthrough(),
			)
			.min(1)
			.max(10),
		limitations: z.array(z.string().max(4000)).max(40),
		published: z.literal(false),
		observedExecution: z.literal(false),
		receiptSha256: Hash,
	})
	.passthrough();
type Basis = {
	operation: string;
	targetIdentity?: { sha256?: string };
	request: Record<string, unknown>;
};
/** Interpret only the exact first-party verification protocol, bound to the prepared input. */
export function summarizeCandidateOutcome(
	plan: Basis,
	result: unknown,
): CandidateOutcome | undefined {
	if (plan.operation === "build_android_candidate")
		return summarizeAndroidCandidateBuild(plan, result);
	if (
		plan.operation !== "validate_candidate" &&
		plan.operation !== "review_candidate_changes"
	)
		return undefined;
	const base: CandidateOutcome = {
		version: "candidate-outcome/v1",
		operation: plan.operation,
		evidence: "unavailable",
		scope: "unverified-receipt",
		checks: [],
		limitations: [
			"Retained metadata only; not a current file hash, producer authentication, build/sign/install/device result, behavioral equivalence, execution proof or approval.",
		],
	};
	try {
		const parsed = Receipt.safeParse(result);
		if (!parsed.success) throw new Error("Unsupported verification receipt");
		const r = parsed.data,
			{ receiptSha256, ...body } = result as Record<string, unknown>;
		const options = plan.request[
			plan.operation === "validate_candidate"
				? "candidate_validation"
				: "candidate_review"
		] as Record<string, unknown> | undefined;
		const expected =
			options?.[
				plan.operation === "validate_candidate"
					? "expected_sha256"
					: "manifest_sha256"
			];
		if (
			r.operation !== plan.operation ||
			r.inputSha256 !== expected ||
			r.inputSha256 !== plan.targetIdentity?.sha256 ||
			digest(body) !== receiptSha256
		)
			throw new Error("Verification receipt identity mismatch");
		const scope =
			plan.operation === "validate_candidate"
				? options?.kind
				: (options?.scope ?? "recipe");
		const ids =
			plan.operation === "validate_candidate"
				? scope === "javascript" || scope === "typescript"
					? ["source-syntax"]
					: scope === "dex"
						? ["dex-header-integrity-extents"]
						: scope === "apk"
							? ["inspect", "verify_apk_signature"]
							: []
				: scope === "recipe"
					? ["exact-recipe-audit"]
					: scope === "project-files"
						? ["full-project-file-scope"]
						: scope === "project-inventory"
							? ["full-project-file-inventory-draft"]
							: [];
		if (
			!ids.length ||
			r.checks.length !== ids.length ||
			ids.some((id) => r.checks.filter((c) => c.id === id).length !== 1)
		)
			throw new Error("Required verification checks missing or duplicated");
		const failed =
			r.status === "failed" || r.checks.some((c) => c.status === "failed");
		const incomplete =
			r.status === "partial" ||
			r.checks.some((c) => c.status !== "completed" || c.truncated === true);
		return {
			...base,
			evidence: failed
				? "failed"
				: incomplete
					? "partial"
					: "bounded-checks-passed",
			scope: String(scope),
			inputSha256: r.inputSha256,
			receiptSha256: r.receiptSha256,
			checks: r.checks.map((c) => ({ id: c.id, status: c.status })),
			limitations: [
				...base.limitations,
				...r.limitations
					.slice(0, 12)
					.map((text) =>
						text.length > 1000
							? `${text.slice(0, 1000)} [limitation truncated]`
							: text,
					),
				...(r.limitations.length > 12
					? [
							"Additional receipt limitations omitted from bounded summary; inspect the original result.",
						]
					: []),
			],
		};
	} catch {
		return {
			...base,
			limitations: [
				...base.limitations,
				"Receipt protocol, integrity, exact input identity or required check set could not be verified. No passing outcome is inferred.",
			],
		};
	}
}
