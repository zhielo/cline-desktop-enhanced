import { digest } from "@cline/core";
import type { AnalysisTaskPlan } from "./analysis-task-orchestrator";
import type { AndroidCandidateLifecycle } from "../shared/android-candidate-lifecycle";

const hash = (value: unknown): value is string =>
	typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const record = (value: unknown): value is Record<string, unknown> =>
	Boolean(value) && typeof value === "object" && !Array.isArray(value);
function requestMatches(plan: AnalysisTaskPlan): boolean {
	try {
		return (
			record(plan.request) &&
			hash(plan.requestHash) &&
			digest(plan.request) === plan.requestHash
		);
	} catch {
		return false;
	}
}
/** Pure bounded read model. Does not read files, retain derived authority or perform follow-ups. */
export function summarizeAndroidCandidateLifecycle(
	build: AnalysisTaskPlan,
	retained: readonly AnalysisTaskPlan[],
): AndroidCandidateLifecycle | undefined {
	const outcome = build.candidateOutcome;
	if (
		build.operation !== "build_android_candidate" ||
		build.status !== "completed" ||
		outcome?.version !== "candidate-outcome/v1" ||
		outcome.operation !== build.operation ||
		outcome.evidence !== "bounded-checks-passed" ||
		outcome.scope !== "android-project-build" ||
		outcome.publication !== "new-unsigned-candidate" ||
		!hash(outcome.outputSha256) ||
		!hash(build.requestHash) ||
		!hash(build.evidence?.resultHash) ||
		build.evidence?.requestHash !== build.requestHash ||
		!requestMatches(build) ||
		typeof build.request.output_file !== "string"
	)
		return undefined;
	const linked: AndroidCandidateLifecycle["verificationAttempts"] = [];
	let rejectedLinks = 0;
	// Count and show every retained attempt independently; a later pass must not hide a failure.
	for (const task of retained) {
		if (
			task.workspaceRoot !== build.workspaceRoot ||
			task.candidateSource?.planId !== build.id
		)
			continue;
		const source = task.candidateSource;
		if (!requestMatches(task)) {
			rejectedLinks++;
			continue;
		}
		const options = task.request.candidate_validation as
			| Record<string, unknown>
			| undefined;
		if (
			source.requestHash !== build.requestHash ||
			source.resultHash !== build.evidence.resultHash ||
			source.outputSha256 !== outcome.outputSha256 ||
			task.operation !== "validate_candidate" ||
			task.kind !== "static" ||
			task.permission !== "Inspect" ||
			task.request.operation !== task.operation ||
			options?.kind !== "apk" ||
			options.expected_sha256 !== outcome.outputSha256 ||
			task.target !== build.request.output_file ||
			task.request.target !== task.target ||
			task.targetIdentity?.sha256 !== outcome.outputSha256 ||
			!hash(task.requestHash)
		) {
			rejectedLinks++;
			continue;
		}
		const saved = task.candidateOutcome;
		const terminal = task.status === "completed" || task.status === "failed";
		const checks = saved?.checks;
		const valid =
			terminal &&
			task.evidence?.requestHash === task.requestHash &&
			hash(task.evidence.resultHash) &&
			saved?.version === "candidate-outcome/v1" &&
			saved.operation === task.operation &&
			saved.scope === "apk" &&
			saved.inputSha256 === outcome.outputSha256 &&
			hash(saved.receiptSha256) &&
			["bounded-checks-passed", "failed", "partial"].includes(saved.evidence) &&
			Array.isArray(checks) &&
			checks.length === 2 &&
			checks.every((c) => record(c)) &&
			["inspect", "verify_apk_signature"].every(
				(id) => checks.filter((c) => c.id === id).length === 1,
			) &&
			checks.every((c) =>
				["completed", "failed", "partial", "blocked"].includes(c.status),
			) &&
			!(
				task.status === "failed" && saved.evidence === "bounded-checks-passed"
			) &&
			!(
				saved.evidence === "bounded-checks-passed" &&
				checks.some((c) => c.status !== "completed")
			);
		linked.push({
			planId: task.id,
			status: task.status,
			evidence: valid ? saved.evidence : "unavailable",
			structure: valid
				? (checks.find((c) => c.id === "inspect")!.status as
						| "completed"
						| "failed"
						| "partial"
						| "blocked")
				: "unavailable",
			signature: valid
				? (checks.find((c) => c.id === "verify_apk_signature")!.status as
						| "completed"
						| "failed"
						| "partial"
						| "blocked")
				: "unavailable",
			...(valid ? { receiptSha256: saved.receiptSha256 } : {}),
		});
	}
	// Stable ledger order, with a hard display cap; never collapse to a single green lifecycle.
	return {
		version: "android-candidate-lifecycle/v1",
		buildPlanId: build.id,
		outputSha256: outcome.outputSha256,
		publication: "new-unsigned-candidate",
		verificationAttempts: linked.slice(0, 10),
		totalLinkedAttempts: linked.length,
		omittedAttempts: Math.max(0, linked.length - 10),
		rejectedLinks,
		signing: "not-attested",
		device: "not-linked",
		limitations: [
			"Retained metadata only; not a current file hash, producer authentication, approval or permission to rerun.",
			"Only exact build/request/result/output-linked APK verification attempts in this workspace are shown; deleted or pruned tasks are not recovered.",
			"A completed task is not a passed check. Signature verification does not sign the unsigned build, prove installation, ART compatibility or execution.",
			"Signing and device outcomes are not attested or linked by this summary. No automatic verification, signing, installation or execution occurs.",
		],
	};
}
