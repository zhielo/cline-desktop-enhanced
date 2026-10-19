"use client";
import type { AndroidCandidateLifecycle } from "../../../../shared/android-candidate-lifecycle";
/** Display only: no RPC, hash guessing, approval, automatic follow-up or execution. */
export function AndroidCandidateLifecycleCard({
	summary,
}: {
	summary?: AndroidCandidateLifecycle;
}) {
	if (summary?.version !== "android-candidate-lifecycle/v1") return null;
	return (
		<section
			aria-label="Android candidate lifecycle"
			className="space-y-1 rounded border p-2 text-xs"
		>
			<h4 className="font-semibold">
				Android candidate lifecycle — retained evidence
			</h4>
			<p>Build task: {summary.buildPlanId}</p>
			<p className="break-all">Unsigned build SHA256: {summary.outputSha256}</p>
			<p>Linked verification attempts: {summary.totalLinkedAttempts}</p>
			{summary.totalLinkedAttempts === 0 && (
				<p>
					No matching retained APK verification attempt. Build completion alone
					is not APK verification.
				</p>
			)}
			{summary.verificationAttempts.map((attempt) => (
				<div key={attempt.planId} className="rounded border p-1">
					<p>Verification task: {attempt.planId}</p>
					<p>
						Task status: {attempt.status}; evidence: {attempt.evidence}
					</p>
					<p>
						APK structure: {attempt.structure}; signature verification:{" "}
						{attempt.signature}
					</p>
					{attempt.receiptSha256 && (
						<p className="break-all">
							Verification receipt SHA256: {attempt.receiptSha256}
						</p>
					)}
				</div>
			))}
			{summary.omittedAttempts > 0 && (
				<p>
					Additional retained attempts not displayed: {summary.omittedAttempts}
				</p>
			)}
			{summary.rejectedLinks > 0 && (
				<p>Rejected inconsistent retained links: {summary.rejectedLinks}</p>
			)}
			<p>
				Signing: {summary.signing}; device outcomes: {summary.device}
			</p>
			{summary.limitations.map((text) => (
				<p key={text}>{text}</p>
			))}
		</section>
	);
}
