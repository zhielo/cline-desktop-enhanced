"use client";
import type { CandidateOutcome } from "../../../../shared/candidate-outcome";
/** No RPCs or automatic reruns: this card displays saved host-derived metadata. */
export function CandidateOutcomeCard({
	outcome,
	status,
}: {
	outcome?: CandidateOutcome;
	status: string;
}) {
	if (!outcome || outcome.version !== "candidate-outcome/v1") return null;
	return (
		<section
			aria-label="Candidate verification outcome"
			className="space-y-1 rounded border p-2 text-xs"
		>
			<h4 className="font-semibold">Candidate verification outcome</h4>
			<p>Task status: {status}</p>
			<p>Evidence outcome: {outcome.evidence}</p>
			<p>Check scope: {outcome.scope}</p>
			{outcome.inputSha256 ? (
				<p className="break-all">Checked input SHA256: {outcome.inputSha256}</p>
			) : null}
			{outcome.receiptSha256 ? (
				<p className="break-all">
					Verification receipt SHA256: {outcome.receiptSha256}
				</p>
			) : null}
			<ul>
				{outcome.checks.map((c) => (
					<li key={c.id}>
						{c.id}: {c.status}
					</li>
				))}
			</ul>
			{[...new Set(outcome.limitations)].map((text) => (
				<p key={text}>{text}</p>
			))}
		</section>
	);
}
