/** Host-derived metadata only. Never an approval, live freshness or behavioral certificate. */
export type CandidateOutcome = {
	version: "candidate-outcome/v1";
	evidence: "bounded-checks-passed" | "failed" | "partial" | "unavailable";
	operation:
		| "validate_candidate"
		| "review_candidate_changes"
		| "build_android_candidate";
	scope: string;
	inputSha256?: string;
	receiptSha256?: string;
	outputSha256?: string;
	publication?: "new-unsigned-candidate";
	checks: { id: string; status: string }[];
	limitations: string[];
};
