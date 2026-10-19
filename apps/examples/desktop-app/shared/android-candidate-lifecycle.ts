/** Retained task relationships only: never current file identity or execution authority. */
export type AndroidCandidateLifecycle = {
	version: "android-candidate-lifecycle/v1";
	buildPlanId: string;
	outputSha256: string;
	publication: "new-unsigned-candidate";
	verificationAttempts: {
		planId: string;
		status: string;
		evidence: "bounded-checks-passed" | "failed" | "partial" | "unavailable";
		structure: "completed" | "failed" | "partial" | "blocked" | "unavailable";
		signature: "completed" | "failed" | "partial" | "blocked" | "unavailable";
		receiptSha256?: string;
	}[];
	totalLinkedAttempts: number;
	omittedAttempts: number;
	rejectedLinks: number;
	signing: "not-attested";
	device: "not-linked";
	limitations: string[];
};
