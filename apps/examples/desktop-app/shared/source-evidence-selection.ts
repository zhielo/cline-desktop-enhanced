/** A saved-evidence selector, never a filesystem path or execution capability. */
export type SourceEvidenceSelector = {
	receiptId: string;
	selector:
		| { kind: "fact"; factId: string }
		| { kind: "artifact"; path: string };
};
export type SourceEvidenceSelection = {
	version: "source-evidence-selection/v1";
	receiptId: string;
	requestHash: string;
	resultHash: string;
	sessionId: string;
	workspace: string;
	path: string;
	expectedSha256: string;
	factId?: string;
	location?: { line: number; column: number };
	status:
		| "matched"
		| "stale"
		| "missing"
		| "blocked"
		| "unsupported"
		| "unavailable";
	checkedAt: string;
	note: string;
	preview?: {
		lines: { line: number; text: string; truncated: boolean }[];
		truncated: boolean;
	};
};
