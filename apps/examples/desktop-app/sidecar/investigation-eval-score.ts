import { z } from "zod";
const Common = {
	receiptId: z.string().uuid(),
	sourceSha256: z.string().regex(/^[a-f0-9]{64}$/),
	targetExecuted: z.literal(false),
	verifiedBehavior: z.literal(false),
};
export const InvestigationEvalAnswer = z.discriminatedUnion("kind", [
	z
		.object({
			...Common,
			kind: z.literal("bundle-factories"),
			count: z.number().int().nonnegative(),
			completeSourceRecovered: z.literal(false),
		})
		.strict(),
	z
		.object({
			...Common,
			kind: z.literal("pyinstaller-carchive"),
			entryName: z.string().max(200),
			pythonVersion: z.number().int(),
			decodedPayload: z.literal(false),
		})
		.strict(),
]);
export type InvestigationEvalExpected = {
	sourceSha256: string;
	receiptIds: string[];
	evidenceReadIds: string[];
	opened: boolean;
	analysisCompleted: boolean;
	reviewed: boolean;
} & (
	| { kind: "bundle-factories"; count: number }
	| { kind: "pyinstaller-carchive"; entryName: string; pythonVersion: number }
);
/** Exact known answers, never an LLM judge. Called with host-derived evidence. */
export function scoreInvestigationEval(
	text: string,
	expected: InvestigationEvalExpected,
) {
	let answer: z.infer<typeof InvestigationEvalAnswer> | undefined;
	try {
		answer = InvestigationEvalAnswer.parse(JSON.parse(text));
	} catch {
		/* Invalid JSON or an unsupported claim fails. */
	}
	const checks = {
		answerSchema: !!answer,
		actualHostJourney:
			expected.opened && expected.analysisCompleted && expected.reviewed,
		exactSavedEvidence:
			!!answer &&
			expected.receiptIds.includes(answer.receiptId) &&
			expected.evidenceReadIds.includes(answer.receiptId) &&
			answer.sourceSha256 === expected.sourceSha256,
		knownAnswer:
			!!answer &&
			answer.kind === expected.kind &&
			(answer.kind === "bundle-factories" &&
			expected.kind === "bundle-factories"
				? answer.count === expected.count
				: answer.kind === "pyinstaller-carchive" &&
					expected.kind === "pyinstaller-carchive" &&
					answer.entryName === expected.entryName &&
					answer.pythonVersion === expected.pythonVersion),
	};
	return {
		checks,
		passed: Object.values(checks).every(Boolean),
		score: Object.values(checks).filter(Boolean).length / 4,
	};
}
