import { z } from "zod";
import { byteDigest, digest } from "./contracts";
export const ScenarioExpectationSchema = z
	.object({
		id: z.string().regex(/^[a-zA-Z0-9_.-]{1,80}$/),
		purpose: z.string().min(1).max(500),
		exitCode: z.number().int().min(0).max(255),
		stdoutSha256: z.string().regex(/^[a-f0-9]{64}$/),
	})
	.strict();
/** A process-interface scenario: host-captured exit/output, not target/provider assertions. */
export function reconcileProcessScenario(
	expectation: unknown,
	observation: {
		exitCode: number;
		stdout: Uint8Array;
		timedOut: boolean;
		overflow: boolean;
		artifactSha256: string;
		requestHash: string;
		isolationVerified: boolean;
	},
) {
	const expected = ScenarioExpectationSchema.parse(expectation);
	if (
		!/^[a-f0-9]{64}$/.test(observation.artifactSha256) ||
		!/^[a-f0-9]{64}$/.test(observation.requestHash)
	)
		throw new Error("Scenario exact artifact/request binding required");
	const actual = {
		exitCode: observation.exitCode,
		stdoutSha256: byteDigest(observation.stdout),
	};
	const conclusive =
		observation.isolationVerified &&
		!observation.timedOut &&
		!observation.overflow;
	const assertions = [
		{
			predicate: "process-exit-code",
			expected: expected.exitCode,
			actual: actual.exitCode,
			matched: actual.exitCode === expected.exitCode,
		},
		{
			predicate: "stdout-byte-digest",
			expected: expected.stdoutSha256,
			actual: actual.stdoutSha256,
			matched: actual.stdoutSha256 === expected.stdoutSha256,
		},
	];
	const body = {
		scenarioId: expected.id,
		purpose: expected.purpose,
		artifactSha256: observation.artifactSha256,
		requestHash: observation.requestHash,
		scope: "host-observed-standalone-process-interface" as const,
		outcome: !conclusive
			? "inconclusive"
			: assertions.every((a) => a.matched)
				? "supported"
				: "contradicted",
		assertions,
		limitations: [
			"One approved isolated run only. Target-generated output can lie about internal behavior. No path coverage, native execution, Electron GUI fidelity, external side-effect verification or equivalence proof.",
		],
	};
	return { ...body, reconciliationHash: digest(body) };
}
