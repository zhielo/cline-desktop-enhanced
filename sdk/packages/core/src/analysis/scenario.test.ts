import { expect, it } from "vitest";
import { byteDigest } from "./contracts";
import { reconcileProcessScenario } from "./scenario";
const stdout = Buffer.from("42\n"),
	hash = byteDigest(stdout);
const expected = {
	id: "owned-add",
	purpose: "Owned arithmetic command output",
	exitCode: 0,
	stdoutSha256: hash,
};
const observed = {
	exitCode: 0,
	stdout,
	timedOut: false,
	overflow: false,
	artifactSha256: hash,
	requestHash: hash,
	isolationVerified: true,
};
it("reconciles controller-observed exit/output independently from source identity", () => {
	expect(reconcileProcessScenario(expected, observed)).toMatchObject({
		outcome: "supported",
		scope: "host-observed-standalone-process-interface",
	});
	expect(
		reconcileProcessScenario(expected, {
			...observed,
			stdout: Buffer.from("43\n"),
		}),
	).toMatchObject({ outcome: "contradicted" });
	expect(
		reconcileProcessScenario(expected, { ...observed, exitCode: 1 }),
	).toMatchObject({ outcome: "contradicted" });
});
it("never turns incomplete execution into confirmation or contradiction", () => {
	for (const extra of [
		{ timedOut: true },
		{ overflow: true },
		{ isolationVerified: false },
	])
		expect(
			reconcileProcessScenario(expected, { ...observed, ...extra }).outcome,
		).toBe("inconclusive");
	expect(() =>
		reconcileProcessScenario(expected, {
			...observed,
			artifactSha256: "provider-claim",
		}),
	).toThrow();
	expect(() =>
		reconcileProcessScenario({ ...expected, unexpected: true }, observed),
	).toThrow();
});
