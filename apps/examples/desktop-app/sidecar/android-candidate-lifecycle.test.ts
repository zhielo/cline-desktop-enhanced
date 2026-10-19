import { expect, it } from "vitest";
import { digest } from "@cline/core";
import type { AnalysisTaskPlan } from "./analysis-task-orchestrator";
import { summarizeAndroidCandidateLifecycle as summarize } from "./android-candidate-lifecycle";
const h = "a".repeat(64),
	r = "b".repeat(64),
	v = "c".repeat(64);
function fixtures() {
	const request = {
		operation: "build_android_candidate",
		output_file: "/owned/out.apk",
		android_project_patch: {},
	};
	const build = {
		id: "build",
		workspaceRoot: "/owned",
		operation: request.operation,
		request,
		requestHash: digest(request),
		kind: "static",
		permission: "Modify",
		status: "completed",
		createdAt: "2026-10-19T00:00:00Z",
		candidateOutcome: {
			version: "candidate-outcome/v1",
			operation: request.operation,
			evidence: "bounded-checks-passed",
			scope: "android-project-build",
			outputSha256: h,
			publication: "new-unsigned-candidate",
			checks: [],
			limitations: [],
		},
		evidence: {
			requestHash: digest(request),
			resultHash: r,
			tool: "synthetic-test",
			outputPaths: [],
		},
	} as unknown as AnalysisTaskPlan;
	const childRequest = {
		operation: "validate_candidate",
		target: request.output_file,
		candidate_validation: { kind: "apk", expected_sha256: h },
	};
	const child = {
		id: "verification",
		workspaceRoot: "/owned",
		operation: childRequest.operation,
		request: childRequest,
		requestHash: digest(childRequest),
		kind: "static",
		permission: "Inspect",
		status: "completed",
		target: request.output_file,
		targetIdentity: { sha256: h },
		candidateSource: {
			planId: build.id,
			requestHash: build.requestHash,
			resultHash: r,
			outputSha256: h,
		},
		candidateOutcome: {
			version: "candidate-outcome/v1",
			operation: childRequest.operation,
			evidence: "failed",
			scope: "apk",
			inputSha256: h,
			receiptSha256: v,
			checks: [
				{ id: "inspect", status: "completed" },
				{ id: "verify_apk_signature", status: "failed" },
			],
			limitations: [],
		},
		evidence: {
			requestHash: digest(childRequest),
			resultHash: v,
			tool: "synthetic-test",
			outputPaths: [],
		},
	} as unknown as AnalysisTaskPlan;
	return { build, child };
}
it("shows structure and failed signature separately, never signed or device passed", () => {
	const { build, child } = fixtures();
	const before = JSON.stringify([build, child]);
	expect(summarize(build, [build, child])).toMatchObject({
		signing: "not-attested",
		device: "not-linked",
		totalLinkedAttempts: 1,
		rejectedLinks: 0,
		verificationAttempts: [
			{
				status: "completed",
				evidence: "failed",
				structure: "completed",
				signature: "failed",
				receiptSha256: v,
			},
		],
	});
	expect(JSON.stringify([build, child])).toBe(before);
});
it("does not interpret absent, awaiting, cancelled, interrupted or expired attempts as success", () => {
	const { build, child } = fixtures();
	expect(summarize(build, [])?.totalLinkedAttempts).toBe(0);
	for (const status of [
		"awaiting-approval",
		"approved",
		"running",
		"cancelled",
		"interrupted",
		"expired",
	] as const) {
		child.status = status;
		expect(summarize(build, [child])?.verificationAttempts[0]).toMatchObject({
			status,
			evidence: "unavailable",
			signature: "unavailable",
			structure: "unavailable",
		});
	}
});
it.each([
	"requestHash",
	"resultHash",
	"outputSha256",
] as const)("rejects mismatched source %s", (key) => {
	const { build, child } = fixtures();
	child.candidateSource![key] = v;
	expect(summarize(build, [child])).toMatchObject({
		rejectedLinks: 1,
		totalLinkedAttempts: 0,
	});
});
it.each([
	(p: AnalysisTaskPlan) => {
		p.target = "/other.apk";
	},
	(p: AnalysisTaskPlan) => {
		p.request.candidate_validation = { kind: "dex", expected_sha256: h };
		p.requestHash = digest(p.request);
	},
	(p: AnalysisTaskPlan) => {
		p.targetIdentity!.sha256 = v;
	},
	(p: AnalysisTaskPlan) => {
		p.request.timeout_ms = 500;
	},
	(p: AnalysisTaskPlan) => {
		p.kind = "device";
	},
	(p: AnalysisTaskPlan) => {
		p.permission = "Execute";
	},
	(p: AnalysisTaskPlan) => {
		p.request = null as never;
	},
])("rejects inconsistent linked target, request or permission (%#)", (mutate) => {
	const { build, child } = fixtures();
	mutate(child);
	expect(summarize(build, [child])).toMatchObject({
		rejectedLinks: 1,
		totalLinkedAttempts: 0,
	});
});
it("ignores foreign workspaces and unrelated same-hash files", () => {
	const { build, child } = fixtures();
	child.workspaceRoot = "/foreign";
	expect(summarize(build, [child])?.totalLinkedAttempts).toBe(0);
	child.workspaceRoot = build.workspaceRoot;
	child.candidateSource = undefined;
	expect(summarize(build, [child])?.totalLinkedAttempts).toBe(0);
});
it.each([
	(p: AnalysisTaskPlan) => {
		p.candidateOutcome!.inputSha256 = v;
	},
	(p: AnalysisTaskPlan) => {
		p.candidateOutcome!.scope = "dex";
	},
	(p: AnalysisTaskPlan) => {
		p.candidateOutcome!.checks.pop();
	},
	(p: AnalysisTaskPlan) => {
		p.candidateOutcome!.checks[1] = p.candidateOutcome!.checks[0];
	},
	(p: AnalysisTaskPlan) => {
		p.candidateOutcome!.checks[0] = null as never;
	},
	(p: AnalysisTaskPlan) => {
		p.candidateOutcome!.evidence = "bounded-checks-passed";
	},
	(p: AnalysisTaskPlan) => {
		p.evidence!.requestHash = v;
	},
	(p: AnalysisTaskPlan) => {
		p.candidateOutcome!.receiptSha256 = "bad";
	},
])("does not promote unsupported retained verification metadata (%#)", (mutate) => {
	const { build, child } = fixtures();
	mutate(child);
	expect(summarize(build, [child])?.verificationAttempts[0]).toMatchObject({
		evidence: "unavailable",
		structure: "unavailable",
		signature: "unavailable",
	});
});
it("does not hide earlier failed verification behind a later passing attempt", () => {
	const { build, child } = fixtures();
	const pass = structuredClone(child);
	pass.id = "second";
	pass.candidateOutcome!.evidence = "bounded-checks-passed";
	pass.candidateOutcome!.checks[1].status = "completed";
	expect(
		summarize(build, [pass, child])?.verificationAttempts.map(
			(a) => a.signature,
		),
	).toEqual(["completed", "failed"]);
});
it("shows explicit bounded history and never recovers pruned tasks", () => {
	const { build, child } = fixtures();
	const result = summarize(
		build,
		Array.from({ length: 12 }, (_, i) => ({ ...child, id: `v-${i}` })),
	);
	expect(result).toMatchObject({ totalLinkedAttempts: 12, omittedAttempts: 2 });
	expect(result?.verificationAttempts).toHaveLength(10);
	expect(summarize(build, [])?.limitations.join(" ")).toContain("pruned tasks");
});
it.each([
	"failed",
	"partial",
	"unavailable",
] as const)("does not create a lifecycle from %s build evidence", (evidence) => {
	const { build } = fixtures();
	build.candidateOutcome!.evidence = evidence;
	expect(summarize(build, [])).toBeUndefined();
});
it("rejects stale build requests and malformed retained requests without throwing", () => {
	const { build } = fixtures();
	build.request.output_file = "/different.apk";
	expect(summarize(build, [])).toBeUndefined();
	build.request = null as never;
	expect(summarize(build, [])).toBeUndefined();
});
