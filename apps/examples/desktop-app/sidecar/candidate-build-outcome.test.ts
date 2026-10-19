import { afterEach, expect, it } from "vitest";
import { mkdtemp, mkdir, writeFile, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { ReverseEngineeringInputSchema } from "@cline/core";
import { AnalysisTaskOrchestrator } from "./analysis-task-orchestrator";
import { summarizeCandidateOutcome } from "./candidate-outcome";
const hash = "a".repeat(64),
	preview = "b".repeat(64),
	output = "c".repeat(64);
const plan = {
	operation: "build_android_candidate",
	request: {
		output_file: "/owned/candidate.apk",
		android_project_patch: {
			expected_project_sha256: hash,
			preview_sha256: preview,
			patches: [
				{ path: "smali/Owned.smali", patch: { expected_sha256: hash } },
			],
		},
	},
};
function receipt(overrides: Record<string, unknown> = {}) {
	return {
		protocol: "cline-android-project-candidate/v1",
		schemaVersion: 1,
		operation: plan.operation,
		effect: "candidate-write",
		status: "completed",
		projectSha256: hash,
		previewSha256: preview,
		outputFile: plan.request.output_file,
		published: true,
		observedExecution: false,
		cleanup: "private-workspace-removal-scheduled",
		cleanupWarnings: [],
		smaliRoots: ["smali", "smali_classes2"],
		stages: [
			{
				id: "patch-0",
				result: {
					status: "completed",
					path: "smali/Owned.smali",
					inputSha256: hash,
					candidateSha256: preview,
				},
			},
			{ id: "assemble-smali", result: { succeeded: true } },
			{ id: "assemble-smali_classes2", result: { succeeded: true } },
			{
				id: "rebuild-apk",
				result: {
					succeeded: true,
					outputSha256: output,
					outputValidation: "bounded-structure-checked; owned test",
				},
			},
		],
		sourceUnchanged: true,
		candidateProjectSha256: preview,
		outputSha256: output,
		validation: "all-smali-roots-assembled; bounded-apk-structure-checked",
		signingStatus: "new-unsigned-artifact",
		limitations: ["Owned test, not a real engine attestation"],
		...overrides,
	};
}
it("summarizes only an approved unsigned build without execution authority", () => {
	const r = summarizeCandidateOutcome(plan, receipt());
	expect(r).toMatchObject({
		evidence: "bounded-checks-passed",
		inputSha256: hash,
		outputSha256: output,
		publication: "new-unsigned-candidate",
	});
	expect(r?.checks).toHaveLength(4);
	expect(r?.limitations.join(" ")).toContain(
		"Signature verification, install, device execution",
	);
	expect(
		summarizeCandidateOutcome({ ...plan, request: {} }, receipt()),
	).toBeUndefined();
});
it.each([
	{ protocol: "other" },
	{ effect: "read" },
	{ projectSha256: preview },
	{ previewSha256: hash },
	{ outputFile: "/other.apk" },
	{ observedExecution: true },
	{ published: false },
	{ sourceUnchanged: false },
	{ signingStatus: "signed" },
	{ validation: "verified" },
	{ smaliRoots: ["smali", "smali"] },
	{ smaliRoots: ["../smali"] },
	{ stages: [] },
	{ outputSha256: preview },
	{ candidateProjectSha256: undefined },
])("does not infer success from unsupported evidence (%j)", (data) =>
	expect(summarizeCandidateOutcome(plan, receipt(data))?.evidence).toBe(
		"unavailable",
	));
it.each([
	"cancelled",
	"timedOut",
	"outputDrainTimedOut",
])("rejects a completed build with %s engine evidence", (key) => {
	const r = receipt();
	Object.assign(r.stages[1].result, { [key]: true });
	expect(summarizeCandidateOutcome(plan, r)?.evidence).toBe("unavailable");
});
it("rejects missing, duplicate, reordered and wrong-input stage evidence", () => {
	for (const mutate of [
		(r: ReturnType<typeof receipt>) => r.stages.splice(1, 1),
		(r: ReturnType<typeof receipt>) => r.stages.push(r.stages[1]),
		(r: ReturnType<typeof receipt>) => r.stages.reverse(),
		(r: ReturnType<typeof receipt>) => {
			Object.assign(r.stages[0].result, { inputSha256: preview });
		},
		(r: ReturnType<typeof receipt>) => {
			Object.assign(r.stages[0].result, { path: "smali/Other.smali" });
		},
	]) {
		const r = receipt();
		mutate(r);
		expect(summarizeCandidateOutcome(plan, r)?.evidence).toBe("unavailable");
	}
});
it.each([
	"blocked",
	"cancelled",
	"failed",
])("retains %s without claiming publication", (status) => {
	const r = summarizeCandidateOutcome(
		plan,
		receipt({ status, published: false, outputSha256: undefined, stages: [] }),
	);
	expect(r?.evidence).toBe(status === "failed" ? "failed" : "partial");
	expect(r?.outputSha256).toBeUndefined();
	expect(summarizeCandidateOutcome(plan, receipt({ status }))?.evidence).toBe(
		"unavailable",
	);
});
it("retains cleanup uncertainty but excludes raw diagnostics and paths", () => {
	const r = receipt({ cleanupWarnings: ["PRIVATE_PATH_NEVER_RETAIN"] });
	Object.assign(r.stages[1].result, { stdout: "RAW_SECRET_NEVER_RETAIN" });
	const s = summarizeCandidateOutcome(plan, r);
	expect(s?.evidence).toBe("partial");
	expect(JSON.stringify(s)).not.toContain("NEVER_RETAIN");
});
const roots: string[] = [];
afterEach(async () => {
	await Promise.all(
		roots.splice(0).map((p) => rm(p, { recursive: true, force: true })),
	);
});
it("retains an explicitly synthetic build receipt through approved ledger restart without replay", async () => {
	const root = await mkdtemp(join(tmpdir(), "cline-build-summary-"));
	roots.push(root);
	const target = join(root, "project"),
		out = join(root, "candidate.apk");
	await mkdir(join(target, "smali"), { recursive: true });
	const before =
		".method public static value()I\n .registers 1\n const/4 v0, 0x0\n return v0\n.end method";
	const text = `.class public Lowned/Sample;\n.super Ljava/lang/Object;\n${before}\n`;
	await writeFile(join(target, "smali", "Sample.smali"), text);
	await writeFile(join(target, "apktool.yml"), "version: 3.0.3\n");
	await writeFile(join(target, "AndroidManifest.xml"), "<manifest/>");
	const input = ReverseEngineeringInputSchema.parse({
		operation: "preview_android_candidate",
		target,
		output_file: out,
		android_project_patch: {
			patches: [
				{
					path: "smali/Sample.smali",
					patch: {
						expected_sha256: createHash("sha256").update(text).digest("hex"),
						class_descriptor: "Lowned/Sample;",
						method_signature: "value()I",
						expected_method: before,
						replacement_method: before.replace("0x0", "0x1"),
					},
				},
			],
		},
	});
	const request = ReverseEngineeringInputSchema.parse({
		...input,
		operation: "build_android_candidate",
		android_project_patch: {
			...input.android_project_patch,
			expected_project_sha256: hash,
			preview_sha256: preview,
		},
	});
	// Ledger contract fixture only: this test does not invoke a builder or produce an APK.
	const built = receipt({ outputFile: out });
	Object.assign(built.stages[0].result, {
		path: "smali/Sample.smali",
		inputSha256: createHash("sha256").update(text).digest("hex"),
	});
	const ledger = join(root, "ledger.json"),
		host = new AnalysisTaskOrchestrator({ ledgerFilePath: ledger });
	const prepared = await host.prepare({
		workspaceRoot: root,
		kind: "static",
		request,
	});
	expect(prepared.permission).toBe("Modify");
	const approval = host.approve(
		prepared.id,
		prepared.requirements,
		prepared.requestHash,
	);
	await host.consume({
		planId: prepared.id,
		executionToken: approval.executionToken,
		workspaceRoot: root,
		kind: "static",
		request,
	});
	const saved = host.complete(prepared.id, built, "reverse-engineering");
	expect(saved.candidateOutcome).toMatchObject({
		evidence: "bounded-checks-passed",
		outputSha256: output,
		publication: "new-unsigned-candidate",
	});
	const restarted = new AnalysisTaskOrchestrator({ ledgerFilePath: ledger });
	expect(restarted.list(root)[0].candidateOutcome).toEqual(
		saved.candidateOutcome,
	);
	expect(
		JSON.stringify(restarted.evidenceBundle(prepared.id, root)),
	).not.toContain("candidateProjectSha256");
	await expect(
		restarted.consume({
			planId: prepared.id,
			executionToken: approval.executionToken,
			workspaceRoot: root,
			kind: "static",
			request,
		}),
	).rejects.toThrow();
	await expect(readFile(out)).rejects.toThrow();
	expect(await readFile(join(target, "smali", "Sample.smali"), "utf8")).toBe(
		text,
	);
});
