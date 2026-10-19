import { afterEach, expect, it } from "vitest";
import { mkdtemp, mkdir, writeFile, rm, readFile, realpath, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { ReverseEngineeringInputSchema, digest } from "@cline/core";
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
it.each([false, true])("retains an explicitly synthetic build receipt through approved ledger restart without replay (aliased workspace: %s)", async (aliased) => {
	const container = await mkdtemp(join(tmpdir(), "cline-build-summary-"));
	roots.push(container);
	const actualRoot = join(container, "workspace");
	await mkdir(actualRoot);
	const root = aliased ? join(container, "workspace-alias") : actualRoot;
	if (aliased) await symlink(actualRoot, root, "junction");
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
	const ledger = join(root, "ledger.json"),
		host = new AnalysisTaskOrchestrator({ ledgerFilePath: ledger });
	const prepared = await host.prepare({
		workspaceRoot: root,
		kind: "static",
		request,
	});
	// The real producer receives the host-canonical request, not the raw input path.
	// Ledger contract fixture only: no builder is invoked and no APK is produced.
	const built = receipt({ outputFile: prepared.request.output_file });
	Object.assign(built.stages[0].result, {
		path: "smali/Sample.smali",
		inputSha256: createHash("sha256").update(text).digest("hex"),
	});
	if (aliased) {
		expect(prepared.request.output_file).not.toBe(out);
		expect(summarizeCandidateOutcome(prepared, { ...built, outputFile: out })?.evidence).toBe("unavailable");
	}
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

// Identity/approval contracts only; these bytes deliberately are not a valid APK.
async function ownedBuildForHandoff(options: { external?: boolean; partial?: boolean; failed?: boolean } = {}) {
 const root = await mkdtemp(join(tmpdir(), "cline-build-handoff-")); roots.push(root);
 const outside = options.external ? await mkdtemp(join(tmpdir(), "cline-external-candidate-")) : root;
 if (outside !== root) roots.push(outside);
 const rawOut = join(outside, "candidate.apk"), bytes = "synthetic identity fixture, not APK acceptance";
 await writeFile(rawOut, bytes);
 const out = await realpath(rawOut);
 const outputHash = createHash("sha256").update(bytes).digest("hex");
 const host = new AnalysisTaskOrchestrator({ ledgerFilePath: join(root, "ledger.json") });
 const request = { ...plan.request, operation: plan.operation, output_file: out };
 const prepared = await host.prepare({ workspaceRoot: root, kind: "static", request });
 const approval = host.approve(prepared.id, prepared.requirements, prepared.requestHash);
 await host.consume({ planId: prepared.id, executionToken: approval.executionToken, workspaceRoot: root, kind: "static", request });
 const built = receipt({ outputFile: prepared.request.output_file, outputSha256: outputHash, ...(options.partial ? { cleanupWarnings: ["owned cleanup uncertainty"] } : {}) });
 Object.assign(built.stages.at(-1)!.result, { outputSha256: outputHash });
 if (options.failed) host.failWithEvidence(prepared.id, built, "synthetic-owned-fixture", "failed");
 else host.complete(prepared.id, built, "synthetic-owned-fixture");
 return { root, out, outputHash, prepared, host };
}
it("prepares a fresh independent Inspect plan with provenance and requires new approval", async () => {
 const f = await ownedBuildForHandoff();
 const host = new AnalysisTaskOrchestrator({ ledgerFilePath: join(f.root, "ledger.json") });
 const next = await host.prepareCandidateVerification({ workspaceRoot: f.root, planId: f.prepared.id });
 expect(next).toMatchObject({ kind: "static", operation: "validate_candidate", permission: "Inspect", status: "awaiting-approval", target: f.out,
  targetIdentity: { sha256: f.outputHash }, candidateSource: { planId: f.prepared.id, requestHash: f.prepared.requestHash, outputSha256: f.outputHash } });
 expect(ReverseEngineeringInputSchema.parse(next.request).candidate_validation).toEqual({ kind: "apk", expected_sha256: f.outputHash });
 expect(ReverseEngineeringInputSchema.parse(next.request)).toEqual(next.request);
 expect(next.id).not.toBe(f.prepared.id); expect(next.budget.network).toBe("disabled");
 expect(JSON.stringify(next)).not.toContain("executionToken");
 await expect(host.consume({ planId: next.id, executionToken: "invented-token", workspaceRoot: f.root, kind: "static", request: next.request })).rejects.toThrow();
 const restored = new AnalysisTaskOrchestrator({ ledgerFilePath: join(f.root, "ledger.json") });
 expect(restored.list(f.root).find(p => p.id === next.id)?.candidateSource).toEqual(next.candidateSource);
 const approved = restored.approve(next.id, next.requirements, next.requestHash);
 await writeFile(f.out, "changed after approval");
 await expect(restored.consume({ planId: next.id, executionToken: approved.executionToken, workspaceRoot: f.root, kind: "static", request: next.request })).rejects.toThrow("target changed");
});
it("rejects wrong workspace, missing or changed output and unrelated plans", async () => {
 const f = await ownedBuildForHandoff();
 const other = await mkdtemp(join(tmpdir(), "cline-other-workspace-")); roots.push(other);
 await expect(f.host.prepareCandidateVerification({ workspaceRoot: other, planId: f.prepared.id })).rejects.toThrow("does not belong");
 await writeFile(f.out, "different");
 await expect(f.host.prepareCandidateVerification({ workspaceRoot: f.root, planId: f.prepared.id })).rejects.toThrow("changed since the build");
 await rm(f.out);
 await expect(f.host.prepareCandidateVerification({ workspaceRoot: f.root, planId: f.prepared.id })).rejects.toThrow("missing");
 const pending = await f.host.prepare({ workspaceRoot: f.root, kind: "static", request: { operation: "inspect" } });
 await expect(f.host.prepareCandidateVerification({ workspaceRoot: f.root, planId: pending.id })).rejects.toThrow("build receipt is required");
 expect(f.host.list(f.root).filter(p => p.operation === "validate_candidate")).toHaveLength(0);
});
it.each([{partial:true}, {failed:true}])("does not promote incomplete build evidence (%j)", async (options) => {
 const f = await ownedBuildForHandoff(options);
 await expect(f.host.prepareCandidateVerification({ workspaceRoot: f.root, planId: f.prepared.id })).rejects.toThrow("build receipt is required");
});
it("requires a new external-target acknowledgement rather than inheriting build authority", async () => {
 const f = await ownedBuildForHandoff({ external: true });
 await expect(f.host.prepareCandidateVerification({ workspaceRoot: f.root, planId: f.prepared.id })).rejects.toThrow("outside the workspace");
 const next = await f.host.prepareCandidateVerification({ workspaceRoot: f.root, planId: f.prepared.id, allowExternalTarget: true });
 expect(next.requirements).toContain("external-target"); expect(next.status).toBe("awaiting-approval");
});

it("consumes only the separately approved canonical verification envelope", async () => {
 const f = await ownedBuildForHandoff();
 const next = await f.host.prepareCandidateVerification({ workspaceRoot: f.root, planId: f.prepared.id });
 const approved = f.host.approve(next.id, next.requirements, next.requestHash);
 const running = await f.host.consume({ planId: next.id, executionToken: approved.executionToken, workspaceRoot: f.root, kind: "static", request: ReverseEngineeringInputSchema.parse(next.request) });
 expect(running.status).toBe("running");
 f.host.fail(next.id, "Owned identity test only; no APK verification engine was invoked");
 await expect(f.host.consume({ planId: next.id, executionToken: approved.executionToken, workspaceRoot: f.root, kind: "static", request: next.request })).rejects.toThrow();
});

it("recomputes build lifecycle from independent retained attempts across restart, without replay", async () => {
 const f = await ownedBuildForHandoff();
 const next = await f.host.prepareCandidateVerification({ workspaceRoot: f.root, planId: f.prepared.id });
 expect(f.host.list(f.root).find(p => p.id === f.prepared.id)?.candidateLifecycle).toMatchObject({
  totalLinkedAttempts: 1, signing: "not-attested", device: "not-linked",
  verificationAttempts: [{ planId: next.id, status: "awaiting-approval", evidence: "unavailable" }],
 });
 f.host.cancel(next.id);
 const savedLedger = JSON.parse(await readFile(join(f.root, "ledger.json"), "utf8"));
 savedLedger.plans.find((p: { id: string }) => p.id === f.prepared.id).candidateLifecycle = { version: "android-candidate-lifecycle/v1", signing: "forged-pass", device: "forged-pass" };
 await writeFile(join(f.root, "ledger.json"), JSON.stringify(savedLedger));
 const restored = new AnalysisTaskOrchestrator({ ledgerFilePath: join(f.root, "ledger.json") });
 expect(restored.list(f.root).find(p => p.id === f.prepared.id)?.candidateLifecycle?.verificationAttempts[0]).toMatchObject({ status: "cancelled", signature: "unavailable" });
 const ledger = JSON.parse(await readFile(join(f.root, "ledger.json"), "utf8"));
 expect(JSON.stringify(ledger)).not.toContain('"candidateLifecycle"');
 expect(JSON.stringify(restored.list(f.root))).not.toContain("executionToken");
 expect(await readFile(f.out, "utf8")).toBe("synthetic identity fixture, not APK acceptance");
});

it("links a separately consumed failed verification receipt without upgrading unsigned/device status", async () => {
 const f = await ownedBuildForHandoff();
 const next = await f.host.prepareCandidateVerification({ workspaceRoot: f.root, planId: f.prepared.id });
 const approval = f.host.approve(next.id, next.requirements, next.requestHash);
 await f.host.consume({ planId: next.id, executionToken: approval.executionToken, workspaceRoot: f.root, kind: "static", request: next.request });
 // Synthetic protocol contract only: the fixture bytes are deliberately not an APK.
 const body = { protocol: "cline-candidate-verification/v1", operation: "validate_candidate", effect: "read", status: "failed", inputSha256: f.outputHash, inputBytes: 45,
  checks: [{ id: "inspect", status: "completed" }, { id: "verify_apk_signature", status: "failed" }], limitations: ["Synthetic test, not APK acceptance"], published: false, observedExecution: false };
 f.host.failWithEvidence(next.id, { ...body, receiptSha256: digest(body) }, "synthetic-owned-fixture", "signature failed");
 const restored = new AnalysisTaskOrchestrator({ ledgerFilePath: join(f.root, "ledger.json") });
 const summary = restored.list(f.root).find(p => p.id === f.prepared.id)?.candidateLifecycle;
 expect(summary).toMatchObject({ signing: "not-attested", device: "not-linked", totalLinkedAttempts: 1,
  verificationAttempts: [{ planId: next.id, status: "failed", evidence: "failed", structure: "completed", signature: "failed", receiptSha256: digest(body) }] });
 expect(restored.evidenceBundle(f.prepared.id, f.root).payload.task.candidateLifecycle).toBeUndefined();
 await expect(restored.consume({ planId: next.id, executionToken: approval.executionToken, workspaceRoot: f.root, kind: "static", request: next.request })).rejects.toThrow();
 expect(await readFile(f.out, "utf8")).toBe("synthetic identity fixture, not APK acceptance");
});
