import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	createReverseEngineeringExecutor,
	digest,
	ReverseEngineeringInputSchema,
} from "@cline/core";
import { afterEach, expect, it } from "vitest";
import { AnalysisTaskOrchestrator } from "./analysis-task-orchestrator";
import { summarizeCandidateOutcome } from "./candidate-outcome";

const hash = "a".repeat(64);
const basis = {
	operation: "validate_candidate",
	targetIdentity: { sha256: hash },
	request: {
		candidate_validation: { kind: "typescript", expected_sha256: hash },
	},
};
function receipt(overrides: Record<string, unknown> = {}) {
	const body = {
		protocol: "cline-candidate-verification/v1",
		operation: "validate_candidate",
		effect: "read",
		status: "completed",
		inputSha256: hash,
		inputBytes: 20,
		checks: [{ id: "source-syntax", status: "completed" }],
		limitations: ["Syntax only"],
		published: false,
		observedExecution: false,
		...overrides,
	};
	return { ...body, receiptSha256: digest(body) };
}
it("separates bounded checks from operational completion and behavior", () => {
	expect(summarizeCandidateOutcome(basis, receipt())).toMatchObject({
		evidence: "bounded-checks-passed",
		scope: "typescript",
		inputSha256: hash,
	});
	expect(
		summarizeCandidateOutcome(basis, receipt())?.limitations.join(" "),
	).toContain("not a current file hash");
	expect(
		summarizeCandidateOutcome({ ...basis, operation: "inspect" }, receipt()),
	).toBeUndefined();
});
it.each([
	[{ status: "failed" }, "failed"],
	[{ checks: [{ id: "source-syntax", status: "failed" }] }, "failed"],
	[{ status: "partial" }, "partial"],
	[{ checks: [{ id: "source-syntax", status: "blocked" }] }, "partial"],
	[{ checks: [{ id: "source-syntax", status: "partial" }] }, "partial"],
	[
		{ checks: [{ id: "source-syntax", status: "completed", truncated: true }] },
		"partial",
	],
])("keeps incomplete or failed checks distinct (%j)", (data, expected) =>
	expect(summarizeCandidateOutcome(basis, receipt(data))?.evidence).toBe(
		expected,
	));
it.each([
	{ protocol: "unknown" },
	{ operation: "review_candidate_changes" },
	{ inputSha256: "b".repeat(64) },
	{ effect: "write" },
	{ published: true },
	{ observedExecution: true },
	{ inputBytes: 17 * 1024 * 1024 },
	{ checks: [] },
	{ checks: [{ id: "other", status: "completed" }] },
	{
		checks: [
			{ id: "source-syntax", status: "completed" },
			{ id: "source-syntax", status: "completed" },
		],
	},
	{ checks: [{ id: "source-syntax", status: "verified" }] },
])("never infers passing from an unsupported receipt (%j)", (data) =>
	expect(summarizeCandidateOutcome(basis, receipt(data))?.evidence).toBe(
		"unavailable",
	));
it("checks canonical integrity and both prepared input identities", () => {
	const r = receipt();
	expect(
		summarizeCandidateOutcome(basis, { ...r, inputBytes: 21 })?.evidence,
	).toBe("unavailable");
	expect(
		summarizeCandidateOutcome(
			{ ...basis, targetIdentity: { sha256: "b".repeat(64) } },
			r,
		)?.evidence,
	).toBe("unavailable");
	expect(
		summarizeCandidateOutcome({ ...basis, request: {} }, r)?.evidence,
	).toBe("unavailable");
	expect(
		summarizeCandidateOutcome(basis, {
			status: "completed",
			verified: true,
			exitCode: 0,
		})?.evidence,
	).toBe("unavailable");
});
it.each([
	"javascript",
	"typescript",
	"dex",
	"apk",
])("requires the exact %s check set", (kind) => {
	const ids =
		kind === "dex"
			? ["dex-header-integrity-extents"]
			: kind === "apk"
				? ["inspect", "verify_apk_signature"]
				: ["source-syntax"];
	const plan = {
		...basis,
		request: { candidate_validation: { kind, expected_sha256: hash } },
	};
	expect(
		summarizeCandidateOutcome(
			plan,
			receipt({ checks: ids.map((id) => ({ id, status: "completed" })) }),
		)?.evidence,
	).toBe("bounded-checks-passed");
});
it.each([
	["recipe", "exact-recipe-audit"],
	["project-files", "full-project-file-scope"],
	["project-inventory", "full-project-file-inventory-draft"],
])("binds %s review to its approved scope", (scope, id) => {
	const plan = {
		...basis,
		operation: "review_candidate_changes",
		request: { candidate_review: { manifest_sha256: hash, scope } },
	};
	expect(
		summarizeCandidateOutcome(
			plan,
			receipt({
				operation: plan.operation,
				checks: [{ id, status: "completed" }],
			}),
		)?.scope,
	).toBe(scope);
	expect(
		summarizeCandidateOutcome(plan, receipt({ operation: plan.operation }))
			?.evidence,
	).toBe("unavailable");
});
it("bounds retained limitations and does not retain raw diagnostics or engine output", () => {
	const outcome = summarizeCandidateOutcome(
		basis,
		receipt({
			limitations: Array.from({ length: 40 }, () => "x".repeat(4000)),
			checks: [
				{
					id: "source-syntax",
					status: "completed",
					diagnostics: [{ secret: "RAW_NEVER_RETAIN" }],
				},
			],
		}),
	);
	expect(JSON.stringify(outcome).length).toBeLessThan(14000);
	expect(JSON.stringify(outcome)).not.toContain("RAW_NEVER_RETAIN");
	expect(outcome?.limitations.at(-1)).toContain("omitted");
});
const roots: string[] = [];
afterEach(() => {
	for (const root of roots.splice(0))
		rmSync(root, { recursive: true, force: true });
});
async function running(text: string) {
	const root = mkdtempSync(join(tmpdir(), "cline-outcome-"));
	roots.push(root);
	const target = join(root, "candidate.ts"),
		ledger = join(root, "ledger.json");
	writeFileSync(target, text);
	const expected_sha256 = createHash("sha256").update(text).digest("hex");
	const request = {
		operation: "validate_candidate" as const,
		target,
		candidate_validation: { kind: "typescript" as const, expected_sha256 },
	};
	const host = new AnalysisTaskOrchestrator({ ledgerFilePath: ledger });
	const plan = await host.prepare({
		workspaceRoot: root,
		kind: "static",
		request,
	});
	const approval = host.approve(plan.id, plan.requirements, plan.requestHash);
	await host.consume({
		planId: plan.id,
		executionToken: approval.executionToken,
		workspaceRoot: root,
		kind: "static",
		request,
	});
	return { root, target, ledger, request, host, plan, approval };
}
it.each([
	["export const value = 1;", "completed"],
	["export const = ;", "failed"],
])("retains real syntax-verifier outcomes through restart (%s)", async (text, status) => {
	const c = await running(text);
	const result = JSON.parse(
		await createReverseEngineeringExecutor()(
			ReverseEngineeringInputSchema.parse(c.request),
			{
				sessionId: "owned",
				toolCallId: "candidate-outcome-test",
				agentId: "owned",
				iteration: 0,
			},
		),
	);
	expect(result.status).toBe(status);
	const saved =
		status === "failed"
			? c.host.failWithEvidence(
					c.plan.id,
					result,
					"reverse-engineering",
					"Candidate syntax failed",
				)
			: c.host.complete(c.plan.id, result, "reverse-engineering");
	expect(saved.status).toBe(status);
	expect(saved.candidateOutcome?.evidence).toBe(
		status === "failed" ? "failed" : "bounded-checks-passed",
	);
	expect(saved.evidence?.outputPaths).toEqual([]);
	const restored = new AnalysisTaskOrchestrator({ ledgerFilePath: c.ledger });
	expect(restored.list(c.root)[0].candidateOutcome).toEqual(
		saved.candidateOutcome,
	);
	expect(restored.evidenceBundle(c.plan.id, c.root).payload.task.status).toBe(
		status,
	);
	expect(readFileSync(c.target, "utf8")).toBe(text);
	expect(readFileSync(c.ledger, "utf8")).not.toContain(
		c.approval.executionToken,
	);
	await expect(
		restored.consume({
			planId: c.plan.id,
			executionToken: c.approval.executionToken,
			workspaceRoot: c.root,
			kind: "static",
			request: c.request,
		}),
	).rejects.toThrow();
	expect(() => restored.evidenceBundle(c.plan.id, tmpdir())).toThrow(
		"workspace",
	);
});
it("never resurrects cancelled work or invents evidence for exceptions", async () => {
	const c = await running("const a = 1;");
	c.host.cancel(c.plan.id);
	expect(
		c.host.failWithEvidence(c.plan.id, receipt(), "test", "error").status,
	).toBe("cancelled");
	expect(() => c.host.evidenceBundle(c.plan.id, c.root)).toThrow(
		"retained evidence",
	);
	const other = await running("const b = 2;");
	other.host.fail(other.plan.id, "engine unavailable");
	expect(other.host.list(other.root)[0].candidateOutcome).toBeUndefined();
	expect(() => other.host.evidenceBundle(other.plan.id, other.root)).toThrow(
		"retained evidence",
	);
});
it("can retain a partial receipt without changing completed operational status", async () => {
	const c = await running("const a = 1;");
	const result = receipt({
		inputSha256: c.request.candidate_validation.expected_sha256,
		status: "partial",
		checks: [{ id: "source-syntax", status: "blocked" }],
	});
	expect(c.host.complete(c.plan.id, result, "test")).toMatchObject({
		status: "completed",
		candidateOutcome: { evidence: "partial" },
	});
});
