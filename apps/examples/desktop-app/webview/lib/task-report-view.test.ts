import { describe, it, expect } from "vitest";
import {
	taskReportView,
	exportReport,
	formatFinalReport,
} from "./task-report-view";
import type { SessionTaskReport } from "./task-report";
import {
	validationScope,
	type TaskObservation,
} from "../../shared/task-observation";
const scope = validationScope({
	label: "Build",
	validationCommands: ["bun test"],
});
function report(): SessionTaskReport {
	return {
		mode: "plan",
		goal: "Build safely",
		planId: "plan-1",
		steps: [
			{
				id: "step-1",
				label: "Build",
				status: "completed",
				kind: "work",
				validationScope: scope,
			},
		],
		evidence: [],
		completedCount: 1,
		progressPercent: 100,
		sourceMessageId: "m1",
		sourceTool: "update_plan",
		updatedAt: 10,
	};
}
const receipt: TaskObservation = {
	version: "task-observation/v1",
	id: "check-1",
	sessionId: "s1",
	toolCallId: "check-1",
	toolName: "task_validation",
	stepId: "step-1",
	planId: "plan-1",
	source: "host-validation",
	execution: "finished",
	outcome: "bounded-checks-passed",
	checkCount: 1,
	recordedAtMs: 20,
	validationScope: scope,
};
function checked(patch: Partial<TaskObservation> = {}) {
	const r = report();
	r.evidence = [
		{
			id: "e1",
			label: "Checks",
			status: "completed",
			toolName: "task_validation",
			createdAt: 20,
			observation: { ...receipt, ...patch },
		},
	];
	return r;
}
describe("evidence-backed final reports", () => {
	it("keeps model plan completion separate from verification", () => {
		expect(taskReportView(report(), "completed").outcome).toBe("Unverified");
		expect(taskReportView(report(), "idle").delivered[0]).toContain(
			"plan-marked",
		);
	});
	it("requires passed nonempty host checks for the exact current declared scope", () => {
		expect(taskReportView(checked(), "completed").outcome).toBe(
			"Declared checks passed",
		);
		for (const patch of [
			{ source: "host-tool" as const },
			{ planId: "other" },
			{ validationScope: "old" },
			{ validationScope: undefined },
			{ checkCount: 0 },
			{ execution: "running" as const },
			{ outcome: "unverified" as const },
		])
			expect(taskReportView(checked(patch), "idle").verified).toEqual([]);
	});
	it("invalidates stale success when a later check fails", () => {
		const r = checked();
		r.evidence.push({
			...r.evidence[0],
			id: "e2",
			observation: {
				...receipt,
				id: "check2",
				recordedAtMs: 30,
				outcome: "failed",
			},
		});
		expect(taskReportView(r, "idle").verified).toEqual([]);
	});
	it("shows cancellation, partial results, errors and missing history honestly", () => {
		expect(taskReportView(report(), "cancelled").outcome).toContain(
			"Cancelled",
		);
		expect(taskReportView(report(), "failed").execution).toBe("Failed");
		const r = report();
		r.evidence = [
			{
				id: "e1",
				label: "Analyze",
				status: "completed",
				toolName: "analyze",
				createdAt: 20,
				outcome: "partial",
			},
		];
		expect(taskReportView(r, "idle").outcome).toContain("Partial");
		expect(taskReportView(null, "idle").remaining).not.toEqual([]);
		expect(taskReportView(r, "idle").execution).not.toBe("Running");
	});
	it("exports parseable redacted JSON, inert escaped HTML and readable Markdown", () => {
		const view = taskReportView(report(), "idle");
		view.goal =
			"<script>alert(1)</script> password=verysecret C:\\Users\\me\\file.txt";
		const json = exportReport(view, "json").content;
		expect(() => JSON.parse(json)).not.toThrow();
		expect(json).not.toContain("verysecret");
		const html = exportReport(view, "html").content;
		expect(html).not.toContain("<script>");
		expect(html).toContain("&lt;script&gt;");
		expect(html).toContain("default-src 'none'");
		expect(formatFinalReport(view)).toContain("## Not verified");
		expect(formatFinalReport(view)).not.toContain("verysecret");
	});
});

it("never promotes ambiguous same-time failures and exports bounded evidence details", () => {
	const r = checked();
	r.evidence.push({
		...r.evidence[0],
		id: "failure",
		observation: { ...receipt, id: "failure", outcome: "failed" },
	});
	expect(taskReportView(r, "idle").verified).toEqual([]);
	const view = taskReportView(checked(), "idle");
	expect(view.evidenceDetails).toHaveLength(1);
	expect(
		JSON.parse(exportReport(view, "json").content).evidenceDetails[0].source,
	).toBe("host-validation");
	expect(formatFinalReport(view)).toContain("## Execution evidence");
});

it("recovers current outcome after a later matching host check passes without erasing history", () => {
	for (const oldOutcome of ["failed", "blocked", "partial"] as const) {
		const r = checked();
		const success = r.evidence[0];
		r.evidence.unshift({
			...success,
			id: "old",
			status: oldOutcome === "failed" ? "failed" : "completed",
			outcome: oldOutcome,
			observation: {
				...receipt,
				id: "old",
				recordedAtMs: 10,
				outcome: oldOutcome,
			},
		});
		expect(taskReportView(r, "completed").outcome).toBe(
			"Declared checks passed",
		);
		expect(taskReportView(r, "completed").evidenceDetails).toHaveLength(2);
	}
});
it("never clears unassigned or different-scope failures with an unrelated success", () => {
	for (const change of [
		{ observation: undefined },
		{
			observation: {
				...receipt,
				id: "old",
				recordedAtMs: 10,
				outcome: "failed" as const,
				validationScope: "different",
			},
		},
	]) {
		const r = checked();
		r.evidence.unshift({
			...r.evidence[0],
			id: "old",
			status: "failed",
			...change,
		});
		expect(taskReportView(r, "completed").outcome).toContain("Failed");
	}
});

describe("complete available evidence exports", () => {
	it("retains old unresolved failures outside the summary window and discloses export coverage", () => {
		const r = report();
		r.evidence = Array.from({ length: 225 }, (_, i) => ({
			id: `e${i}`,
			label: "Read",
			status: "completed",
			toolName: "read_files",
			createdAt: 1000 - i,
		}));
		r.evidence[224] = {
			...r.evidence[224],
			status: "failed",
			outcome: "failed",
		};
		const summary = taskReportView(r, "completed");
		expect(summary.outcome).toContain("Failed");
		expect(summary.evidenceDetails).toHaveLength(200);
		expect(summary.evidenceCoverage).toEqual({
			included: 200,
			available: 225,
			upstreamTotal: null,
			source: "available-transcript",
		});
		const full = taskReportView(r, "completed", { allAvailableEvidence: true });
		expect(full.evidenceDetails).toHaveLength(225);
		expect(full.evidenceCoverage.included).toBe(225);
		expect(full.exportScope).toBe("all-available-evidence");
		expect(formatFinalReport(full)).toContain("upstream history total unknown");
		expect(
			JSON.parse(exportReport(full, "json").content).evidenceDetails.at(-1).id,
		).toBe("e224");
	});
});

it("downgrades adverse host execution receipts even when their outcome field is unverified", () => {
	for (const execution of [
		"failed",
		"timed_out",
		"blocked",
		"cancelled",
	] as const) {
		const r = checked();
		r.evidence.push({
			id: "adverse",
			label: "Other tool",
			status: "completed",
			toolName: "read_files",
			createdAt: 30,
			observation: {
				...receipt,
				id: "adverse",
				toolCallId: "adverse",
				source: "host-tool",
				execution,
				outcome: "unverified",
			},
		});
		expect(taskReportView(r, "completed").outcome).not.toBe(
			"Declared checks passed",
		);
	}
});

it("makes activity-only edits and absent verification scope explicit without claiming a validated deliverable", () => {
	const r = {
		...report(),
		steps: [],
		mode: "activity" as const,
		evidence: [
			{
				id: "edit",
				label: "Editor",
				detail: "tools/recover_strings.py",
				toolName: "editor",
				status: "completed" as const,
				createdAt: 10,
			},
		],
	};
	const view = taskReportView(r, "completed");
	expect(view.delivered).toEqual([
		"Edit tool completion recorded (not validated): tools/recover_strings.py",
	]);
	expect(view.notVerified[0]).toContain(
		"no recorded declared verification scope",
	);
	expect(view.outcome).toBe("Unverified");
});
it("keeps missing terminal results and adverse receipts in remaining work even when every declared step passed", () => {
	const r = checked();
	r.evidence.push({
		id: "running",
		label: "Command",
		toolName: "run_commands",
		status: "running",
		createdAt: 30,
	});
	const view = taskReportView(r, "completed");
	expect(view.outcome).toBe("Partial / unverified");
	expect(view.verified).toHaveLength(1);
	expect(view.remaining).toContain(
		"Command: no terminal receipt recorded; process liveness unknown",
	);
	const failed = checked({ outcome: "failed", execution: "failed" });
	expect(taskReportView(failed, "completed").remaining.join(" ")).toContain(
		"review the recorded receipt",
	);
});
