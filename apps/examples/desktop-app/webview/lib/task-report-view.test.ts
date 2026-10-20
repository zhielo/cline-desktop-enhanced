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
