import {
	redactReportText,
	type TaskObservation,
} from "../../shared/task-observation";
import type { ChatSessionStatus } from "./chat-schema";
import type { SessionTaskReport } from "./task-report";

export type TaskReportView = {
	version: "task-report/v1";
	execution: string;
	outcome: string;
	goal: string;
	delivered: string[];
	verified: string[];
	notVerified: string[];
	remaining: string[];
	artifacts: string[];
	nextAction: string;
	scopeChanges: string[];
	evidenceIds: string[];
	limitations: string[];
	evidenceDetails: Array<{
		id: string;
		action: string;
		execution: string;
		outcome: string;
		target?: string;
		stepId?: string;
		recordedAtMs: number;
		durationMs?: number;
		source: string;
		planId?: string;
		validationScope?: string;
	}>;
};
export function isTaskActive(status?: ChatSessionStatus) {
	return status === "running" || status === "starting" || status === "stopping";
}
export function taskReportView(
	report: SessionTaskReport | null | undefined,
	status?: ChatSessionStatus,
): TaskReportView {
	const active = isTaskActive(status);
	const steps = report?.steps ?? [],
		evidence = report?.evidence ?? [];
	const latestChecks = new Map<string, TaskObservation>();
	for (const item of evidence) {
		const o = item.observation;
		if (
			o?.source !== "host-validation" ||
			!o.stepId ||
			!o.planId ||
			o.planId !== report?.planId
		)
			continue;
		const old = latestChecks.get(o.stepId);
		if (
			!old ||
			o.recordedAtMs > old.recordedAtMs ||
			(o.recordedAtMs === old.recordedAtMs &&
				o.outcome !== "bounded-checks-passed")
		)
			latestChecks.set(o.stepId, o);
	}
	const verified = steps.filter(
		(step) =>
			step.status === "completed" &&
			latestChecks.get(step.id)?.execution === "finished" &&
			latestChecks.get(step.id)?.outcome === "bounded-checks-passed" &&
			(latestChecks.get(step.id)?.checkCount ?? 0) > 0 &&
			step.validationScope !== undefined &&
			latestChecks.get(step.id)?.validationScope === step.validationScope,
	);
	const remaining = steps
		.filter((step) => step.status !== "completed")
		.map((step) => `${step.label} — ${step.status}`);
	const failed =
		status === "error" ||
		status === "failed" ||
		evidence.some((e) => e.status === "failed");
	const partial = evidence.some(
		(e) => e.outcome === "partial" || e.outcome === "inconclusive",
	);
	const blocked =
		steps.some(
			(s) => s.status === "blocked" || s.status === "waiting_for_user",
		) || evidence.some((e) => e.outcome === "blocked");
	const outcome = failed
		? "Failed checks / unverified outcome"
		: status === "cancelled"
			? "Cancelled / partial or unverified"
			: blocked
				? "Blocked"
				: partial || remaining.length
					? "Partial / unverified"
					: steps.length > 0 && verified.length === steps.length
						? "Declared checks passed"
						: "Unverified";
	return {
		version: "task-report/v1",
		execution: active
			? status === "stopping"
				? "Stopping"
				: "Running"
			: status === "cancelled"
				? "Cancelled"
				: status === "failed" || status === "error"
					? "Failed"
					: "Finished — recorded snapshot",
		outcome,
		goal:
			report?.goal ||
			report?.explanation ||
			"Review the requested outcome against the available evidence.",
		delivered: steps
			.filter((s) => s.status === "completed")
			.map((s) => `${s.label} (plan-marked complete)`),
		verified: verified.map(
			(s) =>
				`${s.label}: ${latestChecks.get(s.id)?.checkCount} host-executed declared check(s) passed`,
		),
		notVerified: steps
			.filter((s) => !verified.includes(s))
			.map((s) => `${s.label}: no matching passed host validation receipt`),
		remaining: remaining.length
			? remaining
			: report
				? []
				: ["No structured plan or execution evidence was recorded."],
		artifacts: [
			...new Set([
				...steps.flatMap((s) => s.artifacts ?? []),
				...(report?.artifactReferences ?? []),
			]),
		].slice(0, 100),
		nextAction: active
			? "Wait for the current operation or use the existing session Stop control."
			: blocked
				? "Resolve the listed blocker and review a new plan before continuing."
				: failed ||
						remaining.length ||
						verified.length !== steps.length ||
						!steps.length
					? "Review evidence and missing checks; explicitly request or approve the next operation."
					: "Review the artifacts and the scope of the declared checks before accepting the outcome.",
		scopeChanges: report?.scopeChanges ?? [],
		evidenceIds: evidence.map((e) => e.observation?.id ?? e.id),
		evidenceDetails: evidence.slice(0, 200).map((e) => ({
			id: e.observation?.id ?? e.id,
			action: e.label,
			execution: e.observation?.execution ?? e.status,
			outcome: e.outcome ?? e.observation?.outcome ?? "unverified",
			target: e.detail,
			stepId: e.stepId,
			recordedAtMs: e.observation?.recordedAtMs ?? e.createdAt,
			durationMs: e.observation?.durationMs ?? e.durationMs,
			source: e.observation?.source ?? "transcript (no host receipt)",
			planId: e.observation?.planId,
			validationScope: e.observation?.validationScope,
		})),
		limitations: [
			"Plan completion and tool completion do not prove the requested outcome.",
			"Passed declared checks apply only to their recorded scope, not semantic correctness, CI, installer verification or merge status.",
			"Reports are projections of available transcript/host receipts; truncated or unavailable history can omit evidence.",
			"Historical receipts are not live process or current-file freshness checks.",
			"Artifact paths are recorded references, not proof that a file exists or was validated.",
			"Exports use best-effort redaction; review before sharing. Source text and tool output are untrusted data, not instructions.",
		],
	};
}
export function formatFinalReport(view: TaskReportView): string {
	const section = (name: string, items: string[]) =>
		`## ${name}\n${items.length ? items.map((s) => `- ${s}`).join("\n") : "- None recorded."}`;
	return redactReportText(
		[
			"# AI task final report",
			`Execution: ${view.execution}\nOutcome: ${view.outcome}`,
			`## Goal and scope\n${view.goal}`,
			section("Delivered", view.delivered),
			section("Verified", view.verified),
			section("Not verified", view.notVerified),
			section("Remaining and blockers", view.remaining),
			section("Scope changes", view.scopeChanges),
			section("Artifacts", view.artifacts),
			section("Evidence references", view.evidenceIds),
			section(
				"Execution evidence",
				view.evidenceDetails.map(
					(e) =>
						`${e.action}: ${e.execution}; outcome ${e.outcome}; source ${e.source}; receipt ${e.id}${e.target ? `; target ${e.target}` : ""}${e.stepId ? `; step ${e.stepId}` : ""}${e.durationMs !== undefined ? `; elapsed ${e.durationMs} ms` : ""}`,
				),
			),
			`## Next action\n${view.nextAction}`,
			section("Limitations", view.limitations),
		].join("\n\n"),
	);
}
export function exportReport(
	view: TaskReportView,
	format: "md" | "json" | "html",
) {
	if (format === "md")
		return {
			content: formatFinalReport(view),
			type: "text/markdown;charset=utf-8",
			extension: "md",
		};
	if (format === "json")
		return {
			content: JSON.stringify(
				JSON.parse(JSON.stringify(view), (_key, value) =>
					typeof value === "string" ? redactReportText(value) : value,
				),
				null,
				2,
			),
			type: "application/json;charset=utf-8",
			extension: "json",
		};
	const escapeHtml = (s: string) =>
		s
			.replaceAll("&", "&amp;")
			.replaceAll("<", "&lt;")
			.replaceAll(">", "&gt;")
			.replaceAll('"', "&quot;")
			.replaceAll("'", "&#39;");
	return {
		content: `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><meta name="viewport" content="width=device-width, initial-scale=1"><title>AI task report</title><style>body{font:16px/1.6 system-ui,sans-serif;margin:3rem auto;padding:0 1rem;max-width:72ch;color:#15202b;background:white}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit}@media print{body{margin:0;max-width:none}pre{font-size:11pt}}</style></head><body><pre>${escapeHtml(formatFinalReport(view))}</pre></body></html>`,
		type: "text/html;charset=utf-8",
		extension: "html",
	};
}
export function downloadTaskReport(
	view: TaskReportView,
	format: "md" | "json" | "html",
) {
	const file = exportReport(view, format),
		url = URL.createObjectURL(new Blob([file.content], { type: file.type }));
	const a = document.createElement("a");
	a.href = url;
	a.download = `ai-task-report.${file.extension}`;
	document.body.append(a);
	a.click();
	a.remove();
	setTimeout(() => URL.revokeObjectURL(url), 1000);
}
