"use client";
import { useMemo, useState } from "react";
import {
	buildSessionTaskReports,
	type SessionTaskReport,
} from "@/lib/task-report";
import type { ChatMessage, ChatSessionStatus } from "@/lib/chat-schema";
import {
	downloadTaskReport,
	formatFinalReport,
	isTaskActive,
	taskReportView,
} from "@/lib/task-report-view";
import { redactReportText } from "../../../../shared/task-observation";

export function TaskReportDetails({
	report,
	status,
}: {
	report?: SessionTaskReport | null;
	status?: ChatSessionStatus;
}) {
	const view = taskReportView(report, status);
	const [error, setError] = useState("");
	const [limit, setLimit] = useState(12);
	const copy = async () => {
		try {
			await navigator.clipboard.writeText(formatFinalReport(view));
			setError("Report copied (best-effort redacted).");
		} catch {
			setError("Could not copy. Use a report export instead.");
		}
	};
	const download = (format: "md" | "json" | "html") => {
		try {
			downloadTaskReport(view, format);
			setError("Export prepared. Review redactions before sharing.");
		} catch {
			setError(
				"Report export unavailable in this environment. Use Copy summary.",
			);
		}
	};
	const sections: [string, string[]][] = [
		["Delivered", view.delivered],
		["Verified", view.verified],
		["Not verified", view.notVerified],
		["Remaining and blockers", view.remaining],
		["Scope changes", view.scopeChanges],
		["Artifacts", view.artifacts],
	];
	return (
		<section
			aria-label="Evidence-backed task report"
			className="space-y-5 rounded-xl border p-4 text-[14px] leading-6"
		>
			<header>
				<h2 className="font-semibold">
					{isTaskActive(status) ? "Live task report" : "Final task report"}
				</h2>
				<p>Execution: {view.execution}</p>
				<p>Outcome: {view.outcome}</p>
			</header>
			<section>
				<h3 className="font-medium">Goal and scope</h3>
				<p className="whitespace-pre-wrap break-words">
					{redactReportText(view.goal)}
				</p>
			</section>
			{sections.map(([title, items]) => (
				<section key={title}>
					<h3 className="font-medium">{title}</h3>
					<ul className="list-inside list-disc break-words text-sm">
						{items.length ? (
							items
								.slice(0, 50)
								.map((item, index) => (
									<li key={`${index}-${title}`}>{redactReportText(item)}</li>
								))
						) : (
							<li>None recorded.</li>
						)}
						{items.length > 50 && (
							<li>Additional entries are available in the exported report.</li>
						)}
					</ul>
				</section>
			))}
			<section aria-label="Task execution evidence">
				<h3 className="font-medium">Execution evidence</h3>
				<p className="text-[14px] text-muted-foreground">
					Most recent {Math.min(limit, report?.evidence.length ?? 0)} of{" "}
					{report?.evidence.length ?? 0} retained entries (up to 200 per turn).
					Historical receipts do not check process liveness. Tool completion is
					not outcome verification.
				</p>
				<ol className="space-y-2">
					{report?.evidence.slice(0, limit).map((item) => (
						<li
							key={item.id}
							className="rounded border p-2 text-[14px]"
							id={`task-evidence-${encodeURIComponent(item.id)}`}
						>
							<strong>{item.label}</strong>
							<p>
								{isTaskActive(status) && item.status === "running"
									? "Running"
									: item.status === "running"
										? "No terminal receipt recorded"
										: item.status === "completed"
											? "Tool finished"
											: item.status}{" "}
								· {item.outcome ?? "unverified"}
							</p>
							{item.detail && (
								<p className="break-words">
									Target / scope: {redactReportText(item.detail)}
								</p>
							)}
							{item.durationMs !== undefined && (
								<p>Recorded elapsed: {(item.durationMs / 1000).toFixed(1)}s</p>
							)}
							<details>
								<summary>Receipt details</summary>
								<p className="break-all">
									{redactReportText(item.observation?.id ?? item.id)}
								</p>
								<p>
									Source:{" "}
									{item.observation?.source ?? "transcript (no host receipt)"}
								</p>
								<p>Tool: {redactReportText(item.label)}</p>
								<p>Step: {item.stepId ?? "Unassigned"}</p>
								<p>
									Recorded:{" "}
									{new Date(
										item.observation?.recordedAtMs ?? item.createdAt,
									).toISOString()}
								</p>
							</details>
						</li>
					))}
				</ol>
				{(report?.evidence.length ?? 0) > limit && (
					<button
						type="button"
						className="min-h-11 rounded border p-2"
						onClick={() => setLimit((n) => Math.min(200, n + 20))}
					>
						Show more evidence
					</button>
				)}
			</section>
			<section>
				<h3 className="font-medium">Next action</h3>
				<p>{view.nextAction}</p>
			</section>
			<details>
				<summary>Limitations and sharing safety</summary>
				<ul className="list-inside list-disc text-[14px]">
					{view.limitations.map((s) => (
						<li key={s}>{s}</li>
					))}
				</ul>
			</details>
			<div className="flex flex-wrap gap-2">
				{[
					"Copy summary",
					"Export Markdown",
					"Export JSON",
					"Export print-ready HTML",
				].map((label, index) => (
					<button
						type="button"
						className="min-h-11 rounded border px-3 py-2 text-sm"
						key={label}
						onClick={() =>
							index === 0
								? void copy()
								: download((["md", "json", "html"] as const)[index - 1])
						}
					>
						{label}
					</button>
				))}
			</div>
			{error && <output className="block text-[14px]">
				{error}
			</output>}
		</section>
	);
}
export function ChatReports({
	messages,
	status,
}: {
	messages: ChatMessage[];
	status: ChatSessionStatus;
}) {
	const reports = useMemo(
		() => buildSessionTaskReports(messages, status),
		[messages, status],
	);
	return (
		<section aria-label="Session reports" className="space-y-3 p-4">
			<h1 className="text-lg font-semibold">Reports</h1>
			<p className="text-[14px] text-muted-foreground">
				Up to 50 turns from available session history. Reading, copying and
				exporting reports never runs tools, grants approval or resumes work.
				Missing history is not success.
			</p>
			{reports.length ? (
				reports.map((report, index) => (
					<details key={report.sourceMessageId} open={index === 0}>
						<summary className="cursor-pointer rounded border p-2 text-sm">
							{redactReportText(
								report.goal?.slice(0, 100) ??
									report.explanation ??
									"Recorded task",
							)}{" "}
							· {new Date(report.updatedAt).toLocaleString()}
						</summary>
						<TaskReportDetails
							report={report}
							status={index === 0 ? status : "idle"}
						/>
					</details>
				))
			) : (
				<TaskReportDetails status={status} />
			)}
		</section>
	);
}
