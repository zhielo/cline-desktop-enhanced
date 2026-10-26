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
	const view = useMemo(() => taskReportView(report, status), [report, status]);
	const [error, setError] = useState("");
	// Anchor by receipt ID, not offset: new live receipts must not move an older page.
	const [anchor, setAnchor] = useState<string | null>(null);
	const evidence = report?.evidence ?? [];
	const anchorIndex =
		anchor === null ? 0 : evidence.findIndex((item) => item.id === anchor);
	const offset = Math.max(0, anchorIndex);
	const page = evidence.slice(offset, offset + 20);
	const copy = async () => {
		try {
			await navigator.clipboard.writeText(formatFinalReport(view));
			setError("Report copied (best-effort redacted).");
		} catch {
			setError("Could not copy. Use a report export instead.");
		}
	};
	const download = (
		format: "md" | "json" | "html",
		allAvailableEvidence = false,
	) => {
		try {
			downloadTaskReport(
				allAvailableEvidence
					? taskReportView(report, status, { allAvailableEvidence: true })
					: view,
				format,
			);
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
					Showing {evidence.length ? offset + 1 : 0}–{offset + page.length} of{" "}
					{evidence.length} available entries. Upstream history total unknown.
					Historical receipts do not check process liveness. Tool completion is
					not outcome verification.
					{anchorIndex < 0 &&
						" The previous page anchor is no longer available; showing latest evidence."}
				</p>
				<ol className="space-y-2">
					{page.map((item) => (
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
				<nav aria-label="Evidence pages" className="mt-3 flex flex-wrap gap-2">
					{offset > 0 && (
						<button
							type="button"
							className="min-h-11 rounded border p-2"
							onClick={() =>
								setAnchor(evidence[Math.max(0, offset - 20)]?.id ?? null)
							}
						>
							Newer evidence
						</button>
					)}
					{anchor !== null && (
						<button
							type="button"
							className="min-h-11 rounded border p-2"
							onClick={() => setAnchor(null)}
						>
							Latest evidence
						</button>
					)}
					{offset + 20 < evidence.length && (
						<button
							type="button"
							className="min-h-11 rounded border p-2"
							onClick={() => setAnchor(evidence[offset + 20].id)}
						>
							Older evidence
						</button>
					)}
				</nav>
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
			<p className="text-sm text-muted-foreground">
				Summary exports include {view.evidenceCoverage.included} of{" "}
				{view.evidenceCoverage.available} available evidence details. Use the
				full available-evidence export for older receipts; unavailable upstream
				history cannot be exported.
			</p>
			<div className="flex flex-wrap gap-2">
				<button
					type="button"
					className="min-h-11 rounded border px-3 py-2 text-sm"
					onClick={() => download("json", true)}
				>
					Export all available evidence (JSON)
				</button>
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
			{error && <output className="block text-[14px]">{error}</output>}
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
	const [anchor, setAnchor] = useState<string | null>(null);
	const turnKey = (report: SessionTaskReport) =>
		report.turnId ?? report.sourceMessageId;
	const offset = Math.max(
		0,
		anchor === null
			? 0
			: reports.findIndex((report) => turnKey(report) === anchor),
	);
	const page = reports.slice(offset, offset + 10);

	return (
		<section aria-label="Session reports" className="space-y-3 p-4">
			<h1 className="text-lg font-semibold">Reports</h1>
			<p className="text-[14px] text-muted-foreground">
				{reports.length} available turns; upstream history total unknown.
				Reading, copying and exporting reports never runs tools, grants approval
				or resumes work. Missing history is not success.
			</p>
			{reports.length ? (
				page.map((report, index) => (
					<ReportEntry
						key={turnKey(report)}
						report={report}
						status={offset === 0 && index === 0 ? status : "idle"}
						initiallyOpen={offset === 0 && index === 0}
					/>
				))
			) : (
				<TaskReportDetails status={status} />
			)}
			<nav aria-label="Report pages" className="flex flex-wrap gap-2">
				{offset > 0 && (
					<button
						type="button"
						className="min-h-11 rounded border p-2"
						onClick={() =>
							setAnchor(turnKey(reports[Math.max(0, offset - 10)]))
						}
					>
						Newer reports
					</button>
				)}
				{anchor !== null && (
					<button
						type="button"
						className="min-h-11 rounded border p-2"
						onClick={() => setAnchor(null)}
					>
						Latest reports
					</button>
				)}
				{offset + 10 < reports.length && (
					<button
						type="button"
						className="min-h-11 rounded border p-2"
						onClick={() => setAnchor(turnKey(reports[offset + 10]))}
					>
						Older reports
					</button>
				)}
			</nav>
		</section>
	);
}

function ReportEntry({
	report,
	status,
	initiallyOpen,
}: {
	report: SessionTaskReport;
	status: ChatSessionStatus;
	initiallyOpen: boolean;
}) {
	const [open, setOpen] = useState(initiallyOpen);
	return (
		<details
			open={open}
			onToggle={(event) => setOpen(event.currentTarget.open)}
		>
			<summary className="min-h-11 cursor-pointer rounded border p-2 text-sm">
				{redactReportText(
					report.goal?.slice(0, 100) ?? report.explanation ?? "Recorded task",
				)}{" "}
				· {new Date(report.updatedAt).toLocaleString()}
			</summary>
			{open && (
				<TaskReportDetails
					key={report.turnId ?? report.sourceMessageId}
					report={report}
					status={status}
				/>
			)}
		</details>
	);
}
