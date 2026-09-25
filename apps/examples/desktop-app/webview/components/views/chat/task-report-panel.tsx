"use client";

import {
	AlertCircle,
	Ban,
	Check,
	CheckCircle2,
	ChevronDown,
	Circle,
	Clock3,
	FileCheck2,
	ListChecks,
	Loader2,
	SkipForward,
	Sparkles,
	Wrench,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { ChatSessionStatus } from "@/lib/chat-schema";
import type {
	SessionTaskReport,
	TaskEvidenceStatus,
	TaskReportStep,
	TaskReportStepStatus,
} from "@/lib/task-report";
import { cn } from "@/lib/utils";

function statusIcon(status: TaskReportStepStatus) {
	switch (status) {
		case "completed":
			return <Check className="size-3.5" strokeWidth={2.5} />;
		case "in_progress":
			return <Loader2 className="size-3.5 animate-spin" />;
		case "blocked":
		case "failed":
			return <AlertCircle className="size-3.5" />;
		case "waiting_for_user":
			return <Clock3 className="size-3.5" />;
		case "skipped":
			return <SkipForward className="size-3.5" />;
		case "cancelled":
			return <Ban className="size-3.5" />;
		case "pending":
			return <Circle className="size-3" />;
	}
}

function evidenceIcon(status: TaskEvidenceStatus) {
	switch (status) {
		case "running":
			return <Loader2 className="size-3.5 animate-spin text-blue-500" />;
		case "failed":
			return <AlertCircle className="size-3.5 text-destructive" />;
		case "completed":
			return <CheckCircle2 className="size-3.5 text-emerald-500" />;
	}
}

function reportState(report: SessionTaskReport, status?: ChatSessionStatus) {
	if (status === "failed" || status === "error") {
		return { label: "Failed", tone: "destructive" as const };
	}
	if (status === "cancelled") {
		return { label: "Cancelled", tone: "muted" as const };
	}
	if (report.repair?.state === "blocked") {
		return { label: "Blocked", tone: "destructive" as const };
	}
	if (report.repair?.state === "repairing") {
		return { label: "Repairing", tone: "warning" as const };
	}
	if (report.repair?.state === "verifying") {
		return { label: "Verifying", tone: "warning" as const };
	}
	if (
		report.mode === "plan" &&
		report.steps.length > 0 &&
		report.completedCount === report.steps.length
	) {
		return { label: "Complete", tone: "success" as const };
	}
	if (
		status === "running" ||
		status === "starting" ||
		report.steps.some((step) => step.status === "in_progress") ||
		report.evidence.some((item) => item.status === "running")
	) {
		return { label: "Executing", tone: "active" as const };
	}
	if (report.mode === "activity") {
		return { label: "Activity", tone: "muted" as const };
	}
	return { label: "Planned", tone: "muted" as const };
}

function stepTone(step: TaskReportStep) {
	if (step.status === "completed") {
		return "border-emerald-500/70 bg-emerald-500 text-white";
	}
	if (step.status === "in_progress") {
		return "border-blue-500/70 bg-blue-500 text-white shadow-[0_0_0_4px_rgba(59,130,246,0.12)]";
	}
	if (step.status === "failed" || step.status === "blocked") {
		return "border-destructive/70 bg-destructive text-destructive-foreground";
	}
	if (step.status === "waiting_for_user") {
		return "border-amber-500/70 bg-amber-500 text-white";
	}
	return "border-border bg-background text-muted-foreground";
}

function stepStatusLabel(status: TaskReportStepStatus) {
	return {
		pending: "Pending",
		in_progress: "In progress",
		blocked: "Blocked",
		waiting_for_user: "Needs input",
		completed: "Completed",
		failed: "Failed",
		skipped: "Skipped",
		cancelled: "Cancelled",
	}[status];
}

export function TaskReportPanel({
	report,
	status,
}: {
	report: SessionTaskReport;
	status?: ChatSessionStatus;
}) {
	const complete =
		report.mode === "plan" &&
		report.steps.length > 0 &&
		report.completedCount === report.steps.length;
	const [expanded, setExpanded] = useState(!complete);
	useEffect(() => {
		setExpanded(!complete);
	}, [complete, report.sourceMessageId]);

	const activeStep = useMemo(
		() =>
			report.steps.find((step) => step.id === report.activeStepId) ??
			report.steps.find((step) => step.status === "in_progress"),
		[report.activeStepId, report.steps],
	);
	const state = reportState(report, status);
	const latestActivity =
		report.evidence.find((item) => item.status === "running") ??
		report.evidence[0];
	const evidenceByStep = useMemo(() => {
		const grouped = new Map<string, typeof report.evidence>();
		for (const item of report.evidence) {
			if (!item.stepId) continue;
			const items = grouped.get(item.stepId) ?? [];
			items.push(item);
			grouped.set(item.stepId, items);
		}
		return grouped;
	}, [report.evidence]);
	const unassignedEvidence = useMemo(
		() => report.evidence.filter((item) => !item.stepId),
		[report.evidence],
	);
	const headline =
		activeStep?.label ??
		latestActivity?.label ??
		(complete ? "All planned steps completed" : report.explanation);
	const repairLabel = report.repair
		? {
				repair_required: "Repair required before continuing",
				repairing: `Repairing · attempt ${report.repair.attempt}/${report.repair.maxAttempts}`,
				verifying: "Verifying the repair",
				blocked: "Blocked after a failed step",
			}[report.repair.state]
		: null;

	return (
		<section
			aria-label="AI task report"
			className={cn(
				"sticky top-2 z-20 overflow-hidden rounded-2xl border bg-background/95 shadow-[0_14px_38px_-24px_rgba(15,23,42,0.55)] backdrop-blur-xl",
				state.tone === "active" && "border-blue-500/30",
				state.tone === "success" && "border-emerald-500/30",
				state.tone === "warning" && "border-amber-500/35",
				state.tone === "destructive" && "border-destructive/40",
				state.tone === "muted" && "border-border/70",
			)}
		>
			<button
				aria-expanded={expanded}
				className="group flex w-full items-center gap-3 px-3.5 py-3 text-left transition-colors hover:bg-muted/35 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-inset"
				onClick={() => setExpanded((current) => !current)}
				type="button"
			>
				<div
					className={cn(
						"grid size-9 shrink-0 place-items-center rounded-xl border",
						state.tone === "active" &&
							"border-blue-500/25 bg-blue-500/10 text-blue-500",
						state.tone === "success" &&
							"border-emerald-500/25 bg-emerald-500/10 text-emerald-500",
						state.tone === "warning" &&
							"border-amber-500/25 bg-amber-500/10 text-amber-500",
						state.tone === "destructive" &&
							"border-destructive/25 bg-destructive/10 text-destructive",
						state.tone === "muted" &&
							"border-border bg-muted/50 text-muted-foreground",
					)}
				>
					{state.tone === "active" ? (
						<Sparkles className="size-4" />
					) : (
						<ListChecks className="size-4" />
					)}
				</div>
				<div className="min-w-0 flex-1">
					<div className="flex min-w-0 items-center gap-2">
						<span className="truncate text-sm font-semibold tracking-tight">
							{report.mode === "plan" ? "AI task report" : "Live task activity"}
						</span>
						<span
							className={cn(
								"shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
								state.tone === "active" &&
									"border-blue-500/25 bg-blue-500/10 text-blue-600 dark:text-blue-400",
								state.tone === "success" &&
									"border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
								state.tone === "warning" &&
									"border-amber-500/25 bg-amber-500/10 text-amber-700 dark:text-amber-400",
								state.tone === "destructive" &&
									"border-destructive/25 bg-destructive/10 text-destructive",
								state.tone === "muted" &&
									"border-border bg-muted/60 text-muted-foreground",
							)}
						>
							{state.label}
						</span>
					</div>
					{headline ? (
						<p className="mt-0.5 truncate text-xs text-muted-foreground">
							{headline}
						</p>
					) : null}
					{report.mode === "plan" && report.progressPercent !== null ? (
						<div className="mt-2 flex items-center gap-2">
							<div
								aria-label={`${report.completedCount} of ${report.steps.length} steps completed`}
								aria-valuemax={report.steps.length}
								aria-valuemin={0}
								aria-valuenow={report.completedCount}
								className="h-1.5 min-w-16 flex-1 overflow-hidden rounded-full bg-muted"
								role="progressbar"
							>
								<div
									className="h-full rounded-full bg-gradient-to-r from-blue-500 to-emerald-500 transition-[width] duration-500 ease-out"
									style={{ width: `${report.progressPercent}%` }}
								/>
							</div>
							<span className="shrink-0 text-[11px] tabular-nums text-muted-foreground">
								{report.completedCount} of {report.steps.length}
							</span>
						</div>
					) : null}
				</div>
				<ChevronDown
					className={cn(
						"size-4 shrink-0 text-muted-foreground transition-transform duration-200 group-hover:text-foreground",
						!expanded && "-rotate-90",
					)}
				/>
			</button>

			{expanded ? (
				<div className="border-border/60 border-t">
					<div className="max-h-[min(56vh,32rem)] overflow-y-auto px-3.5 py-3.5">
						{activeStep ? (
							<div className="mb-3 rounded-xl border border-blue-500/20 bg-gradient-to-br from-blue-500/10 to-transparent px-3 py-2.5">
								<div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-blue-600 dark:text-blue-400">
									<span className="relative flex size-2">
										<span className="absolute inline-flex size-full animate-ping rounded-full bg-blue-500 opacity-60" />
										<span className="relative inline-flex size-2 rounded-full bg-blue-500" />
									</span>
									Working now
								</div>
								<p className="mt-1.5 text-sm font-medium leading-5">
									{activeStep.label}
								</p>
								{latestActivity?.detail ? (
									<p className="mt-1 truncate font-mono text-[11px] text-muted-foreground">
										{latestActivity.detail}
									</p>
								) : null}
							</div>
						) : null}

						{report.repair && repairLabel ? (
							<div
								className={cn(
									"mb-3 rounded-xl border px-3 py-2.5",
									report.repair.state === "blocked"
										? "border-destructive/35 bg-destructive/10"
										: "border-amber-500/30 bg-amber-500/10",
								)}
							>
								<div className="flex items-center gap-2 text-xs font-semibold">
									{report.repair.state === "repairing" ||
									report.repair.state === "verifying" ? (
										<Loader2 className="size-3.5 animate-spin" />
									) : (
										<Wrench className="size-3.5" />
									)}
									{repairLabel}
								</div>
								<p className="mt-1 text-xs text-muted-foreground">
									Failed step: {report.repair.failedStepLabel}
								</p>
							</div>
						) : null}

						{report.explanation ? (
							<p className="mb-3 text-xs leading-5 text-muted-foreground">
								{report.explanation}
							</p>
						) : null}

						{report.steps.length > 0 ? (
							<ol aria-label="Task steps" className="relative space-y-0.5">
								{report.steps.map((step, index) => (
									<li
										className={cn(
											"group/step relative flex min-w-0 gap-3 rounded-xl px-1.5 py-2",
											step.status === "in_progress" && "bg-blue-500/5",
											step.kind !== "work" && "ml-5",
										)}
										key={step.id}
									>
										{index < report.steps.length - 1 ? (
											<span className="absolute left-[15px] top-7 h-[calc(100%-14px)] w-px bg-border" />
										) : null}
										<span
											aria-label={stepStatusLabel(step.status)}
											className={cn(
												"relative z-10 mt-0.5 grid size-5 shrink-0 place-items-center rounded-full border",
												stepTone(step),
											)}
										>
											{statusIcon(step.status)}
										</span>
										<div className="min-w-0 flex-1">
											<p
												className={cn(
													"text-sm leading-5",
													step.status === "in_progress" && "font-medium",
													step.status === "completed" &&
														"text-muted-foreground line-through decoration-muted-foreground/40",
													(step.status === "pending" ||
														step.status === "skipped" ||
														step.status === "cancelled") &&
														"text-muted-foreground",
												)}
											>
												{step.label}
											</p>
											{step.kind !== "work" ? (
												<span className="mt-0.5 inline-block text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
													{step.kind}
												</span>
											) : null}
											{(evidenceByStep.get(step.id) ?? []).length > 0 ? (
												<ul className="mt-1.5 space-y-1">
													{(evidenceByStep.get(step.id) ?? [])
														.slice(0, 2)
														.map((item) => (
															<li
																className="flex min-w-0 items-center gap-1.5 text-[10px] text-muted-foreground"
																key={item.id}
															>
																{evidenceIcon(item.status)}
																<span className="truncate">{item.label}</span>
																{typeof item.durationMs === "number" ? (
																	<span className="shrink-0 tabular-nums">
																		{(item.durationMs / 1000).toFixed(1)}s
																	</span>
																) : null}
															</li>
														))}
												</ul>
											) : null}
										</div>
									</li>
								))}
							</ol>
						) : null}

						{unassignedEvidence.length > 0 ? (
							<div
								className={cn(
									"mt-3",
									report.steps.length > 0 && "border-border/60 border-t pt-3",
								)}
							>
								<div className="mb-2 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
									<FileCheck2 className="size-3.5" />
									Execution evidence
								</div>
								<ul className="space-y-1.5">
									{unassignedEvidence.map((item) => (
										<li
											className="flex min-w-0 items-start gap-2 rounded-lg bg-muted/35 px-2.5 py-2"
											key={item.id}
										>
											<span className="mt-0.5 shrink-0">
												{evidenceIcon(item.status)}
											</span>
											<div className="min-w-0 flex-1">
												<p className="truncate text-xs font-medium">
													{item.label}
												</p>
												{item.detail ? (
													<p className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground">
														{item.detail}
													</p>
												) : null}
											</div>
										</li>
									))}
								</ul>
							</div>
						) : null}
					</div>
				</div>
			) : null}
		</section>
	);
}
