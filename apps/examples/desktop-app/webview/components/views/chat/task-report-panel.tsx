"use client";

import {
	AlertCircle,
	Ban,
	CheckCircle2,
	ChevronDown,
	Circle,
	Clock3,
	ListChecks,
	Loader2,
	SkipForward,
	Wrench,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { ChatSessionStatus } from "@/lib/chat-schema";
import type {
	SessionTaskReport,
	TaskReportStepStatus,
} from "@/lib/task-report";
import { cn } from "@/lib/utils";

function statusIcon(status: TaskReportStepStatus) {
	switch (status) {
		case "completed": return <CheckCircle2 className="size-4 text-emerald-500" />;
		case "in_progress": return <Loader2 className="size-4 animate-spin text-blue-500" />;
		case "blocked":
		case "failed": return <AlertCircle className="size-4 text-destructive" />;
		case "waiting_for_user": return <Clock3 className="size-4 text-amber-500" />;
		case "skipped": return <SkipForward className="size-4 text-muted-foreground" />;
		case "cancelled": return <Ban className="size-4 text-muted-foreground" />;
		case "pending": return <Circle className="size-4 text-muted-foreground/70" />;
	}
}

function sessionLabel(status: ChatSessionStatus | undefined, activeCount: number, completedCount: number, totalCount: number): string {
	if (status === "failed" || status === "error") return "Failed";
	if (status === "cancelled") return "Cancelled";
	if (status === "completed" || completedCount === totalCount) return "Complete";
	if (activeCount > 0) return "Executing";
	return "Planned";
}

export function TaskReportPanel({ report, status }: { report: SessionTaskReport; status?: ChatSessionStatus }) {
	const [expanded, setExpanded] = useState(true);
	useEffect(() => setExpanded(true), [report.sourceMessageId]);
	const completedCount = useMemo(() => report.steps.filter((step) => step.status === "completed").length, [report.steps]);
	const activeCount = report.steps.filter((step) => step.status === "in_progress").length;
	const progress = Math.round((completedCount / report.steps.length) * 100);
	const repairLabel = report.repair ? {
		repair_required: "Repair required",
		repairing: `Repairing · attempt ${report.repair.attempt}/${report.repair.maxAttempts}`,
		verifying: "Verifying repair",
		blocked: "Blocked after repair failure",
	}[report.repair.state] : null;

	return (
		<section aria-label="AI task report" className="sticky top-2 z-20 overflow-hidden rounded-xl border border-border/70 bg-background/95 shadow-sm backdrop-blur">
			<button aria-expanded={expanded} className="flex w-full items-center gap-3 px-3 py-2.5 text-left hover:bg-muted/40" onClick={() => setExpanded((current) => !current)} type="button">
				<ListChecks className="size-4 shrink-0 text-primary" />
				<div className="min-w-0 flex-1">
					<div className="flex items-center gap-2">
						<span className="text-sm font-medium">Task report</span>
						<span className="rounded-full bg-muted px-2 py-0.5 text-[11px] text-muted-foreground">{sessionLabel(status, activeCount, completedCount, report.steps.length)}</span>
					</div>
					<div className="mt-1 flex items-center gap-2">
						<div className="h-1.5 min-w-16 flex-1 overflow-hidden rounded-full bg-muted"><div className="h-full rounded-full bg-emerald-500 transition-[width]" style={{ width: `${progress}%` }} /></div>
						<span className="text-[11px] tabular-nums text-muted-foreground">{completedCount}/{report.steps.length}</span>
					</div>
				</div>
				<ChevronDown className={cn("size-4 shrink-0 text-muted-foreground transition-transform", !expanded && "-rotate-90")} />
			</button>
			{expanded ? (
				<div className="border-border/60 border-t px-3 py-3">
					{report.repair && repairLabel ? (
						<div className={cn("mb-3 rounded-lg border px-3 py-2", report.repair.state === "blocked" ? "border-destructive/40 bg-destructive/10" : "border-amber-500/30 bg-amber-500/10")}>
							<div className="flex items-center gap-2 text-xs font-medium">
								{report.repair.state === "repairing" ? <Loader2 className="size-3.5 animate-spin" /> : <Wrench className="size-3.5" />}
								{repairLabel}
							</div>
							<p className="mt-1 text-xs text-muted-foreground">Failed step: {report.repair.failedStepLabel}</p>
						</div>
					) : null}
					{report.explanation ? <p className="mb-3 text-xs text-muted-foreground">{report.explanation}</p> : null}
					<ol className="space-y-2">
						{report.steps.map((step) => (
							<li className={cn("flex min-w-0 items-start gap-2", step.isRepair && "ml-6 border-muted border-l pl-3")} key={step.id}>
								<span className="mt-0.5 shrink-0">{statusIcon(step.status)}</span>
								<span className={cn("min-w-0 text-sm leading-5", step.status === "completed" && "text-muted-foreground line-through decoration-muted-foreground/50", (step.status === "pending" || step.status === "skipped" || step.status === "cancelled") && "text-muted-foreground")}>{step.label}</span>
							</li>
						))}
					</ol>
				</div>
			) : null}
		</section>
	);
}
