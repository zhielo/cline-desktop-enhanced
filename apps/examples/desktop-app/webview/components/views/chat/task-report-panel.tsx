"use client";

import type { TaskExecutionStepStatus } from "@cline/shared";
import {
	Activity,
	Ban,
	CheckCircle2,
	ChevronDown,
	ChevronRight,
	Circle,
	Clock3,
	FileCode2,
	ListChecks,
	Loader2,
	Pause,
	ShieldAlert,
	TestTube2,
	X,
	XCircle,
} from "lucide-react";
import { useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { ChatMessage, ChatSessionStatus } from "@/lib/chat-schema";
import type { SessionFileDiff } from "@/lib/session-diff";
import {
	buildTaskExecutionReport,
	reportProgress,
	type TaskReportSummary,
} from "@/lib/task-report";
import { cn } from "@/lib/utils";

export function TaskReportPanel({
	sessionId,
	status,
	messages,
	fileDiffs,
	summary,
	provider,
	model,
	mode,
	queuedInstructions,
	onStop,
}: {
	sessionId?: string | null;
	status: ChatSessionStatus;
	messages: ChatMessage[];
	fileDiffs: SessionFileDiff[];
	summary: TaskReportSummary;
	provider: string;
	model: string;
	mode: "act" | "plan" | "yolo";
	queuedInstructions: string[];
	onStop: () => void | Promise<void>;
}) {
	const [open, setOpen] = useState(false);
	const [expandedSteps, setExpandedSteps] = useState<Set<string>>(
		() => new Set(),
	);
	const report = useMemo(
		() =>
			buildTaskExecutionReport({
				sessionId,
				status,
				messages,
				fileDiffs,
				queuedInstructions,
			}),
		[sessionId, status, messages, fileDiffs, queuedInstructions],
	);
	const progress = reportProgress(report);
	const isBusy =
		status === "starting" || status === "running" || status === "stopping";
	const toggleStep = (stepId: string) => {
		setExpandedSteps((current) => {
			const next = new Set(current);
			if (next.has(stepId)) next.delete(stepId);
			else next.add(stepId);
			return next;
		});
	};

	if (!open) {
		return (
			<Button
				aria-label="Show task report"
				className="absolute right-3 top-3 z-30 gap-2 shadow-sm"
				onClick={() => setOpen(true)}
				size="sm"
				title="Task report"
				type="button"
				variant="outline"
			>
				<ListChecks className="size-4" />
				<span className="hidden lg:inline">Task report</span>
				{isBusy ? (
					<span className="size-2 rounded-full bg-blue-500 animate-pulse" />
				) : null}
			</Button>
		);
	}

	return (
		<aside className="relative z-20 flex h-full w-[min(24rem,42vw)] min-w-80 shrink-0 flex-col border-l bg-card text-card-foreground max-md:absolute max-md:inset-y-0 max-md:right-0 max-md:w-[min(24rem,calc(100vw-2rem))] max-md:shadow-2xl">
			<header className="shrink-0 border-b p-4">
				<div className="flex items-start justify-between gap-3">
					<div className="min-w-0">
						<div className="flex items-center gap-2">
							<ListChecks className="size-4" />
							<h2 className="font-semibold">Task report</h2>
							<StatusBadge status={report.status} />
						</div>
						<p
							className="mt-2 line-clamp-3 text-xs leading-5 text-muted-foreground"
							title={report.objective}
						>
							{report.objective}
						</p>
					</div>
					<Button
						aria-label="Close task report"
						className="size-8 shrink-0"
						onClick={() => setOpen(false)}
						size="icon"
						type="button"
						variant="ghost"
					>
						<X className="size-4" />
					</Button>
				</div>
				<div className="mt-4 flex items-center gap-3">
					<Progress
						aria-label={`${progress.percent}% complete`}
						className="h-2 flex-1"
						value={progress.percent}
					/>
					<span className="text-xs tabular-nums text-muted-foreground">
						{progress.completed}/{progress.total}
					</span>
				</div>
				<div className="mt-3 flex flex-wrap gap-1.5 text-[11px] text-muted-foreground">
					<Badge variant="secondary">
						{provider}:{model}
					</Badge>
					<Badge variant={mode === "yolo" ? "destructive" : "outline"}>
						{mode === "yolo" ? "Full Access" : mode}
					</Badge>
					<Badge variant="outline">{summary.toolCalls} tools</Badge>
					<Badge variant="outline">
						{summary.tokensIn + summary.tokensOut} tokens
					</Badge>
				</div>
				{mode === "yolo" ? (
					<div className="mt-3 flex gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-2 text-[11px] leading-4 text-amber-700 dark:text-amber-300">
						<ShieldAlert className="mt-0.5 size-3.5 shrink-0" />
						Full Access auto-approves tools. Review commands, network activity,
						and changed files below.
					</div>
				) : null}
			</header>

			<ScrollArea className="min-h-0 flex-1">
				<div className="space-y-5 p-4">
					<section>
						<h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
							Plan
						</h3>
						<div className="space-y-1.5">
							{report.steps.map((step) => {
								const expanded = expandedSteps.has(step.stepId);
								return (
									<div
										className="rounded-md border bg-background/60"
										key={step.stepId}
									>
										<button
											className="flex w-full items-center gap-2 px-3 py-2 text-left"
											onClick={() => toggleStep(step.stepId)}
											type="button"
										>
											<StepIcon status={step.status} />
											<span className="min-w-0 flex-1 truncate text-sm">
												{step.title}
											</span>
											{step.evidence.length > 0 ? (
												<span className="text-[10px] text-muted-foreground">
													{step.evidence.length}
												</span>
											) : null}
											{expanded ? (
												<ChevronDown className="size-3.5" />
											) : (
												<ChevronRight className="size-3.5" />
											)}
										</button>
										{expanded ? (
											<div className="space-y-2 border-t px-3 py-2">
												{step.evidence.length === 0 ? (
													<p className="text-xs text-muted-foreground">
														No execution evidence recorded yet.
													</p>
												) : (
													step.evidence.map((item) => (
														<EvidenceRow item={item} key={item.evidenceId} />
													))
												)}
											</div>
										) : null}
									</div>
								);
							})}
						</div>
					</section>

					{report.queuedInstructions.length > 0 ? (
						<section>
							<h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
								Queued instructions
							</h3>
							<ul className="space-y-2">
								{report.queuedInstructions.map((instruction, index) => (
									<li
										className="rounded-md border bg-background/60 p-2 text-xs"
										key={`${index}-${instruction}`}
									>
										{instruction}
									</li>
								))}
							</ul>
						</section>
					) : null}

					<section>
						<h3 className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
							<Activity className="size-3.5" />
							Activity
						</h3>
						{report.evidence.length === 0 ? (
							<p className="text-xs text-muted-foreground">
								Tool activity will appear here as the agent works.
							</p>
						) : (
							<div className="space-y-2">
								{report.evidence
									.slice()
									.reverse()
									.slice(0, 30)
									.map((item) => (
										<EvidenceRow item={item} key={item.evidenceId} />
									))}
							</div>
						)}
					</section>

					<section>
						<h3 className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
							<FileCode2 className="size-3.5" />
							Changed files
						</h3>
						{report.changedFiles.length === 0 ? (
							<p className="text-xs text-muted-foreground">
								No file changes recorded.
							</p>
						) : (
							<div className="space-y-1.5">
								{report.changedFiles.map((file) => (
									<div
										className="flex items-center gap-2 rounded-md border bg-background/60 px-2 py-1.5 text-xs"
										key={file.path}
									>
										<span
											className="min-w-0 flex-1 truncate font-mono"
											title={file.path}
										>
											{file.path}
										</span>
										<span className="text-green-600">+{file.additions}</span>
										<span className="text-red-600">-{file.deletions}</span>
									</div>
								))}
							</div>
						)}
					</section>

					{report.summary ? (
						<section>
							<h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
								Latest report
							</h3>
							<p className="max-h-40 overflow-hidden whitespace-pre-wrap rounded-md border bg-background/60 p-3 text-xs leading-5">
								{report.summary}
							</p>
						</section>
					) : null}
				</div>
			</ScrollArea>

			<footer className="flex shrink-0 items-center justify-between gap-2 border-t p-3">
				<div className="text-[11px] text-muted-foreground">
					{summary.additions ?? 0} additions · {summary.deletions ?? 0}{" "}
					deletions
				</div>
				{isBusy ? (
					<Button
						disabled={status === "stopping"}
						onClick={() => void onStop()}
						size="sm"
						type="button"
						variant="destructive"
					>
						{status === "stopping" ? (
							<Loader2 className="size-4 animate-spin" />
						) : (
							<Pause className="size-4" />
						)}
						{status === "stopping" ? "Stopping" : "Stop"}
					</Button>
				) : null}
			</footer>
		</aside>
	);
}

function StatusBadge({ status }: { status: string }) {
	const destructive = status === "failed" || status === "cancelled";
	return (
		<Badge
			className="capitalize"
			variant={
				destructive
					? "destructive"
					: status === "completed"
						? "default"
						: "secondary"
			}
		>
			{status.replaceAll("_", " ")}
		</Badge>
	);
}

function StepIcon({ status }: { status: TaskExecutionStepStatus }) {
	const classes = "size-4 shrink-0";
	if (status === "passed")
		return <CheckCircle2 className={cn(classes, "text-green-600")} />;
	if (status === "failed")
		return <XCircle className={cn(classes, "text-destructive")} />;
	if (status === "running")
		return <Loader2 className={cn(classes, "animate-spin text-blue-500")} />;
	if (status === "blocked")
		return <Ban className={cn(classes, "text-amber-500")} />;
	if (status === "skipped")
		return <Clock3 className={cn(classes, "text-muted-foreground")} />;
	return <Circle className={cn(classes, "text-muted-foreground")} />;
}

function EvidenceRow({
	item,
}: {
	item: {
		label: string;
		status?: string;
		timestamp: string;
		summary?: string;
		type: string;
	};
}) {
	return (
		<div className="flex items-start gap-2 text-xs">
			{item.type === "test" ? (
				<TestTube2 className="mt-0.5 size-3.5 shrink-0" />
			) : (
				<Activity className="mt-0.5 size-3.5 shrink-0" />
			)}
			<div className="min-w-0 flex-1">
				<div className="flex items-center gap-2">
					<span className="truncate font-medium" title={item.label}>
						{item.label}
					</span>
					<span
						className={cn(
							"size-1.5 rounded-full",
							item.status === "failure"
								? "bg-destructive"
								: item.status === "running"
									? "bg-blue-500 animate-pulse"
									: "bg-green-500",
						)}
					/>
				</div>
				{item.summary ? (
					<p className="mt-0.5 line-clamp-2 break-all text-[11px] leading-4 text-muted-foreground">
						{item.summary}
					</p>
				) : null}
			</div>
			<time className="shrink-0 text-[10px] tabular-nums text-muted-foreground">
				{new Date(item.timestamp).toLocaleTimeString([], {
					hour: "2-digit",
					minute: "2-digit",
				})}
			</time>
		</div>
	);
}
