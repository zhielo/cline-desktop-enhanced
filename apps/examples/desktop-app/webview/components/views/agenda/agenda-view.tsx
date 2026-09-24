"use client";

import type { AgendaTaskRecord } from "@cline/shared";
import { Switch } from "@cline/ui";
import {
	CalendarClock,
	CheckCircle2,
	CircleAlert,
	Clock3,
	Loader2,
	Play,
	RefreshCw,
	ShieldCheck,
	XCircle,
} from "lucide-react";
import { useMemo, useState } from "react";
import { AgendaTaskReviewDialog } from "@/components/agenda-task-review-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useAgendaAutomation, useAgendaTasks } from "@/hooks/use-agenda-tasks";
import { toast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

const ACTIVE_STATUSES = new Set([
	"pending_approval",
	"approved",
	"in_progress",
	"failed",
]);

export function AgendaView({
	onOpenSession,
}: {
	onOpenSession: (sessionId: string) => void | Promise<void>;
}) {
	const agenda = useAgendaTasks({ includeArchived: false, limit: 100 });
	const automation = useAgendaAutomation();
	const [reviewTask, setReviewTask] = useState<AgendaTaskRecord | null>(null);
	const [showCompleted, setShowCompleted] = useState(false);
	const visibleTasks = useMemo(
		() =>
			agenda.tasks.filter(
				(task) => showCompleted || ACTIVE_STATUSES.has(task.status),
			),
		[agenda.tasks, showCompleted],
	);
	const automatic =
		automation.policy?.mode === "auto_start" ||
		automation.policy?.mode === "unattended";

	const run = async (task: AgendaTaskRecord) => {
		try {
			let current = task;
			if (current.status === "pending_approval")
				current = await agenda.approveTask(current);
			if (current.status === "approved" || current.status === "failed")
				current = await agenda.runTask(current);
			setReviewTask(null);
			if (current.lastSessionId) await onOpenSession(current.lastSessionId);
		} catch (error) {
			toast({
				title: "Unable to start task",
				description: error instanceof Error ? error.message : String(error),
				variant: "destructive",
			});
		}
	};

	return (
		<div className="flex h-full min-h-0 flex-col overflow-hidden bg-background text-foreground">
			<header className="flex shrink-0 flex-wrap items-end justify-between gap-5 border-b px-10 py-8 max-md:px-5">
				<div>
					<div className="flex items-center gap-3">
						<CalendarClock className="size-6" />
						<h1 className="text-3xl font-semibold">Agenda</h1>
					</div>
					<p className="mt-2 text-sm text-muted-foreground">
						Review, approve, run, and audit queued AI work.
					</p>
				</div>
				<div className="flex items-center gap-3">
					<label className="flex items-center gap-2 rounded-md border px-3 py-2 text-sm">
						<ShieldCheck className="size-4" />
						<span>Auto-start approved work</span>
						<Switch
							checked={automatic}
							disabled={automation.isLoading || automation.isUpdating}
							onCheckedChange={(checked) =>
								void automation.setAutomatic(checked)
							}
						/>
					</label>
					<Button
						aria-label="Refresh Agenda"
						disabled={agenda.isLoading}
						onClick={() => void agenda.refresh()}
						size="icon"
						type="button"
						variant="outline"
					>
						<RefreshCw
							className={cn("size-4", agenda.isLoading && "animate-spin")}
						/>
					</Button>
				</div>
			</header>

			<div className="flex items-center justify-between border-b px-10 py-3 text-sm max-md:px-5">
				<span className="text-muted-foreground">
					{visibleTasks.length} visible task
					{visibleTasks.length === 1 ? "" : "s"}
				</span>
				<label className="flex items-center gap-2">
					<Switch checked={showCompleted} onCheckedChange={setShowCompleted} />
					<span>Show completed</span>
				</label>
			</div>

			<div className="min-h-0 flex-1 overflow-auto p-10 max-md:p-5">
				{agenda.error || automation.error ? (
					<div
						className="mb-4 flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
						role="alert"
					>
						<CircleAlert className="size-4" />
						{agenda.error ?? automation.error}
					</div>
				) : null}
				{agenda.isLoading && agenda.tasks.length === 0 ? (
					<div className="flex items-center gap-2 text-sm text-muted-foreground">
						<Loader2 className="size-4 animate-spin" />
						Loading Agenda…
					</div>
				) : null}
				{!agenda.isLoading && visibleTasks.length === 0 ? (
					<div className="rounded-lg border border-dashed p-12 text-center">
						<CheckCircle2 className="mx-auto size-8 text-muted-foreground" />
						<h2 className="mt-3 font-medium">Agenda is clear</h2>
						<p className="mt-1 text-sm text-muted-foreground">
							Agent-created tasks that need review or execution will appear
							here.
						</p>
					</div>
				) : null}
				<div className="grid gap-3 xl:grid-cols-2">
					{visibleTasks.map((task) => {
						const pending = agenda.pendingTaskIds.has(task.taskId);
						return (
							<article
								className="rounded-lg border bg-card p-4 shadow-sm"
								key={task.taskId}
							>
								<div className="flex items-start justify-between gap-3">
									<div className="min-w-0">
										<div className="flex flex-wrap items-center gap-2">
											<TaskStatus status={task.status} />
											<Badge variant="outline">P{task.priority}</Badge>
											<Badge variant="secondary">{task.type}</Badge>
										</div>
										<h2
											className="mt-3 truncate font-semibold"
											title={task.title}
										>
											{task.title}
										</h2>
									</div>
									<span className="shrink-0 text-xs text-muted-foreground">
										rev {task.revision}
									</span>
								</div>
								<p className="mt-2 line-clamp-3 text-sm leading-5 text-muted-foreground">
									{task.description || task.instructions}
								</p>
								<div className="mt-3 grid grid-cols-2 gap-2 text-xs text-muted-foreground">
									<span>
										Mode:{" "}
										{task.mode === "yolo"
											? "Full Access"
											: (task.mode ?? "act")}
									</span>
									<span>
										Model:{" "}
										{task.modelSelection
											? `${task.modelSelection.providerId}/${task.modelSelection.modelId ?? "default"}`
											: "default"}
									</span>
									<span
										className="col-span-2 truncate"
										title={task.cwd ?? task.workspaceRoot ?? task.scope}
									>
										Scope: {task.cwd ?? task.workspaceRoot ?? task.scope}
									</span>
								</div>
								{task.error ? (
									<p className="mt-3 rounded-md bg-destructive/10 p-2 text-xs text-destructive">
										{task.error}
									</p>
								) : null}
								<div className="mt-4 flex flex-wrap justify-end gap-2">
									{task.lastSessionId ? (
										<Button
											onClick={() =>
												void onOpenSession(task.lastSessionId as string)
											}
											size="sm"
											type="button"
											variant="outline"
										>
											Open report
										</Button>
									) : null}
									{task.status === "pending_approval" ? (
										<Button
											disabled={pending}
											onClick={() => setReviewTask(task)}
											size="sm"
											type="button"
										>
											Review
										</Button>
									) : null}
									{task.status === "approved" || task.status === "failed" ? (
										<Button
											disabled={pending}
											onClick={() => void run(task)}
											size="sm"
											type="button"
										>
											<Play className="size-4" />
											{task.status === "failed" ? "Retry" : "Run"}
										</Button>
									) : null}
									{task.status === "pending_approval" ||
									task.status === "approved" ? (
										<Button
											disabled={pending}
											onClick={() => void agenda.cancelTask(task)}
											size="sm"
											type="button"
											variant="outline"
										>
											<XCircle className="size-4" />
											Cancel
										</Button>
									) : null}
								</div>
							</article>
						);
					})}
				</div>
			</div>

			<AgendaTaskReviewDialog
				confirmLabel="Approve and start"
				onConfirm={run}
				onOpenChange={(open) => {
					if (!open) setReviewTask(null);
				}}
				open={reviewTask !== null}
				pending={
					reviewTask ? agenda.pendingTaskIds.has(reviewTask.taskId) : false
				}
				task={reviewTask}
			/>
		</div>
	);
}

function TaskStatus({ status }: { status: AgendaTaskRecord["status"] }) {
	const icon =
		status === "in_progress" ? (
			<Loader2 className="size-3.5 animate-spin" />
		) : status === "completed" ? (
			<CheckCircle2 className="size-3.5" />
		) : status === "failed" ||
			status === "cancelled" ||
			status === "expired" ? (
			<XCircle className="size-3.5" />
		) : (
			<Clock3 className="size-3.5" />
		);
	return (
		<Badge
			className="gap-1 capitalize"
			variant={
				status === "failed"
					? "destructive"
					: status === "completed"
						? "default"
						: "secondary"
			}
		>
			{icon}
			{status.replaceAll("_", " ")}
		</Badge>
	);
}
