"use client";

import type { TaskExecutionStepStatus } from "@cline/shared";
import {
	Activity,
	Ban,
	BookOpen,
	CheckCircle2,
	ChevronDown,
	ChevronRight,
	Circle,
	Clock3,
	FileCode2,
	ListChecks,
	Loader2,
	Pause,
	Plug,
	ShieldAlert,
	TestTube2,
	Wrench,
	X,
	XCircle,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Textarea } from "@/components/ui/textarea";
import type { ChatMessage, ChatSessionStatus } from "@/lib/chat-schema";
import { desktopClient } from "@/lib/desktop-client";
import {
	buildEffectiveInstructionSources,
	type EffectiveInstructionInventory,
	type EffectiveInstructionSource,
} from "@/lib/effective-instructions";
import type { SessionFileDiff } from "@/lib/session-diff";
import {
	buildTaskExecutionReport,
	reportProgress,
	type TaskReportSummary,
} from "@/lib/task-report";
import { cn } from "@/lib/utils";

export function TaskReportPanel({
	open,
	onOpenChange,
	sessionId,
	status,
	messages,
	fileDiffs,
	summary,
	provider,
	model,
	mode,
	queuedInstructions,
	systemPrompt,
	rules,
	workspaceRoot,
	onManageInstructions,
	onUpdateInstructions,
	onStop,
}: {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	sessionId?: string | null;
	status: ChatSessionStatus;
	messages: ChatMessage[];
	fileDiffs: SessionFileDiff[];
	summary: TaskReportSummary;
	provider: string;
	model: string;
	mode: "act" | "plan" | "yolo";
	queuedInstructions: string[];
	systemPrompt?: string;
	rules?: string;
	workspaceRoot?: string;
	onManageInstructions?: () => void;
	onUpdateInstructions: (value: {
		systemPrompt?: string;
		rules?: string;
	}) => void;
	onStop: () => void | Promise<void>;
}) {
	const [expandedSteps, setExpandedSteps] = useState<Set<string>>(
		() => new Set(),
	);
	const [expandedInstructionIds, setExpandedInstructionIds] = useState<
		Set<string>
	>(() => new Set());
	const [instructionInventory, setInstructionInventory] =
		useState<EffectiveInstructionInventory | null>(null);
	const [instructionsLoading, setInstructionsLoading] = useState(false);
	const [instructionsError, setInstructionsError] = useState<string | null>(
		null,
	);
	const [editingInstructions, setEditingInstructions] = useState(false);
	const [systemPromptDraft, setSystemPromptDraft] = useState(
		systemPrompt ?? "",
	);
	const [rulesDraft, setRulesDraft] = useState(rules ?? "");
	useEffect(() => {
		if (editingInstructions) return;
		setSystemPromptDraft(systemPrompt ?? "");
		setRulesDraft(rules ?? "");
	}, [editingInstructions, rules, systemPrompt]);
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
	const instructionSources = useMemo(
		() =>
			buildEffectiveInstructionSources({
				systemPrompt,
				rules,
				workspaceRoot,
				inventory: instructionInventory,
			}),
		[systemPrompt, rules, workspaceRoot, instructionInventory],
	);
	useEffect(() => {
		if (!open) return;
		let cancelled = false;
		const load = async () => {
			setInstructionsLoading(true);
			try {
				const inventory =
					await desktopClient.invoke<EffectiveInstructionInventory>(
						"list_user_instruction_configs",
						workspaceRoot ? { workspaceRoot } : undefined,
					);
				if (!cancelled) {
					setInstructionInventory(inventory);
					setInstructionsError(null);
				}
			} catch (error) {
				if (!cancelled) {
					setInstructionsError(
						error instanceof Error
							? error.message
							: "Unable to load instruction sources.",
					);
				}
			} finally {
				if (!cancelled) setInstructionsLoading(false);
			}
		};
		void load();
		const unsubscribe = desktopClient.subscribe("settings.changed", () => {
			void load();
		});
		return () => {
			cancelled = true;
			unsubscribe();
		};
	}, [open, workspaceRoot]);
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
		return null;
	}

	return (
		<aside className="relative z-30 flex h-full w-[min(28rem,46vw)] min-w-80 shrink-0 animate-in flex-col border-l bg-card/95 text-card-foreground shadow-2xl backdrop-blur-xl duration-200 slide-in-from-right-4 max-md:absolute max-md:inset-y-0 max-md:right-0 max-md:w-[min(28rem,calc(100vw-1rem))]">
			<header className="shrink-0 border-b bg-gradient-to-b from-primary/5 to-transparent p-4">
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
						onClick={() => onOpenChange(false)}
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

					<section>
						<div className="mb-2 flex items-center justify-between gap-2">
							<h3 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
								<BookOpen className="size-3.5" />
								Effective AI instructions
							</h3>
							<div className="flex items-center gap-1">
								{onManageInstructions ? (
									<Button
										onClick={onManageInstructions}
										size="sm"
										type="button"
										variant="ghost"
									>
										Manage sources
									</Button>
								) : null}
								<Button
									onClick={() => setEditingInstructions((current) => !current)}
									size="sm"
									type="button"
									variant="outline"
								>
									{editingInstructions ? "Cancel" : "Edit"}
								</Button>
							</div>
						</div>
						<p className="mb-2 text-[11px] leading-4 text-muted-foreground">
							Session instructions apply to the next turn. Internal platform
							prompts and credentials remain hidden; common secret values are
							redacted in this report.
						</p>
						{editingInstructions ? (
							<div className="mb-3 space-y-3 rounded-md border bg-background/60 p-3">
								<label className="block space-y-1.5">
									<span className="text-xs font-medium">
										Custom system prompt
									</span>
									<Textarea
										aria-label="Custom system prompt"
										className="min-h-28 font-mono text-xs"
										onChange={(event) =>
											setSystemPromptDraft(event.target.value)
										}
										placeholder="Optional instructions that customize this session's behavior"
										value={systemPromptDraft}
									/>
								</label>
								<label className="block space-y-1.5">
									<span className="text-xs font-medium">Session rules</span>
									<Textarea
										aria-label="Session rules"
										className="min-h-24 font-mono text-xs"
										onChange={(event) => setRulesDraft(event.target.value)}
										placeholder="Constraints, conventions, validation requirements, and done conditions"
										value={rulesDraft}
									/>
								</label>
								<div className="flex justify-end">
									<Button
										onClick={() => {
											onUpdateInstructions({
												systemPrompt: systemPromptDraft.trim() || undefined,
												rules: rulesDraft.trim() || undefined,
											});
											setEditingInstructions(false);
										}}
										size="sm"
										type="button"
									>
										Save for this session
									</Button>
								</div>
							</div>
						) : null}
						{instructionsLoading && instructionSources.length === 0 ? (
							<div className="flex items-center gap-2 text-xs text-muted-foreground">
								<Loader2 className="size-3.5 animate-spin" />
								Loading instruction sources…
							</div>
						) : instructionSources.length === 0 ? (
							<p className="text-xs text-muted-foreground">
								No user-configured instructions are active for this session.
							</p>
						) : (
							<div className="space-y-1.5">
								{instructionSources.map((source) => (
									<InstructionSourceRow
										expanded={expandedInstructionIds.has(source.id)}
										key={source.id}
										onToggle={() =>
											setExpandedInstructionIds((current) => {
												const next = new Set(current);
												if (next.has(source.id)) next.delete(source.id);
												else next.add(source.id);
												return next;
											})
										}
										source={source}
									/>
								))}
							</div>
						)}
						{instructionsError ? (
							<p className="mt-2 text-[11px] text-destructive" role="alert">
								{instructionsError}
							</p>
						) : null}
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

export function TaskReportTrigger({
	open,
	status,
	onClick,
}: {
	open: boolean;
	status: ChatSessionStatus;
	onClick: () => void;
}) {
	const isBusy =
		status === "starting" || status === "running" || status === "stopping";
	return (
		<Button
			aria-expanded={open}
			aria-label={open ? "Task report open" : "Open task report"}
			className={cn(
				"h-7 shrink-0 gap-1.5 rounded-md px-2 text-xs",
				open && "border-primary/40 bg-primary/10 text-foreground",
			)}
			onClick={onClick}
			size="sm"
			title={open ? "Close task report" : "Open task report"}
			type="button"
			variant="outline"
		>
			<ListChecks className="size-3.5" />
			<span className="max-[680px]:sr-only">Task report</span>
			{isBusy ? (
				<span className="size-1.5 rounded-full bg-blue-500 animate-pulse" />
			) : null}
		</Button>
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

function InstructionSourceRow({
	source,
	expanded,
	onToggle,
}: {
	source: EffectiveInstructionSource;
	expanded: boolean;
	onToggle: () => void;
}) {
	const icon =
		source.kind === "mcp" ? (
			<Plug className="size-3.5" />
		) : source.kind === "tool" ? (
			<Wrench className="size-3.5" />
		) : (
			<BookOpen className="size-3.5" />
		);
	return (
		<div className="rounded-md border bg-background/60">
			<button
				className="flex w-full items-center gap-2 px-2.5 py-2 text-left"
				onClick={onToggle}
				type="button"
			>
				{icon}
				<div className="min-w-0 flex-1">
					<div className="truncate text-xs font-medium">{source.label}</div>
					{source.detail ? (
						<div
							className="truncate text-[10px] text-muted-foreground"
							title={source.detail}
						>
							{source.detail}
						</div>
					) : null}
				</div>
				<Badge className="capitalize" variant="outline">
					{source.kind}
				</Badge>
				{source.content ? (
					expanded ? (
						<ChevronDown className="size-3.5" />
					) : (
						<ChevronRight className="size-3.5" />
					)
				) : null}
			</button>
			{expanded && source.content ? (
				<pre className="max-h-56 overflow-auto whitespace-pre-wrap break-words border-t p-3 font-mono text-[11px] leading-4 text-muted-foreground">
					{source.content}
				</pre>
			) : null}
		</div>
	);
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
