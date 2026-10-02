"use client";

import {
	Ban,
	Check,
	CheckCircle2,
	Copy,
	FileCode2,
	Files,
	GitCompareArrows,
	Loader2,
	XCircle,
} from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { toast } from "@/hooks/use-toast";
import type { ChatSessionStatus } from "@/lib/chat-schema";
import { desktopClient } from "@/lib/desktop-client";
import type { SessionFileDiff } from "@/lib/session-diff";
import {
	formatTaskReportText,
	type SessionTaskReport,
} from "@/lib/task-report";
import { cn } from "@/lib/utils";

function completionState(status: ChatSessionStatus) {
	if (status === "failed" || status === "error") {
		return {
			icon: XCircle,
			label: "Session ended with an error",
			tone: "text-destructive",
		};
	}
	if (status === "cancelled") {
		return {
			icon: Ban,
			label: "Session cancelled",
			tone: "text-muted-foreground",
		};
	}
	return {
		icon: CheckCircle2,
		label: "Task completed",
		tone: "text-emerald-600 dark:text-emerald-400",
	};
}

export function SessionCompletionCard({
	cwd,
	environmentId,
	fileDiffs,
	onOpenDiff,
	report,
	status,
	tools,
	turns,
}: {
	cwd?: string;
	environmentId: string;
	fileDiffs: SessionFileDiff[];
	onOpenDiff?: () => void;
	report?: SessionTaskReport | null;
	status: ChatSessionStatus;
	tools: number;
	turns: number;
}) {
	const [copied, setCopied] = useState(false);
	const [openingPath, setOpeningPath] = useState<string | null>(null);
	const state = completionState(status);
	const StatusIcon = state.icon;
	const totals = useMemo(
		() =>
			fileDiffs.reduce(
				(sum, file) => ({
					additions: sum.additions + file.additions,
					deletions: sum.deletions + file.deletions,
				}),
				{ additions: 0, deletions: 0 },
			),
		[fileDiffs],
	);
	const visibleFiles = fileDiffs.slice(0, 8);

	const openFile = useCallback(
		async (path: string) => {
			setOpeningPath(path);
			try {
				await desktopClient.invoke("open_file_in_editor", {
					environmentId,
					path,
					...(cwd?.trim() ? { cwd } : {}),
				});
			} catch (error) {
				toast({
					variant: "destructive",
					title: "Could not open file",
					description:
						error instanceof Error ? error.message : "The file could not be opened.",
				});
			} finally {
				setOpeningPath((current) => (current === path ? null : current));
			}
		},
		[cwd, environmentId],
	);

	const copySummary = useCallback(async () => {
		const lines = [
			state.label,
			report?.explanation ?? "",
			`Turns: ${turns} · Tools: ${tools} · Files changed: ${fileDiffs.length}`,
			...fileDiffs.map(
				(file) => `${file.path} (+${file.additions} -${file.deletions})`,
			),
			report ? `\n${formatTaskReportText(report)}` : "",
		].filter(Boolean);
		await navigator.clipboard.writeText(lines.join("\n"));
		setCopied(true);
		window.setTimeout(() => setCopied(false), 1600);
	}, [fileDiffs, report, state.label, tools, turns]);

	return (
		<section
			aria-label="Session completion summary"
			className="mt-5 overflow-hidden rounded-xl border border-border/70 bg-card/55"
		>
			<header className="flex items-start gap-3 border-b border-border/60 px-4 py-3.5">
				<StatusIcon className={cn("mt-0.5 size-5 shrink-0", state.tone)} />
				<div className="min-w-0 flex-1">
					<h2 className="text-sm font-semibold tracking-tight">{state.label}</h2>
					<p className="mt-0.5 text-xs leading-5 text-muted-foreground">
						{report?.explanation ??
							"The session finished. Review the result and changed files below."}
					</p>
				</div>
				<Button
					aria-label="Copy session summary"
					className="shrink-0"
					onClick={() => void copySummary()}
					size="icon-sm"
					variant="ghost"
				>
					{copied ? <Check className="size-4" /> : <Copy className="size-4" />}
				</Button>
			</header>

			<div className="grid grid-cols-3 border-b border-border/60 text-xs">
				<div className="px-4 py-2.5">
					<span className="text-muted-foreground">Turns</span>
					<strong className="ml-2 font-semibold text-foreground">{turns}</strong>
				</div>
				<div className="border-x border-border/60 px-4 py-2.5">
					<span className="text-muted-foreground">Tools</span>
					<strong className="ml-2 font-semibold text-foreground">{tools}</strong>
				</div>
				<div className="px-4 py-2.5">
					<span className="text-muted-foreground">Files</span>
					<strong className="ml-2 font-semibold text-foreground">
						{fileDiffs.length}
					</strong>
				</div>
			</div>

			{visibleFiles.length > 0 ? (
				<div>
					<div className="flex items-center justify-between px-4 pb-2 pt-3">
						<div className="flex items-center gap-2 text-xs font-medium">
							<Files className="size-3.5 text-muted-foreground" />
							Changed files
						</div>
						<div className="font-mono text-[11px]">
							<span className="text-emerald-600 dark:text-emerald-400">
								+{totals.additions}
							</span>{" "}
							<span className="text-destructive">-{totals.deletions}</span>
						</div>
					</div>
					<div className="divide-y divide-border/50 border-y border-border/50">
						{visibleFiles.map((file) => (
							<button
								className="group flex min-h-11 w-full items-center gap-3 px-4 text-left transition-colors hover:bg-muted/45 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-inset"
								key={file.path}
								onClick={() => void openFile(file.path)}
								type="button"
							>
								{openingPath === file.path ? (
									<Loader2 className="size-4 shrink-0 animate-spin text-muted-foreground" />
								) : (
									<FileCode2 className="size-4 shrink-0 text-muted-foreground group-hover:text-foreground" />
								)}
								<span className="min-w-0 flex-1 truncate font-mono text-xs">
									{file.path}
								</span>
								<span className="shrink-0 font-mono text-[11px]">
									<span className="text-emerald-600 dark:text-emerald-400">
										+{file.additions}
									</span>{" "}
									<span className="text-destructive">-{file.deletions}</span>
								</span>
							</button>
						))}
					</div>
					{fileDiffs.length > visibleFiles.length ? (
						<p className="px-4 py-2 text-xs text-muted-foreground">
							+{fileDiffs.length - visibleFiles.length} more files
						</p>
					) : null}
				</div>
			) : null}

			<footer className="flex flex-wrap items-center justify-end gap-2 px-4 py-3">
				{fileDiffs.length > 0 && onOpenDiff ? (
					<Button onClick={onOpenDiff} size="sm" variant="outline">
						<GitCompareArrows className="size-4" />
						Review changes
					</Button>
				) : null}
			</footer>
		</section>
	);
}
