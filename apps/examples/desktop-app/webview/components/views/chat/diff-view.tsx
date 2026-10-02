"use client";

import { ToolFileDiff } from "@cline/ui/components/agent-chat/tool-diff";
import {
	AppWindow,
	Check,
	ChevronDown,
	ChevronRight,
	Copy,
	ExternalLink,
	FileCode2,
	Loader2,
	RotateCcw,
	Search,
	SquareTerminal,
	X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
	AlertDialog,
	AlertDialogAction,
	AlertDialogCancel,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
	DropdownMenu,
	DropdownMenuContent,
	DropdownMenuItem,
	DropdownMenuLabel,
	DropdownMenuSeparator,
	DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { toast } from "@/hooks/use-toast";
import { desktopClient } from "@/lib/desktop-client";
import type { SessionDiffHunk, SessionFileDiff } from "@/lib/session-diff";
import { cn } from "@/lib/utils";
import { resolveWorkspaceFilePath } from "@/lib/workspace-paths";
import { AnalysisWorkbench } from "./analysis-workbench";
import { ArtifactContextMenu } from "./artifact-context-menu";
import { EditorIcon } from "./editor-icons";
import { WorkspaceTerminal } from "./workspace-terminal";

type DiffViewProps = {
	environmentId: string;
	fileDiffs: SessionFileDiff[];
	cwd?: string;
	onClose: () => void;
};

type EditorOption = { id: string; label: string };
type ReviewScope = "all" | "staged" | "unstaged";
type WorkspaceFileResult = { root: string; files: string[]; limit: number };

export function DiffView({
	environmentId,
	fileDiffs,
	cwd,
	onClose,
}: DiffViewProps) {
	const [collapsedFiles, setCollapsedFiles] = useState<Set<string>>(new Set());
	const [editors, setEditors] = useState<EditorOption[]>([]);
	const [scope, setScope] = useState<ReviewScope>("all");
	const [stagedPaths, setStagedPaths] = useState<Set<string>>(new Set());
	const [hiddenPaths, setHiddenPaths] = useState<Set<string>>(new Set());
	const [busyPaths, setBusyPaths] = useState<Set<string>>(new Set());
	const [pendingRevert, setPendingRevert] = useState<string[] | null>(null);
	const [activeTab, setActiveTab] = useState<
		"changes" | "files" | "terminal" | "analysis"
	>("changes");
	const [fileQuery, setFileQuery] = useState("");
	const [workspaceFiles, setWorkspaceFiles] = useState<string[]>([]);
	const [filesLoading, setFilesLoading] = useState(false);

	useEffect(() => {
		let cancelled = false;
		desktopClient
			.invoke<EditorOption[]>("list_available_editors")
			.then((list) => {
				if (!cancelled && Array.isArray(list)) setEditors(list);
			})
			.catch(() => {});
		return () => {
			cancelled = true;
		};
	}, []);

	useEffect(() => {
		if (activeTab !== "files") return;
		let cancelled = false;
		const timer = window.setTimeout(() => {
			setFilesLoading(true);
			desktopClient
				.invoke<WorkspaceFileResult>("list_workspace_files", {
					environmentId,
					...(cwd?.trim() ? { cwd } : {}),
					query: fileQuery,
				})
				.then((result) => {
					if (!cancelled) setWorkspaceFiles(result.files ?? []);
				})
				.catch((error) => {
					if (!cancelled)
						toast({
							variant: "destructive",
							title: "Could not search files",
							description:
								error instanceof Error
									? error.message
									: "Workspace search failed.",
						});
				})
				.finally(() => {
					if (!cancelled) setFilesLoading(false);
				});
		}, 180);
		return () => {
			cancelled = true;
			window.clearTimeout(timer);
		};
	}, [activeTab, cwd, environmentId, fileQuery]);

	const reviewFiles = useMemo(
		() =>
			fileDiffs.filter((file) => {
				if (hiddenPaths.has(file.path)) return false;
				if (scope === "staged") return stagedPaths.has(file.path);
				if (scope === "unstaged") return !stagedPaths.has(file.path);
				return true;
			}),
		[fileDiffs, hiddenPaths, scope, stagedPaths],
	);

	const mutatePaths = useCallback(
		async (action: "stage" | "unstage" | "revert", paths: string[]) => {
			if (paths.length === 0) return;
			setBusyPaths((previous) => new Set([...previous, ...paths]));
			try {
				await desktopClient.invoke(`${action}_git_paths`, {
					environmentId,
					...(cwd?.trim() ? { cwd } : {}),
					paths,
					...(action === "revert" ? { confirm: true } : {}),
				});
				if (action === "stage")
					setStagedPaths((previous) => new Set([...previous, ...paths]));
				if (action === "unstage")
					setStagedPaths((previous) => {
						const next = new Set(previous);
						for (const path of paths) next.delete(path);
						return next;
					});
				if (action === "revert")
					setHiddenPaths((previous) => new Set([...previous, ...paths]));
				toast({
					title:
						action === "revert"
							? "Changes reverted"
							: action === "stage"
								? "Changes staged"
								: "Changes unstaged",
					description: `${paths.length} file${paths.length === 1 ? "" : "s"} updated.`,
				});
			} catch (error) {
				toast({
					variant: "destructive",
					title: `Could not ${action} changes`,
					description:
						error instanceof Error ? error.message : "Git action failed.",
				});
			} finally {
				setBusyPaths((previous) => {
					const next = new Set(previous);
					for (const path of paths) next.delete(path);
					return next;
				});
			}
		},
		[cwd, environmentId],
	);

	const openWorkspaceFile = useCallback(
		async (path: string) => {
			await desktopClient.invoke("open_file_in_editor", {
				environmentId,
				path,
				...(cwd?.trim() ? { cwd } : {}),
			});
		},
		[cwd, environmentId],
	);

	const openTerminal = useCallback(async () => {
		try {
			await desktopClient.invoke("open_workspace_terminal", {
				environmentId,
				...(cwd?.trim() ? { cwd } : {}),
			});
		} catch (error) {
			toast({
				variant: "destructive",
				title: "Could not open terminal",
				description:
					error instanceof Error ? error.message : "Terminal launch failed.",
			});
		}
	}, [cwd, environmentId]);

	return (
		<div className="flex h-full min-h-0 flex-col overflow-hidden">
			<div className="flex min-h-10 shrink-0 flex-wrap items-center justify-between gap-2 border-b border-border bg-card px-3 py-1.5">
				<div className="flex items-center gap-1">
					{(["changes", "files", "terminal", "analysis"] as const).map(
						(tab) => (
							<button
								className={cn(
									"rounded-md px-2.5 py-1 text-xs capitalize",
									activeTab === tab
										? "bg-secondary text-foreground"
										: "text-muted-foreground hover:text-foreground",
								)}
								key={tab}
								onClick={() => setActiveTab(tab)}
								type="button"
							>
								{tab}
							</button>
						),
					)}
					{activeTab === "changes" && (
						<span className="ml-1 rounded bg-secondary px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
							Files: {reviewFiles.length}
						</span>
					)}
				</div>
				<div className="flex items-center gap-1">
					<button
						aria-label="Open workspace terminal"
						className="rounded-md p-1.5 text-muted-foreground hover:bg-surface-hover hover:text-foreground"
						onClick={() => void openTerminal()}
						title="Open terminal here"
						type="button"
					>
						<SquareTerminal className="h-4 w-4" />
					</button>
					<button
						aria-label="Close diff view"
						className="rounded-md p-1.5 text-muted-foreground hover:bg-surface-hover hover:text-foreground"
						onClick={onClose}
						type="button"
					>
						<X className="h-4 w-4" />
					</button>
				</div>
			</div>

			{activeTab === "changes" ? (
				<>
					<div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-border px-3 py-2">
						<div className="flex rounded-md bg-secondary/70 p-0.5">
							{(["all", "unstaged", "staged"] as const).map((item) => (
								<button
									className={cn(
										"rounded px-2 py-1 text-[11px] capitalize",
										scope === item
											? "bg-background text-foreground shadow-sm"
											: "text-muted-foreground",
									)}
									key={item}
									onClick={() => setScope(item)}
									type="button"
								>
									{item === "all" ? "Last turn" : item}
								</button>
							))}
						</div>
						<div className="ml-auto flex gap-1.5">
							<button
								className="rounded-md border border-border px-2.5 py-1 text-[11px] hover:bg-surface-hover disabled:opacity-50"
								disabled={reviewFiles.length === 0}
								onClick={() =>
									void mutatePaths(
										reviewFiles.every((file) => stagedPaths.has(file.path))
											? "unstage"
											: "stage",
										reviewFiles.map((file) => file.path),
									)
								}
								type="button"
							>
								{reviewFiles.length > 0 &&
								reviewFiles.every((file) => stagedPaths.has(file.path))
									? "Unstage all"
									: "Stage all"}
							</button>
							<button
								className="rounded-md border border-destructive/40 px-2.5 py-1 text-[11px] text-destructive hover:bg-destructive/10 disabled:opacity-50"
								disabled={reviewFiles.length === 0}
								onClick={() =>
									setPendingRevert(reviewFiles.map((file) => file.path))
								}
								type="button"
							>
								Revert all
							</button>
						</div>
					</div>
					<ScrollArea className="min-h-0 flex-1">
						{reviewFiles.length === 0 ? (
							<div className="flex h-full items-center justify-center px-4 py-16 text-sm text-muted-foreground">
								No changes in this view.
							</div>
						) : (
							<div className="flex flex-col">
								{reviewFiles.map((file) => (
									<DiffFileSection
										busy={busyPaths.has(file.path)}
										collapsed={collapsedFiles.has(file.path)}
										cwd={cwd}
										editors={editors}
										environmentId={environmentId}
										file={file}
										key={file.path}
										onRequestRevert={() => setPendingRevert([file.path])}
										onStageToggle={() =>
											void mutatePaths(
												stagedPaths.has(file.path) ? "unstage" : "stage",
												[file.path],
											)
										}
										onToggle={() =>
											setCollapsedFiles((previous) => {
												const next = new Set(previous);
												next.has(file.path)
													? next.delete(file.path)
													: next.add(file.path);
												return next;
											})
										}
										staged={stagedPaths.has(file.path)}
									/>
								))}
							</div>
						)}
					</ScrollArea>
				</>
			) : activeTab === "files" ? (
				<>
					<div className="relative shrink-0 border-b border-border p-3">
						<Search className="absolute left-5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
						<Input
							aria-label="Search workspace files"
							className="h-8 pl-8 text-xs"
							onChange={(event) => setFileQuery(event.target.value)}
							placeholder="Search files by path…"
							value={fileQuery}
						/>
					</div>
					<ScrollArea className="min-h-0 flex-1">
						<div className="p-2">
							{filesLoading ? (
								<div className="grid place-items-center py-16">
									<Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
								</div>
							) : workspaceFiles.length === 0 ? (
								<div className="py-16 text-center text-sm text-muted-foreground">
									No matching workspace files.
								</div>
							) : (
								workspaceFiles.map((path) => (
									<ArtifactContextMenu
										cwd={cwd}
										environmentId={environmentId}
										key={path}
										onOpen={() => openWorkspaceFile(path)}
										path={resolveWorkspaceFilePath(path, cwd)}
									>
										<button
											className="group flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left hover:bg-surface-hover"
											onClick={() => void openWorkspaceFile(path)}
											type="button"
										>
											<FileCode2 className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
											<span className="min-w-0 flex-1 truncate font-mono text-xs">
												{path}
											</span>
											<ExternalLink className="h-3 w-3 text-muted-foreground opacity-0 group-hover:opacity-100" />
										</button>
									</ArtifactContextMenu>
								))
							)}
						</div>
					</ScrollArea>
				</>
			) : activeTab === "terminal" ? (
				<WorkspaceTerminal cwd={cwd} environmentId={environmentId} />
			) : (
				<AnalysisWorkbench cwd={cwd} environmentId={environmentId} />
			)}

			<AlertDialog
				onOpenChange={(open) => {
					if (!open) setPendingRevert(null);
				}}
				open={pendingRevert !== null}
			>
				<AlertDialogContent>
					<AlertDialogHeader>
						<AlertDialogTitle>Discard these changes?</AlertDialogTitle>
						<AlertDialogDescription>
							This permanently restores {pendingRevert?.length ?? 0} file
							{pendingRevert?.length === 1 ? "" : "s"} from Git. This action
							cannot be undone.
						</AlertDialogDescription>
					</AlertDialogHeader>
					<AlertDialogFooter>
						<AlertDialogCancel>Cancel</AlertDialogCancel>
						<AlertDialogAction
							className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
							onClick={() => {
								const paths = pendingRevert ?? [];
								setPendingRevert(null);
								void mutatePaths("revert", paths);
							}}
						>
							Revert changes
						</AlertDialogAction>
					</AlertDialogFooter>
				</AlertDialogContent>
			</AlertDialog>
		</div>
	);
}

function DiffFileSection({
	file,
	collapsed,
	cwd,
	editors,
	environmentId,
	onToggle,
	staged,
	busy,
	onStageToggle,
	onRequestRevert,
}: {
	file: SessionFileDiff;
	collapsed: boolean;
	cwd?: string;
	editors: EditorOption[];
	environmentId: string;
	onToggle: () => void;
	staged: boolean;
	busy: boolean;
	onStageToggle: () => void;
	onRequestRevert: () => void;
}) {
	const [copied, setCopied] = useState(false);
	const [opening, setOpening] = useState(false);
	const copyResetTimerRef = useRef<number | null>(null);
	const resolvedPath = resolveWorkspaceFilePath(file.path, cwd);
	const handleCopyPath = useCallback(async () => {
		try {
			await navigator.clipboard.writeText(resolvedPath);
			setCopied(true);
			if (copyResetTimerRef.current !== null)
				window.clearTimeout(copyResetTimerRef.current);
			copyResetTimerRef.current = window.setTimeout(() => {
				setCopied(false);
				copyResetTimerRef.current = null;
			}, 1600);
		} catch {
			toast({
				variant: "destructive",
				title: "Copy failed",
				description: "The file path could not be copied to the clipboard.",
			});
		}
	}, [resolvedPath]);
	const handleOpenInEditor = useCallback(
		async (editor?: string) => {
			setOpening(true);
			try {
				await desktopClient.invoke("open_file_in_editor", {
					environmentId,
					path: file.path,
					...(cwd?.trim() ? { cwd } : {}),
					...(editor ? { editor } : {}),
				});
			} catch (error) {
				toast({
					variant: "destructive",
					title: "Could not open file",
					description:
						error instanceof Error
							? error.message
							: "The file could not be opened in an editor.",
				});
			} finally {
				setOpening(false);
			}
		},
		[cwd, environmentId, file.path],
	);
	return (
		<div className="border-b border-border">
			<div className="group flex w-full items-center gap-2 bg-card/80 px-4 py-2 hover:bg-surface-hover-lighter">
				<button
					className="flex min-w-0 shrink items-center gap-2 text-left"
					onClick={onToggle}
					type="button"
				>
					{collapsed ? (
						<ChevronRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
					) : (
						<ChevronDown className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
					)}
					<span className="min-w-0 truncate font-mono text-xs text-foreground">
						{file.path}
					</span>
				</button>
				{staged && (
					<span className="rounded bg-primary/10 px-1.5 py-0.5 text-[9px] font-medium uppercase text-primary">
						Staged
					</span>
				)}
				<button
					aria-label={`Copy file path for ${file.path}`}
					className={cn(
						"shrink-0 rounded-md p-1 text-muted-foreground opacity-0 group-hover:opacity-100",
						copied && "opacity-100 text-primary",
					)}
					onClick={() => void handleCopyPath()}
					type="button"
				>
					{copied ? (
						<Check className="h-3.5 w-3.5" />
					) : (
						<Copy className="h-3.5 w-3.5" />
					)}
				</button>
				<button
					aria-hidden
					className="h-6 min-w-0 flex-1"
					onClick={onToggle}
					tabIndex={-1}
					type="button"
				/>
				<button
					className="rounded px-2 py-1 text-[10px] text-muted-foreground hover:bg-secondary hover:text-foreground disabled:opacity-50"
					disabled={busy}
					onClick={onStageToggle}
					type="button"
				>
					{busy ? "Working…" : staged ? "Unstage" : "Stage"}
				</button>
				<button
					aria-label={`Revert ${file.path}`}
					className="rounded p-1 text-muted-foreground opacity-0 hover:bg-destructive/10 hover:text-destructive group-hover:opacity-100"
					disabled={busy}
					onClick={onRequestRevert}
					title="Revert file"
					type="button"
				>
					<RotateCcw className="h-3.5 w-3.5" />
				</button>
				<DropdownMenu>
					<DropdownMenuTrigger asChild>
						<button
							aria-label={`Open ${file.path} in editor`}
							className="shrink-0 rounded-md p-1 text-muted-foreground opacity-0 hover:bg-surface-hover hover:text-foreground group-hover:opacity-100 data-[state=open]:opacity-100"
							disabled={opening}
							type="button"
						>
							<ExternalLink className="h-3.5 w-3.5" />
						</button>
					</DropdownMenuTrigger>
					<DropdownMenuContent align="end" className="w-52">
						<DropdownMenuLabel>Open in</DropdownMenuLabel>
						{editors.map((editor) => (
							<DropdownMenuItem
								key={editor.id}
								onSelect={() => void handleOpenInEditor(editor.id)}
							>
								<EditorIcon editorId={editor.id} />
								{editor.label}
							</DropdownMenuItem>
						))}
						{editors.length > 0 && <DropdownMenuSeparator />}
						<DropdownMenuItem
							onSelect={() => void handleOpenInEditor("default")}
						>
							<AppWindow aria-hidden />
							System default
						</DropdownMenuItem>
					</DropdownMenuContent>
				</DropdownMenu>
				<span className="font-mono text-[11px] text-primary">
					+{file.additions}
				</span>
				<span className="font-mono text-[11px] text-destructive">
					-{file.deletions}
				</span>
			</div>
			{!collapsed && (
				<div className="space-y-2 border-t border-border bg-card/40 px-4 py-3">
					{file.hunks.length === 0 ? (
						<p className="text-xs text-muted-foreground">
							No hunk details available.
						</p>
					) : (
						file.hunks.map((hunk, index) => (
							<DiffHunk
								hunk={hunk}
								// biome-ignore lint/suspicious/noArrayIndexKey: hunks never reorder inside a file.
								key={`${file.path}-${index}-${hunk.oldStart}-${hunk.newStart}-${hunk.old.length}-${hunk.new.length}`}
								path={file.path}
							/>
						))
					)}
				</div>
			)}
		</div>
	);
}

function DiffHunk({ hunk, path }: { hunk: SessionDiffHunk; path: string }) {
	const isCompleteNewContents =
		hunk.old.length === 0 && hunk.oldStart === 1 && hunk.newStart === 1;
	return (
		<ToolFileDiff
			background="var(--background)"
			className="cline-chat-selectable"
			fragment={!isCompleteNewContents}
			newText={hunk.new}
			oldText={isCompleteNewContents ? undefined : hunk.old}
			path={path}
		/>
	);
}
