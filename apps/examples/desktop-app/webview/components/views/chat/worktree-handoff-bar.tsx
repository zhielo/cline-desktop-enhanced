"use client";

import { GitBranch, GitPullRequest, Loader2, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { desktopClient, openExternalUrl } from "@/lib/desktop-client";
import { isTaskWorktreePath } from "@/lib/workspace-paths";

type WorktreeStatus = {
	path: string;
	branch: string;
	currentBranch: string;
	dirty: boolean;
	sourceDirty: boolean;
	conflicts: string[];
	commitsAhead: number;
	retained?: boolean;
};

type HandoffAction =
	| "apply_local"
	| "create_branch"
	| "open_pr"
	| "keep"
	| "discard";

export function WorktreeHandoffBar({ cwd }: { cwd: string }) {
	const [status, setStatus] = useState<WorktreeStatus | null>(null);
	const [busy, setBusy] = useState<HandoffAction | null>(null);
	const [error, setError] = useState<string | null>(null);
	const managed = isTaskWorktreePath(cwd);

	useEffect(() => {
		if (!managed) return;
		let cancelled = false;
		desktopClient
			.invoke<WorktreeStatus>("get_git_worktree_handoff", { path: cwd })
			.then((value) => {
				if (!cancelled) setStatus(value);
			})
			.catch((cause) => {
				if (!cancelled)
					setError(
						cause instanceof Error
							? cause.message
							: "Could not inspect worktree",
					);
			});
		return () => {
			cancelled = true;
		};
	}, [cwd, managed]);

	if (!managed) return null;

	async function run(action: HandoffAction) {
		let branch: string | undefined;
		let confirmDiscard = false;
		if (action === "create_branch") {
			branch = window
				.prompt("Branch name", status?.currentBranch ?? "")
				?.trim();
			if (!branch) return;
		}
		if (action === "discard") {
			confirmDiscard = window.confirm(
				"Discard this managed worktree and its uncommitted changes? This cannot be undone.",
			);
			if (!confirmDiscard) return;
		}
		setBusy(action);
		setError(null);
		try {
			const result = await desktopClient.invoke<{
				url?: string;
				branch?: string;
			}>("handoff_git_worktree", {
				path: cwd,
				action,
				branch,
				confirmDiscard,
			});
			if (result.url) await openExternalUrl(result.url);
			if (action === "discard") window.location.reload();
			else {
				const next = await desktopClient.invoke<WorktreeStatus>(
					"get_git_worktree_handoff",
					{ path: cwd },
				);
				setStatus(next);
			}
		} catch (cause) {
			setError(
				cause instanceof Error ? cause.message : "Worktree handoff failed",
			);
		} finally {
			setBusy(null);
		}
	}

	const blocked = Boolean(status?.conflicts.length);
	return (
		<section
			aria-label="Worktree handoff"
			className="border-b border-border px-4 py-2 text-xs"
		>
			<div className="flex min-w-0 flex-wrap items-center gap-2">
				{busy ? (
					<Loader2 className="size-4 animate-spin" />
				) : (
					<GitBranch className="size-4" />
				)}
				<span className="min-w-0 flex-1 truncate text-muted-foreground">
					Isolated worktree · {status?.currentBranch ?? "loading"}
					{status?.dirty ? " · uncommitted changes" : ""}
					{blocked ? " · conflicts" : ""}
				</span>
				<button
					type="button"
					disabled={Boolean(busy) || blocked}
					onClick={() => void run("apply_local")}
					className="rounded px-2 py-1 hover:bg-muted disabled:opacity-50"
				>
					Apply to Local
				</button>
				<button
					type="button"
					disabled={Boolean(busy)}
					onClick={() => void run("create_branch")}
					className="rounded px-2 py-1 hover:bg-muted disabled:opacity-50"
				>
					Create Branch
				</button>
				<button
					type="button"
					disabled={Boolean(busy) || blocked}
					onClick={() => void run("open_pr")}
					className="rounded px-2 py-1 hover:bg-muted disabled:opacity-50"
				>
					<GitPullRequest className="mr-1 inline size-3" />
					Open PR
				</button>
				<button
					type="button"
					disabled={Boolean(busy)}
					onClick={() => void run("keep")}
					className="rounded px-2 py-1 hover:bg-muted disabled:opacity-50"
				>
					Keep
				</button>
				<button
					type="button"
					disabled={Boolean(busy)}
					onClick={() => void run("discard")}
					className="rounded p-1 text-destructive hover:bg-destructive/10"
					aria-label="Discard worktree"
				>
					<Trash2 className="size-3.5" />
				</button>
			</div>
			{error ? (
				<output className="mt-1 block text-destructive">{error}</output>
			) : null}
		</section>
	);
}
