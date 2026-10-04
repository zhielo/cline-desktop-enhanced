"use client";

import {
	Bot,
	CheckCircle2,
	GitBranch,
	GitCompare,
	Loader2,
	RefreshCw,
	Route,
	ShieldCheck,
	Sparkles,
	TriangleAlert,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import { desktopClient } from "@/lib/desktop-client";
import {
	LOCAL_WORKSPACE_ENVIRONMENT_ID,
	readWorkspaceSelectionFromWindow,
} from "@/lib/workspace-paths";

type Mission = {
	id: string;
	title: string;
	status: string;
	tasks: Array<{
		id: string;
		label: string;
		role: string;
		status: string;
		requiresWorktree: boolean;
		ownerAgentId?: string;
		worktreePath?: string;
		worktreeBranch?: string;
	}>;
};
type GitReview = {
	branch: string;
	summary: {
		filesChanged: number;
		changedLines: number;
		added: number;
		deleted: number;
		sensitiveFiles: number;
	};
	risk: {
		score: number;
		level: string;
		reasons: string[];
		mergeAllowed: boolean;
	};
	files: Array<{
		path: string;
		category: string;
		sensitive: boolean;
		symbols: string[];
	}>;
};
type Snapshot = {
	profile: {
		workspaceRoot: string;
		name: string;
		isGitRepository: boolean;
		branch?: string;
		languages: Array<{ language: string; files: number }>;
		packageManagers: string[];
		buildCommands: string[];
		testCommands: string[];
		ciProviders: string[];
		sensitivePaths: string[];
	};
	policy: {
		defaultTier: string;
		network: string;
		maxRuntimeMinutes: number;
		maxProcesses: number;
		requireSandboxFor: string[];
		requireWorktreeForWrites: boolean;
		requireIndependentReview: boolean;
	};
	missions: Mission[];
	health: {
		durableState: boolean;
		journalMode: string;
		recovery: string;
		normalChatIsolation: boolean;
		activeMissions: number;
		securityPosture: string;
	};
};

const PILLARS = [
	[
		"Secure execution",
		"Request-bound policy decisions, denied-by-default networking, sandbox and VM tiers.",
	],
	[
		"Parallel agents",
		"Dependency-aware missions with isolated worktrees for every repository-writing role.",
	],
	[
		"Git review",
		"Transparent risk scoring, independent review, evidence gates, and protected merge candidates.",
	],
	[
		"Model intelligence",
		"Capability and outcome-driven routing without replacing your selected provider.",
	],
	[
		"Reliability",
		"SQLite WAL state, restart recovery, bounded work, and an auditable event trail.",
	],
] as const;

export function EngineeringWorkspace({
	onLaunchTask,
}: {
	onLaunchTask?: (request: { title: string; prompt: string }) => void;
}) {
	const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
	const [review, setReview] = useState<GitReview | null>(null);
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);
	const selection = readWorkspaceSelectionFromWindow(
		LOCAL_WORKSPACE_ENVIRONMENT_ID,
	);
	const cwd = selection.lastWorkspace || selection.workspaces[0] || "";
	const refresh = useCallback(async () => {
		if (!cwd) {
			setLoading(false);
			setSnapshot(null);
			return;
		}
		setLoading(true);
		setError(null);
		try {
			setSnapshot(
				await desktopClient.invoke<Snapshot>("get_engineering_workspace", {
					cwd,
				}),
			);
		} catch (value) {
			setError(value instanceof Error ? value.message : String(value));
		} finally {
			setLoading(false);
		}
	}, [cwd]);
	useEffect(() => {
		void refresh();
	}, [refresh]);

	const planMission = useCallback(async () => {
		if (!cwd) return;
		setLoading(true);
		setError(null);
		try {
			await desktopClient.invoke("plan_engineering_mission", {
				cwd,
				title: "Advanced engineering upgrade",
				objective:
					"Plan, implement, test, independently review, and prepare a protected merge candidate in isolated worktrees.",
			});
			await refresh();
		} catch (value) {
			setError(value instanceof Error ? value.message : String(value));
			setLoading(false);
		}
	}, [cwd, refresh]);

	const refreshReview = useCallback(async () => {
		if (!cwd) return;
		setLoading(true);
		setError(null);
		try {
			setReview(
				await desktopClient.invoke<GitReview>("get_engineering_git_review", {
					cwd,
					base: "HEAD",
				}),
			);
		} catch (value) {
			setError(value instanceof Error ? value.message : String(value));
		} finally {
			setLoading(false);
		}
	}, [cwd]);

	const prepareAgentDrafts = useCallback(
		async (mission: Mission) => {
			if (!cwd || !onLaunchTask) return;
			setLoading(true);
			setError(null);
			const agentIds = Array.from(
				{ length: 4 },
				(_, index) => `desktop-agent-${Date.now()}-${index + 1}`,
			);
			try {
				const updated = await desktopClient.invoke<Mission>(
					"claim_engineering_tasks",
					{ cwd, missionId: mission.id, agentIds },
				);
				const claimed = updated.tasks.filter(
					(task) =>
						task.status === "running" &&
						task.ownerAgentId &&
						agentIds.includes(task.ownerAgentId),
				);
				for (const task of claimed) {
					const executionRoot = task.worktreePath || cwd;
					onLaunchTask({
						title: `${mission.title}: ${task.label}`,
						prompt: `You are the ${task.role} assigned to engineering mission ${mission.id}.

Task: ${task.label}
Project root: ${executionRoot}
${task.worktreeBranch ? `Managed worktree branch: ${task.worktreeBranch}` : "This is a read-only or coordination task; do not modify repository files unless the user explicitly changes the task."}

Follow the current Cline permission profile and all tool approval boundaries. Work only on this assigned task. Run focused validation, report exact evidence, and do not merge, push, contact Notion, or operate outside the project without explicit approval.

When finished, summarize changed files, commands/tests, remaining risk, and whether the task is ready for independent review.`,
					});
				}
				await refresh();
			} catch (value) {
				setError(value instanceof Error ? value.message : String(value));
				setLoading(false);
			}
		},
		[cwd, onLaunchTask, refresh],
	);

	return (
		<div className="h-full overflow-y-auto bg-background">
			<div className="mx-auto flex w-full max-w-6xl flex-col gap-6 px-6 py-8">
				<header className="flex flex-wrap items-start justify-between gap-4">
					<div>
						<div className="mb-2 flex items-center gap-2 text-sm font-medium text-primary">
							<Sparkles className="size-4" />
							Advanced workspace
						</div>
						<h1 className="text-3xl font-semibold tracking-tight">
							Engineering Control Center
						</h1>
						<p className="mt-2 max-w-3xl text-sm text-muted-foreground">
							A separate, policy-governed workspace for agents, Git review,
							secure execution, model routing, Notion intelligence, and
							analysis. Normal Cline chat remains unchanged.
						</p>
					</div>
					<div className="flex gap-2">
						<Button
							disabled={loading || !cwd || !snapshot?.profile.isGitRepository}
							onClick={() => void refreshReview()}
							variant="outline"
						>
							<GitCompare className="size-4" />
							Review changes
						</Button>
						<Button
							disabled={loading || !cwd}
							onClick={() => void refresh()}
							variant="outline"
						>
							<RefreshCw
								className={loading ? "size-4 animate-spin" : "size-4"}
							/>
							Refresh
						</Button>
						<Button
							disabled={loading || !cwd}
							onClick={() => void planMission()}
						>
							<Bot className="size-4" />
							Plan mission
						</Button>
					</div>
				</header>
				{!cwd ? (
					<Card>
						<CardHeader>
							<CardTitle>Open a project first</CardTitle>
							<CardDescription>
								Select a local workspace in Chat. Engineering Control Center
								never changes your normal chat mode or sends project data to
								Notion automatically.
							</CardDescription>
						</CardHeader>
					</Card>
				) : null}
				{error ? (
					<div className="flex items-center gap-2 rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
						<TriangleAlert className="size-4" />
						{error}
					</div>
				) : null}
				{loading && !snapshot ? (
					<div className="flex min-h-48 items-center justify-center">
						<Loader2 className="size-6 animate-spin text-muted-foreground" />
					</div>
				) : null}
				{snapshot ? (
					<>
						<section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
							<Card>
								<CardHeader className="pb-3">
									<CardDescription>Project</CardDescription>
									<CardTitle className="truncate text-lg">
										{snapshot.profile.name}
									</CardTitle>
								</CardHeader>
								<CardContent className="space-y-2 text-sm">
									<div className="flex items-center gap-2">
										<GitBranch className="size-4" />
										{snapshot.profile.branch ||
											(snapshot.profile.isGitRepository
												? "Detached"
												: "No Git")}
									</div>
									<div className="flex flex-wrap gap-1">
										{snapshot.profile.languages.slice(0, 4).map((item) => (
											<Badge key={item.language} variant="secondary">
												{item.language} · {item.files}
											</Badge>
										))}
									</div>
								</CardContent>
							</Card>
							<Card>
								<CardHeader className="pb-3">
									<CardDescription>Security posture</CardDescription>
									<CardTitle className="flex items-center gap-2 text-lg">
										<ShieldCheck className="size-5 text-emerald-500" />
										{snapshot.health.securityPosture}
									</CardTitle>
								</CardHeader>
								<CardContent className="space-y-1 text-sm text-muted-foreground">
									<p>Network: {snapshot.policy.network}</p>
									<p>Default tier: {snapshot.policy.defaultTier}</p>
									<p>
										{snapshot.policy.maxRuntimeMinutes} min /{" "}
										{snapshot.policy.maxProcesses} processes
									</p>
								</CardContent>
							</Card>
							<Card>
								<CardHeader className="pb-3">
									<CardDescription>Durable control plane</CardDescription>
									<CardTitle className="flex items-center gap-2 text-lg">
										<CheckCircle2 className="size-5 text-emerald-500" />
										Healthy
									</CardTitle>
								</CardHeader>
								<CardContent className="space-y-1 text-sm text-muted-foreground">
									<p>SQLite {snapshot.health.journalMode}</p>
									<p>Recovery {snapshot.health.recovery}</p>
									<p>Normal chat isolated</p>
								</CardContent>
							</Card>
							<Card>
								<CardHeader className="pb-3">
									<CardDescription>Agent missions</CardDescription>
									<CardTitle className="flex items-center gap-2 text-lg">
										<Route className="size-5" />
										{snapshot.health.activeMissions} active
									</CardTitle>
								</CardHeader>
								<CardContent className="text-sm text-muted-foreground">
									Repository-writing agents are assigned isolated worktrees and
									independent review gates.
								</CardContent>
							</Card>
						</section>
						<section className="grid gap-4 lg:grid-cols-5">
							{PILLARS.map(([title, description]) => (
								<Card key={title}>
									<CardHeader>
										<CardTitle className="text-base">{title}</CardTitle>
										<CardDescription>{description}</CardDescription>
									</CardHeader>
								</Card>
							))}
						</section>
						{review ? (
							<Card>
								<CardHeader>
									<div className="flex flex-wrap items-center justify-between gap-3">
										<div>
											<CardTitle>Git review evidence</CardTitle>
											<CardDescription>
												Deterministic local evidence for{" "}
												{review.branch || "detached HEAD"}.
											</CardDescription>
										</div>
										<Badge
											variant={
												review.risk.mergeAllowed ? "secondary" : "destructive"
											}
										>
											{review.risk.level} risk · {review.risk.score}/100
										</Badge>
									</div>
								</CardHeader>
								<CardContent className="space-y-3">
									<div className="flex flex-wrap gap-2 text-sm text-muted-foreground">
										<span>{review.summary.filesChanged} files</span>
										<span>+{review.summary.added}</span>
										<span>−{review.summary.deleted}</span>
										<span>{review.summary.sensitiveFiles} sensitive</span>
									</div>
									{review.risk.reasons.length ? (
										<ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
											{review.risk.reasons.map((reason) => (
												<li key={reason}>{reason}</li>
											))}
										</ul>
									) : (
										<p className="text-sm text-muted-foreground">
											No deterministic risk flags detected.
										</p>
									)}
									<div className="grid gap-2 md:grid-cols-2">
										{review.files.slice(0, 12).map((file) => (
											<div
												className="rounded-md border p-2 text-sm"
												key={file.path}
											>
												<div className="flex items-center justify-between gap-2">
													<span className="truncate font-medium">
														{file.path}
													</span>
													<Badge variant="outline">{file.category}</Badge>
												</div>
												{file.symbols.length ? (
													<p className="mt-1 truncate text-xs text-muted-foreground">
														{file.symbols.slice(0, 5).join(" · ")}
													</p>
												) : null}
											</div>
										))}
									</div>
								</CardContent>
							</Card>
						) : null}
						<section className="grid gap-4 lg:grid-cols-[1.3fr_1fr]">
							<Card>
								<CardHeader>
									<CardTitle>Mission queue</CardTitle>
									<CardDescription>
										Plans are durable and dependency-aware. Planning does not
										execute commands or merge code.
									</CardDescription>
								</CardHeader>
								<CardContent className="space-y-3">
									{snapshot.missions.length === 0 ? (
										<p className="text-sm text-muted-foreground">
											No engineering mission has been planned for this
											workspace.
										</p>
									) : (
										snapshot.missions.slice(0, 8).map((mission) => (
											<div className="rounded-lg border p-3" key={mission.id}>
												<div className="flex items-center justify-between gap-3">
													<span className="font-medium">{mission.title}</span>
													<Badge variant="outline">{mission.status}</Badge>
												</div>
												<div className="mt-2 flex flex-wrap gap-1">
													{mission.tasks.map((task) => (
														<Badge
															key={task.id}
															variant={
																task.requiresWorktree ? "default" : "secondary"
															}
														>
															{task.role}
															{task.requiresWorktree ? " · worktree" : ""}
														</Badge>
													))}
												</div>
												<Button
													className="mt-3"
													disabled={
														loading ||
														!onLaunchTask ||
														!["planned", "running", "interrupted"].includes(
															mission.status,
														)
													}
													onClick={() => void prepareAgentDrafts(mission)}
													size="sm"
													variant="outline"
												>
													<Bot className="size-4" />
													Prepare next agent drafts
												</Button>
											</div>
										))
									)}
								</CardContent>
							</Card>
							<Card>
								<CardHeader>
									<CardTitle>Detected project controls</CardTitle>
									<CardDescription>
										Local-only discovery used to ground agents and select
										validation commands.
									</CardDescription>
								</CardHeader>
								<CardContent className="space-y-3 text-sm">
									<div>
										<p className="font-medium">Package managers</p>
										<p className="text-muted-foreground">
											{snapshot.profile.packageManagers.join(", ") ||
												"None detected"}
										</p>
									</div>
									<div>
										<p className="font-medium">CI</p>
										<p className="text-muted-foreground">
											{snapshot.profile.ciProviders.join(", ") ||
												"None detected"}
										</p>
									</div>
									<div>
										<p className="font-medium">Validation commands</p>
										<p className="text-muted-foreground">
											{[
												...snapshot.profile.buildCommands,
												...snapshot.profile.testCommands,
											]
												.slice(0, 5)
												.join(" · ") || "No package scripts detected"}
										</p>
									</div>
									<div>
										<p className="font-medium">Sensitive paths</p>
										<p className="text-muted-foreground">
											{snapshot.profile.sensitivePaths.length
												? `${snapshot.profile.sensitivePaths.length} detected and protected`
												: "No known sensitive root files detected"}
										</p>
									</div>
								</CardContent>
							</Card>
						</section>
					</>
				) : null}
			</div>
		</div>
	);
}
