import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import type { Dirent } from "node:fs";
import {
	existsSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	statSync,
} from "node:fs";
import { dirname, extname, join, resolve } from "node:path";
import { loadSqliteDb, type SqliteDb } from "@cline/shared/db";

export type ExecutionTier =
	| "read-only"
	| "restricted"
	| "sandbox"
	| "isolated-vm";
export type NetworkPolicy = "deny" | "allow-approved-hosts" | "allow";
export type EngineeringPolicy = {
	defaultTier: ExecutionTier;
	network: NetworkPolicy;
	maxRuntimeMinutes: number;
	maxProcesses: number;
	requireSandboxFor: string[];
	protectedPathKinds: string[];
	requireWorktreeForWrites: boolean;
	requireIndependentReview: boolean;
};

export const DEFAULT_ENGINEERING_POLICY: EngineeringPolicy = {
	defaultTier: "restricted",
	network: "deny",
	maxRuntimeMinutes: 20,
	maxProcesses: 32,
	requireSandboxFor: [
		"unknown-binary",
		"debugger",
		"package-install",
		"untrusted-script",
	],
	protectedPathKinds: ["credentials", "browser-data", "ssh", "user-profile"],
	requireWorktreeForWrites: true,
	requireIndependentReview: true,
};

export type ProjectProfile = {
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
	detectedAt: string;
};

export type EngineeringTask = {
	id: string;
	label: string;
	role:
		| "planner"
		| "explorer"
		| "implementer"
		| "tester"
		| "debugger"
		| "reviewer"
		| "security"
		| "documentation"
		| "reverse-engineer"
		| "merge-coordinator";
	dependsOn: string[];
	writesRepository: boolean;
	requiresWorktree: boolean;
	status:
		| "queued"
		| "running"
		| "blocked"
		| "review"
		| "completed"
		| "failed"
		| "cancelled"
		| "interrupted";
	ownerAgentId?: string;
	worktreePath?: string;
	worktreeBranch?: string;
	startedAt?: string;
	completedAt?: string;
	resultSummary?: string;
};

export type EngineeringMission = {
	id: string;
	workspaceRoot: string;
	title: string;
	objective: string;
	status:
		| "planned"
		| "running"
		| "review"
		| "completed"
		| "failed"
		| "cancelled"
		| "interrupted";
	tasks: EngineeringTask[];
	createdAt: string;
	updatedAt: string;
};

export type ModelCandidate = {
	id: string;
	provider: string;
	capabilities: string[];
	contextWindow: number;
	costPerMillionTokens?: number;
	latencyMs?: number;
	successRate?: number;
	toolReliability?: number;
	sampleCount?: number;
};

const LANGUAGE_BY_EXTENSION: Record<string, string> = {
	".c": "C",
	".cc": "C++",
	".cpp": "C++",
	".cs": "C#",
	".go": "Go",
	".java": "Java",
	".js": "JavaScript",
	".jsx": "JavaScript",
	".kt": "Kotlin",
	".py": "Python",
	".rs": "Rust",
	".swift": "Swift",
	".ts": "TypeScript",
	".tsx": "TypeScript",
};
const PROFILE_IGNORES = new Set([
	".git",
	".next",
	".turbo",
	"build",
	"coverage",
	"dist",
	"node_modules",
	"target",
	"vendor",
]);
const ENGINEERING_ROLES = new Set<EngineeringTask["role"]>([
	"planner",
	"explorer",
	"implementer",
	"tester",
	"debugger",
	"reviewer",
	"security",
	"documentation",
	"reverse-engineer",
	"merge-coordinator",
]);

function safeGit(root: string, args: string[]): string | undefined {
	try {
		return (
			execFileSync("git", ["-C", root, ...args], {
				encoding: "utf8",
				timeout: 2_000,
				windowsHide: true,
				stdio: ["ignore", "pipe", "ignore"],
			}).trim() || undefined
		);
	} catch {
		return undefined;
	}
}

function readPackageScripts(root: string): { build: string[]; test: string[] } {
	try {
		const parsed = JSON.parse(
			readFileSync(join(root, "package.json"), "utf8"),
		) as { scripts?: Record<string, unknown> };
		const names = Object.keys(parsed.scripts ?? {});
		return {
			build: names
				.filter((name) => name === "build" || name.startsWith("build:"))
				.map((name) => `bun run ${name}`)
				.slice(0, 8),
			test: names
				.filter((name) => name === "test" || name.startsWith("test:"))
				.map((name) => `bun run ${name}`)
				.slice(0, 12),
		};
	} catch {
		return { build: [], test: [] };
	}
}

export function detectProjectProfile(workspaceRoot: string): ProjectProfile {
	const root = resolve(workspaceRoot);
	if (!existsSync(root) || !statSync(root).isDirectory())
		throw new Error(`Workspace directory not found: ${root}`);
	const languageCounts = new Map<string, number>();
	const pending = [root];
	let scanned = 0;
	while (pending.length > 0 && scanned < 10_000) {
		const directory = pending.pop();
		if (!directory) break;
		let entries: Dirent[];
		try {
			entries = readdirSync(directory, { withFileTypes: true });
		} catch {
			continue;
		}
		for (const entry of entries) {
			if (entry.isDirectory()) {
				if (!PROFILE_IGNORES.has(entry.name) && !entry.name.startsWith("."))
					pending.push(join(directory, entry.name));
				continue;
			}
			if (!entry.isFile()) continue;
			scanned += 1;
			const language = LANGUAGE_BY_EXTENSION[extname(entry.name).toLowerCase()];
			if (language)
				languageCounts.set(language, (languageCounts.get(language) ?? 0) + 1);
			if (scanned >= 10_000) break;
		}
	}
	const managers = [
		["bun.lock", "Bun"],
		["pnpm-lock.yaml", "pnpm"],
		["yarn.lock", "Yarn"],
		["package-lock.json", "npm"],
		["Cargo.lock", "Cargo"],
		["uv.lock", "uv"],
		["poetry.lock", "Poetry"],
		["go.mod", "Go modules"],
	] as const;
	const ciProviders: string[] = [];
	if (existsSync(join(root, ".github", "workflows")))
		ciProviders.push("GitHub Actions");
	if (existsSync(join(root, ".gitlab-ci.yml"))) ciProviders.push("GitLab CI");
	if (existsSync(join(root, "azure-pipelines.yml")))
		ciProviders.push("Azure Pipelines");
	const sensitive = [
		".env",
		".env.local",
		".npmrc",
		".pypirc",
		".ssh",
		"credentials.json",
	].filter((path) => existsSync(join(root, path)));
	const scripts = readPackageScripts(root);
	const gitRoot = safeGit(root, ["rev-parse", "--show-toplevel"]);
	return {
		workspaceRoot: root,
		name: root.split(/[\\/]/).filter(Boolean).at(-1) ?? "workspace",
		isGitRepository: Boolean(gitRoot),
		branch: gitRoot ? safeGit(root, ["branch", "--show-current"]) : undefined,
		languages: [...languageCounts.entries()]
			.map(([language, files]) => ({ language, files }))
			.sort((a, b) => b.files - a.files),
		packageManagers: managers
			.filter(([file]) => existsSync(join(root, file)))
			.map(([, label]) => label),
		buildCommands: scripts.build,
		testCommands: scripts.test,
		ciProviders,
		sensitivePaths: sensitive,
		detectedAt: new Date().toISOString(),
	};
}

function parsePolicy(value: unknown): EngineeringPolicy {
	const input =
		value && typeof value === "object" && !Array.isArray(value)
			? (value as Partial<EngineeringPolicy>)
			: {};
	const tier = ["read-only", "restricted", "sandbox", "isolated-vm"].includes(
		String(input.defaultTier),
	)
		? (input.defaultTier as ExecutionTier)
		: DEFAULT_ENGINEERING_POLICY.defaultTier;
	const network = ["deny", "allow-approved-hosts", "allow"].includes(
		String(input.network),
	)
		? (input.network as NetworkPolicy)
		: DEFAULT_ENGINEERING_POLICY.network;
	return {
		...DEFAULT_ENGINEERING_POLICY,
		...input,
		defaultTier: tier,
		network,
		maxRuntimeMinutes: Math.min(
			240,
			Math.max(
				1,
				Number(
					input.maxRuntimeMinutes ??
						DEFAULT_ENGINEERING_POLICY.maxRuntimeMinutes,
				),
			),
		),
		maxProcesses: Math.min(
			256,
			Math.max(
				1,
				Number(input.maxProcesses ?? DEFAULT_ENGINEERING_POLICY.maxProcesses),
			),
		),
		requireSandboxFor: Array.isArray(input.requireSandboxFor)
			? input.requireSandboxFor.map(String).filter(Boolean)
			: [...DEFAULT_ENGINEERING_POLICY.requireSandboxFor],
		protectedPathKinds: Array.isArray(input.protectedPathKinds)
			? input.protectedPathKinds.map(String).filter(Boolean)
			: [...DEFAULT_ENGINEERING_POLICY.protectedPathKinds],
	};
}

function parseJson(value: unknown): unknown {
	if (typeof value !== "string") return undefined;
	try {
		return JSON.parse(value);
	} catch {
		return undefined;
	}
}

function ensureSchema(db: SqliteDb): void {
	db.exec(
		"PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;",
	);
	db.exec(`
		CREATE TABLE IF NOT EXISTS engineering_projects (
			workspace_key TEXT PRIMARY KEY, workspace_root TEXT NOT NULL, profile_json TEXT NOT NULL,
			policy_json TEXT NOT NULL, updated_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS engineering_missions (
			id TEXT PRIMARY KEY, workspace_key TEXT NOT NULL, title TEXT NOT NULL, objective TEXT NOT NULL,
			status TEXT NOT NULL, tasks_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS engineering_missions_workspace ON engineering_missions(workspace_key, updated_at DESC);
		CREATE TABLE IF NOT EXISTS engineering_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT, workspace_key TEXT NOT NULL, mission_id TEXT,
			type TEXT NOT NULL, payload_json TEXT NOT NULL, created_at TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS engineering_events_workspace ON engineering_events(workspace_key, id DESC);
		CREATE TABLE IF NOT EXISTS engineering_model_outcomes (
			id INTEGER PRIMARY KEY AUTOINCREMENT, workspace_key TEXT NOT NULL, model_id TEXT NOT NULL,
			task_kind TEXT NOT NULL, success INTEGER NOT NULL, duration_ms INTEGER, cost_usd REAL, created_at TEXT NOT NULL
		);
	`);
}

function workspaceKey(root: string): string {
	return createHash("sha256")
		.update(
			process.platform === "win32"
				? resolve(root).toLowerCase()
				: resolve(root),
		)
		.digest("hex");
}

export class EngineeringControlPlane {
	private db?: SqliteDb;
	constructor(private readonly dbPath: string) {}
	private database(): SqliteDb {
		if (!this.db) {
			mkdirSync(dirname(this.dbPath), { recursive: true });
			this.db = loadSqliteDb(this.dbPath);
			ensureSchema(this.db);
		}
		return this.db;
	}
	close(): void {
		this.db?.close?.();
		this.db = undefined;
	}

	getWorkspace(workspaceRoot: string): {
		profile: ProjectProfile;
		policy: EngineeringPolicy;
		missions: EngineeringMission[];
		health: Record<string, unknown>;
	} {
		const profile = detectProjectProfile(workspaceRoot);
		const key = workspaceKey(profile.workspaceRoot);
		const db = this.database();
		const existing = db
			.prepare(
				"SELECT policy_json FROM engineering_projects WHERE workspace_key = ?",
			)
			.get(key) as { policy_json?: string } | undefined;
		const policy = parsePolicy(parseJson(existing?.policy_json));
		const now = new Date().toISOString();
		db.prepare(`INSERT INTO engineering_projects (workspace_key, workspace_root, profile_json, policy_json, updated_at)
			VALUES (?, ?, ?, ?, ?) ON CONFLICT(workspace_key) DO UPDATE SET workspace_root=excluded.workspace_root, profile_json=excluded.profile_json, updated_at=excluded.updated_at`).run(
			key,
			profile.workspaceRoot,
			JSON.stringify(profile),
			JSON.stringify(policy),
			now,
		);
		const rows = db
			.prepare(
				"SELECT * FROM engineering_missions WHERE workspace_key = ? ORDER BY updated_at DESC LIMIT 50",
			)
			.all(key) as Array<Record<string, unknown>>;
		const missions = rows.map((row) =>
			this.rowToMission(row, profile.workspaceRoot),
		);
		return {
			profile,
			policy,
			missions,
			health: {
				durableState: true,
				journalMode: "WAL",
				recovery: "enabled",
				normalChatIsolation: true,
				activeMissions: missions.filter((mission) =>
					["planned", "running", "review"].includes(mission.status),
				).length,
				securityPosture:
					policy.network === "deny" && policy.requireWorktreeForWrites
						? "hardened"
						: "custom",
			},
		};
	}

	updatePolicy(workspaceRoot: string, value: unknown): EngineeringPolicy {
		const snapshot = this.getWorkspace(workspaceRoot);
		const changes =
			value && typeof value === "object" && !Array.isArray(value) ? value : {};
		const policy = parsePolicy({ ...snapshot.policy, ...changes });
		const key = workspaceKey(workspaceRoot);
		this.database()
			.prepare(
				"UPDATE engineering_projects SET policy_json = ?, updated_at = ? WHERE workspace_key = ?",
			)
			.run(JSON.stringify(policy), new Date().toISOString(), key);
		this.recordEvent(key, undefined, "policy.updated", policy);
		return policy;
	}

	planMission(
		workspaceRoot: string,
		input: { title?: unknown; objective?: unknown; tasks?: unknown },
	): EngineeringMission {
		this.getWorkspace(workspaceRoot);
		const title =
			String(input.title ?? "Engineering mission")
				.trim()
				.slice(0, 160) || "Engineering mission";
		const objective =
			String(input.objective ?? title)
				.trim()
				.slice(0, 4_000) || title;
		const rawTasks = Array.isArray(input.tasks) ? input.tasks : [];
		const tasks: EngineeringTask[] = (
			rawTasks.length > 0
				? rawTasks
				: [
						{
							id: "plan",
							label: "Plan and map repository",
							role: "planner",
							dependsOn: [],
							writesRepository: false,
						},
						{
							id: "implement",
							label: "Implement in isolated worktree",
							role: "implementer",
							dependsOn: ["plan"],
							writesRepository: true,
						},
						{
							id: "test",
							label: "Run focused and regression tests",
							role: "tester",
							dependsOn: ["implement"],
							writesRepository: false,
						},
						{
							id: "review",
							label: "Independent security and correctness review",
							role: "reviewer",
							dependsOn: ["test"],
							writesRepository: false,
						},
						{
							id: "merge",
							label: "Prepare reviewed merge candidate",
							role: "merge-coordinator",
							dependsOn: ["review"],
							writesRepository: true,
						},
					]
		).map((value, index) => {
			const task =
				value && typeof value === "object"
					? (value as Record<string, unknown>)
					: {};
			const writesRepository = task.writesRepository === true;
			return {
				id: String(task.id ?? `task-${index + 1}`).trim(),
				label: String(task.label ?? `Task ${index + 1}`).trim(),
				role: ENGINEERING_ROLES.has(
					String(task.role ?? "implementer") as EngineeringTask["role"],
				)
					? (String(task.role ?? "implementer") as EngineeringTask["role"])
					: "implementer",
				dependsOn: Array.isArray(task.dependsOn)
					? task.dependsOn.map(String)
					: [],
				writesRepository,
				requiresWorktree: writesRepository,
				status: "queued" as const,
			};
		});
		const ids = new Set(tasks.map((task) => task.id));
		if (ids.size !== tasks.length || tasks.some((task) => !task.id))
			throw new Error("Mission task ids must be unique and non-empty");
		if (
			tasks.some((task) =>
				task.dependsOn.some(
					(dependency) => !ids.has(dependency) || dependency === task.id,
				),
			)
		)
			throw new Error(
				"Mission dependencies must reference another task in the mission",
			);
		const visiting = new Set<string>();
		const visited = new Set<string>();
		const visit = (id: string) => {
			if (visiting.has(id))
				throw new Error("Mission task graph contains a cycle");
			if (visited.has(id)) return;
			visiting.add(id);
			const task = tasks.find((candidate) => candidate.id === id);
			for (const dependency of task?.dependsOn ?? []) visit(dependency);
			visiting.delete(id);
			visited.add(id);
		};
		for (const task of tasks) visit(task.id);
		const now = new Date().toISOString();
		const mission: EngineeringMission = {
			id: `mission_${randomUUID()}`,
			workspaceRoot: resolve(workspaceRoot),
			title,
			objective,
			status: "planned",
			tasks,
			createdAt: now,
			updatedAt: now,
		};
		const key = workspaceKey(workspaceRoot);
		this.database()
			.prepare(
				"INSERT INTO engineering_missions (id, workspace_key, title, objective, status, tasks_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			)
			.run(
				mission.id,
				key,
				title,
				objective,
				mission.status,
				JSON.stringify(tasks),
				now,
				now,
			);
		this.recordEvent(key, mission.id, "mission.planned", {
			title,
			taskCount: tasks.length,
		});
		return mission;
	}

	getMission(workspaceRoot: string, missionId: string): EngineeringMission {
		const mission = this.getWorkspace(workspaceRoot).missions.find(
			(candidate) => candidate.id === missionId,
		);
		if (!mission)
			throw new Error(`Engineering mission not found: ${missionId}`);
		return mission;
	}

	claimReadyTasks(
		workspaceRoot: string,
		missionId: string,
		agentIds: string[],
	): { mission: EngineeringMission; claimed: EngineeringTask[] } {
		const mission = this.getMission(workspaceRoot, missionId);
		if (!["planned", "running", "interrupted"].includes(mission.status)) {
			throw new Error(`Mission cannot be started from ${mission.status}`);
		}
		const availableAgents = agentIds
			.map((value) => value.trim())
			.filter(Boolean)
			.slice(0, 16);
		if (availableAgents.length === 0) {
			throw new Error("At least one agent id is required");
		}
		const completed = new Set(
			mission.tasks
				.filter((task) => task.status === "completed")
				.map((task) => task.id),
		);
		const ready = mission.tasks.filter(
			(task) =>
				task.status === "queued" &&
				task.dependsOn.every((dependency) => completed.has(dependency)),
		);
		const now = new Date().toISOString();
		const claimed: EngineeringTask[] = [];
		for (const [index, task] of ready
			.slice(0, availableAgents.length)
			.entries()) {
			task.status = "running";
			task.ownerAgentId = availableAgents[index];
			task.startedAt = now;
			claimed.push(task);
		}
		if (claimed.length === 0) {
			return { mission, claimed };
		}
		mission.status = "running";
		mission.updatedAt = now;
		this.persistMission(mission);
		this.recordEvent(workspaceKey(workspaceRoot), mission.id, "tasks.claimed", {
			tasks: claimed.map((task) => ({
				id: task.id,
				agentId: task.ownerAgentId,
				requiresWorktree: task.requiresWorktree,
			})),
		});
		return { mission, claimed };
	}

	updateMissionTask(
		workspaceRoot: string,
		missionId: string,
		input: {
			taskId: string;
			agentId: string;
			status: "completed" | "failed" | "blocked" | "cancelled";
			resultSummary?: string;
			worktreePath?: string;
			worktreeBranch?: string;
		},
	): EngineeringMission {
		if (
			!["completed", "failed", "blocked", "cancelled"].includes(input.status)
		) {
			throw new Error("Unsupported engineering task transition");
		}
		const mission = this.getMission(workspaceRoot, missionId);
		const task = mission.tasks.find(
			(candidate) => candidate.id === input.taskId,
		);
		if (!task) throw new Error(`Mission task not found: ${input.taskId}`);
		if (task.status !== "running" && input.status !== "cancelled") {
			throw new Error(`Task cannot transition from ${task.status}`);
		}
		if (!task.ownerAgentId || task.ownerAgentId !== input.agentId.trim()) {
			throw new Error("Only the agent that claimed the task may update it");
		}
		if (
			task.requiresWorktree &&
			input.status === "completed" &&
			!(input.worktreePath?.trim() || task.worktreePath)
		) {
			throw new Error("Repository-writing tasks require worktree evidence");
		}
		task.status = input.status;
		task.resultSummary = input.resultSummary?.trim().slice(0, 4_000);
		task.worktreePath = input.worktreePath?.trim() || task.worktreePath;
		task.worktreeBranch = input.worktreeBranch?.trim() || task.worktreeBranch;
		task.completedAt = new Date().toISOString();
		const statuses = new Set(
			mission.tasks.map((candidate) => candidate.status),
		);
		mission.status = statuses.has("failed")
			? "failed"
			: mission.tasks.every((candidate) =>
						["completed", "cancelled"].includes(candidate.status),
					)
				? "review"
				: "running";
		mission.updatedAt = task.completedAt;
		this.persistMission(mission);
		this.recordEvent(workspaceKey(workspaceRoot), mission.id, "task.updated", {
			taskId: task.id,
			agentId: input.agentId,
			status: task.status,
		});
		return mission;
	}

	setTaskWorktree(
		workspaceRoot: string,
		missionId: string,
		taskId: string,
		agentId: string,
		worktree: { path: string; branch: string },
	): EngineeringMission {
		const mission = this.getMission(workspaceRoot, missionId);
		const task = mission.tasks.find((candidate) => candidate.id === taskId);
		if (!task) throw new Error(`Mission task not found: ${taskId}`);
		if (
			task.status !== "running" ||
			task.ownerAgentId !== agentId ||
			!task.requiresWorktree
		) {
			throw new Error(
				"Worktree assignment does not match a claimed writer task",
			);
		}
		task.worktreePath = worktree.path;
		task.worktreeBranch = worktree.branch;
		mission.updatedAt = new Date().toISOString();
		this.persistMission(mission);
		this.recordEvent(
			workspaceKey(workspaceRoot),
			mission.id,
			"task.worktree-assigned",
			{ taskId, agentId, branch: worktree.branch },
		);
		return mission;
	}

	recoverInterrupted(): number {
		const db = this.database();
		const rows = db
			.prepare(
				"SELECT id, workspace_key FROM engineering_missions WHERE status = 'running'",
			)
			.all() as Array<{ id: string; workspace_key: string }>;
		const now = new Date().toISOString();
		for (const row of rows) {
			db.prepare(
				"UPDATE engineering_missions SET status = 'interrupted', updated_at = ? WHERE id = ?",
			).run(now, row.id);
			this.recordEvent(row.workspace_key, row.id, "mission.interrupted", {
				reason: "sidecar-restart",
			});
		}
		return rows.length;
	}

	recordModelOutcome(
		workspaceRoot: string,
		input: {
			modelId: string;
			taskKind: string;
			success: boolean;
			durationMs?: number;
			costUsd?: number;
		},
	): void {
		this.database()
			.prepare(
				"INSERT INTO engineering_model_outcomes (workspace_key, model_id, task_kind, success, duration_ms, cost_usd, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			)
			.run(
				workspaceKey(workspaceRoot),
				input.modelId,
				input.taskKind,
				input.success ? 1 : 0,
				input.durationMs ?? null,
				input.costUsd ?? null,
				new Date().toISOString(),
			);
	}

	private rowToMission(
		row: Record<string, unknown>,
		workspaceRoot: string,
	): EngineeringMission {
		const tasks = parseJson(row.tasks_json);
		return {
			id: String(row.id),
			workspaceRoot,
			title: String(row.title),
			objective: String(row.objective),
			status: String(row.status) as EngineeringMission["status"],
			tasks: Array.isArray(tasks) ? (tasks as EngineeringTask[]) : [],
			createdAt: String(row.created_at),
			updatedAt: String(row.updated_at),
		};
	}

	private persistMission(mission: EngineeringMission): void {
		this.database()
			.prepare(
				"UPDATE engineering_missions SET status = ?, tasks_json = ?, updated_at = ? WHERE id = ? AND workspace_key = ?",
			)
			.run(
				mission.status,
				JSON.stringify(mission.tasks),
				mission.updatedAt,
				mission.id,
				workspaceKey(mission.workspaceRoot),
			);
	}
	private recordEvent(
		key: string,
		missionId: string | undefined,
		type: string,
		payload: unknown,
	): void {
		this.database()
			.prepare(
				"INSERT INTO engineering_events (workspace_key, mission_id, type, payload_json, created_at) VALUES (?, ?, ?, ?, ?)",
			)
			.run(
				key,
				missionId ?? null,
				type,
				JSON.stringify(payload),
				new Date().toISOString(),
			);
	}
}

export function evaluateExecutionPolicy(
	policyValue: unknown,
	requestValue: unknown,
) {
	const policy = parsePolicy(policyValue);
	const request =
		requestValue && typeof requestValue === "object"
			? (requestValue as Record<string, unknown>)
			: {};
	const categories = Array.isArray(request.categories)
		? request.categories.map(String)
		: [];
	const writes = request.writes === true;
	const asksNetwork = request.network === true;
	let requiredTier = policy.defaultTier;
	if (
		categories.some((category) => policy.requireSandboxFor.includes(category))
	)
		requiredTier =
			categories.includes("unknown-binary") || categories.includes("debugger")
				? "isolated-vm"
				: "sandbox";
	const reasons: string[] = [];
	if (writes && policy.requireWorktreeForWrites && request.worktree !== true)
		reasons.push("Repository writes require an isolated worktree");
	if (asksNetwork && policy.network === "deny")
		reasons.push("Network access is denied by project policy");
	if (request.protectedPath === true)
		reasons.push("Protected host paths are outside the execution scope");
	if (Number(request.timeoutMinutes ?? 0) > policy.maxRuntimeMinutes)
		reasons.push(
			`Runtime exceeds the ${policy.maxRuntimeMinutes}-minute policy limit`,
		);
	return {
		allowed: reasons.length === 0,
		requiredTier,
		network: policy.network,
		approvalRequired: requiredTier !== "read-only" || writes || asksNetwork,
		reasons,
	};
}

export function scoreReviewRisk(inputValue: unknown) {
	const input =
		inputValue && typeof inputValue === "object"
			? (inputValue as Record<string, unknown>)
			: {};
	let score = 0;
	const reasons: string[] = [];
	const changedLines = Math.max(0, Number(input.changedLines ?? 0));
	if (changedLines > 1_000) {
		score += 25;
		reasons.push("Large change set");
	} else if (changedLines > 300) {
		score += 15;
		reasons.push("Broad change set");
	}
	const sensitiveFiles = Array.isArray(input.sensitiveFiles)
		? input.sensitiveFiles.length
		: 0;
	if (sensitiveFiles) {
		score += Math.min(30, sensitiveFiles * 10);
		reasons.push(`${sensitiveFiles} sensitive file(s) changed`);
	}
	if (input.dependenciesChanged === true) {
		score += 15;
		reasons.push("Dependencies changed");
	}
	if (input.publicApiChanged === true) {
		score += 15;
		reasons.push("Public API changed");
	}
	if (input.migrationsChanged === true) {
		score += 15;
		reasons.push("Migration or schema changed");
	}
	const failedChecks = Math.max(0, Number(input.failedChecks ?? 0));
	if (failedChecks) {
		score += Math.min(30, failedChecks * 10);
		reasons.push(`${failedChecks} check(s) failing`);
	}
	if (input.testsAdded !== true) {
		score += 10;
		reasons.push("No new tests detected");
	}
	score = Math.min(100, score);
	return {
		score,
		level:
			score >= 70
				? "critical"
				: score >= 45
					? "high"
					: score >= 20
						? "medium"
						: "low",
		reasons,
		mergeAllowed: score < 70 && failedChecks === 0,
	};
}

export function routeEngineeringModel(
	taskValue: unknown,
	candidatesValue: unknown,
) {
	const task =
		taskValue && typeof taskValue === "object"
			? (taskValue as Record<string, unknown>)
			: {};
	const candidates = Array.isArray(candidatesValue)
		? (candidatesValue as ModelCandidate[])
		: [];
	if (candidates.length === 0)
		throw new Error("At least one model candidate is required");
	for (const candidate of candidates) {
		if (
			!candidate ||
			typeof candidate.id !== "string" ||
			typeof candidate.provider !== "string" ||
			!Array.isArray(candidate.capabilities) ||
			candidate.capabilities.some((c) => typeof c !== "string") ||
			!Number.isFinite(candidate.contextWindow) ||
			candidate.contextWindow < 0
		)
			throw new Error("Invalid model candidate identity or capabilities");
		for (const value of [candidate.successRate, candidate.toolReliability])
			if (
				value !== undefined &&
				(!Number.isFinite(value) || value < 0 || value > 1)
			)
				throw new Error("Model outcome estimates must be finite rates in 0..1");
		for (const value of [candidate.costPerMillionTokens, candidate.latencyMs])
			if (value !== undefined && (!Number.isFinite(value) || value < 0))
				throw new Error(
					"Model cost and latency estimates must be finite and nonnegative",
				);
	}
	const required = Array.isArray(task.requiredCapabilities)
		? task.requiredCapabilities.map(String)
		: [];
	const mode = task.mode ?? "balanced";
	if (mode !== "economy" && mode !== "balanced" && mode !== "deep")
		throw new Error("Model routing mode must be economy, balanced or deep");
	const manualModelId =
		typeof task.manualModelId === "string" ? task.manualModelId : undefined;
	const minimumContext = Math.max(0, Number(task.minimumContext ?? 0));
	const maxCost =
		task.maxCostPerMillionTokens === undefined
			? undefined
			: Number(task.maxCostPerMillionTokens);
	if (
		!Number.isFinite(minimumContext) ||
		(maxCost !== undefined && (!Number.isFinite(maxCost) || maxCost < 0))
	)
		throw new Error("Invalid model routing budget");
	const ranked = candidates
		.map((candidate) => {
			const missing = required.filter(
				(capability) => !candidate.capabilities.includes(capability),
			);
			let score =
				(candidate.successRate ?? 0.75) * 45 +
				(candidate.toolReliability ?? 0.75) * 35;
			if (candidate.contextWindow >= minimumContext) score += 10;
			else score -= 30;
			score -= Math.min(10, (candidate.latencyMs ?? 2_000) / 1_000);
			score -= Math.min(10, (candidate.costPerMillionTokens ?? 10) / 10);
			score -= missing.length * 40;
			if (mode === "economy") {
				score -= Math.min(40, (candidate.costPerMillionTokens ?? 40) * 2);
				score -= Math.min(20, (candidate.latencyMs ?? 2000) / 500);
			} else if (mode === "deep") {
				score +=
					(candidate.successRate ?? 0.75) * 30 +
					(candidate.toolReliability ?? 0.75) * 30;
			}
			return {
				candidate,
				score: Math.round(score * 100) / 100,
				missingCapabilities: missing,
				eligible:
					missing.length === 0 &&
					Number.isFinite(candidate.contextWindow) &&
					candidate.contextWindow >= minimumContext &&
					(maxCost === undefined ||
						(typeof candidate.costPerMillionTokens === "number" &&
							candidate.costPerMillionTokens >= 0 &&
							candidate.costPerMillionTokens <= maxCost)),
				measurements:
					candidate.sampleCount && candidate.sampleCount >= 20
						? "supplied-measured-outcomes"
						: "estimates-or-low-sample",
				sampleCount: Math.max(0, Math.trunc(candidate.sampleCount ?? 0)),
			};
		})
		.sort((a, b) => b.score - a.score);
	const selected = manualModelId
		? ranked.find(
				(item) => item.eligible && item.candidate.id === manualModelId,
			)?.candidate
		: ranked.find((item) => item.eligible)?.candidate;
	return {
		selected,
		mode,
		manualOverride: Boolean(manualModelId),
		retryPolicy:
			"Routing advice never replays commands or changes the selected chat provider automatically",
		reason: manualModelId
			? selected
				? "Explicit eligible model selected"
				: "Manual model is unavailable or ineligible; no silent fallback"
			: ranked.some((item) => item.eligible)
				? "Highest-ranked eligible model; missing-capability and insufficient-context models cannot be selected"
				: "No eligible model meets the required capabilities and minimum context",
		ranked,
	};
}
