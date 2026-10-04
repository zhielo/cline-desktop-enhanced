import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
	existsSync,
	mkdirSync,
	readFileSync,
	realpathSync,
	renameSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";

export type EngineeringWorktreeLease = {
	id: string;
	missionId: string;
	taskId: string;
	agentId: string;
	repositoryRoot: string;
	path: string;
	branch: string;
	baseRevision: string;
	createdAt: string;
	status: "active" | "kept" | "released";
};

function git(root: string, args: string[]): string {
	return execFileSync("git", ["-C", root, ...args], {
		encoding: "utf8",
		timeout: 30_000,
		windowsHide: true,
		stdio: ["ignore", "pipe", "pipe"],
	}).trim();
}

function slug(value: string): string {
	return (
		value
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, "-")
			.replace(/^-|-$/g, "")
			.slice(0, 36) || "task"
	);
}

function atomicWrite(path: string, value: unknown): void {
	mkdirSync(dirname(path), { recursive: true });
	const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
	writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {
		mode: 0o600,
	});
	renameSync(temporary, path);
}

function canonicalFuturePath(pathValue: string): string {
	let current = resolve(pathValue);
	const missing: string[] = [];
	while (!existsSync(current)) {
		const parent = dirname(current);
		if (parent === current) break;
		missing.unshift(basename(current));
		current = parent;
	}
	const canonicalParent = existsSync(current)
		? realpathSync.native(current)
		: current;
	return resolve(canonicalParent, ...missing);
}

export class EngineeringWorktreeManager {
	constructor(private readonly managedRoot: string) {}

	create(input: {
		workspaceRoot: string;
		missionId: string;
		taskId: string;
		agentId: string;
	}): EngineeringWorktreeLease {
		const repositoryRoot = realpathSync.native(
			git(input.workspaceRoot, ["rev-parse", "--show-toplevel"]),
		);
		const baseRevision = git(repositoryRoot, ["rev-parse", "HEAD"]);
		const id = createHash("sha256")
			.update(`${input.missionId}\0${input.taskId}\0${input.agentId}`)
			.digest("hex")
			.slice(0, 20);
		const container = resolve(this.managedRoot, slug(input.missionId), id);
		const path = join(container, basename(repositoryRoot));
		this.assertManagedPath(path);
		if (existsSync(path))
			throw new Error(`Managed worktree already exists: ${path}`);
		const branch = `cline/engineering/${slug(input.missionId).slice(-18)}-${slug(input.taskId)}-${id.slice(0, 6)}`;
		mkdirSync(container, { recursive: true });
		try {
			git(repositoryRoot, [
				"worktree",
				"add",
				"-b",
				branch,
				path,
				baseRevision,
			]);
		} catch (error) {
			rmSync(container, { recursive: true, force: true });
			throw error;
		}
		const lease: EngineeringWorktreeLease = {
			id,
			missionId: input.missionId,
			taskId: input.taskId,
			agentId: input.agentId,
			repositoryRoot,
			path: realpathSync.native(path),
			branch,
			baseRevision,
			createdAt: new Date().toISOString(),
			status: "active",
		};
		atomicWrite(this.metadataPath(lease.path), lease);
		return lease;
	}

	inspect(pathValue: string): EngineeringWorktreeLease & {
		dirty: boolean;
		changedFiles: string[];
		aheadBy: number;
	} {
		const path = realpathSync.native(pathValue);
		this.assertManagedPath(path);
		const lease = this.readLease(path);
		const changedFiles = git(path, ["status", "--porcelain=v1"])
			.split(/\r?\n/)
			.filter(Boolean)
			.map((line) => line.slice(3));
		const aheadBy = Number(
			git(path, ["rev-list", "--count", `${lease.baseRevision}..HEAD`]) || 0,
		);
		return { ...lease, dirty: changedFiles.length > 0, changedFiles, aheadBy };
	}

	release(
		pathValue: string,
		options: { confirmDiscard: boolean; keep?: boolean },
	): EngineeringWorktreeLease {
		const inspection = this.inspect(pathValue);
		if (options.keep) {
			const kept = { ...inspection, status: "kept" as const };
			atomicWrite(this.metadataPath(inspection.path), kept);
			return kept;
		}
		if (
			(inspection.dirty || inspection.aheadBy > 0) &&
			!options.confirmDiscard
		) {
			throw new Error(
				"Worktree has changes or commits; explicit discard confirmation is required",
			);
		}
		git(inspection.repositoryRoot, [
			"worktree",
			"remove",
			"--force",
			inspection.path,
		]);
		try {
			git(inspection.repositoryRoot, ["branch", "-D", inspection.branch]);
		} catch {
			/* already removed or renamed */
		}
		rmSync(dirname(inspection.path), { recursive: true, force: true });
		return { ...inspection, status: "released" };
	}

	private metadataPath(path: string): string {
		return join(dirname(path), "lease.json");
	}
	private readLease(path: string): EngineeringWorktreeLease {
		const parsed = JSON.parse(
			readFileSync(this.metadataPath(path), "utf8"),
		) as EngineeringWorktreeLease;
		if (parsed.path !== path || parsed.status === "released")
			throw new Error("Invalid or released engineering worktree lease");
		return parsed;
	}
	private assertManagedPath(path: string): void {
		const root = canonicalFuturePath(this.managedRoot);
		const candidate = canonicalFuturePath(path);
		const comparableRoot =
			process.platform === "win32" ? root.toLowerCase() : root;
		const comparableCandidate =
			process.platform === "win32" ? candidate.toLowerCase() : candidate;
		const rel = relative(comparableRoot, comparableCandidate);
		if (!rel || rel.startsWith("..") || rel.split(sep).length < 3)
			throw new Error("Engineering worktree path is outside the managed root");
	}
}
