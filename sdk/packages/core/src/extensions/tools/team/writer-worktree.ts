import { execFile as execFileCallback } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { promisify } from "node:util";
import { resolveClineDir } from "@cline/shared/storage";

const execFile = promisify(execFileCallback);

export interface WriterWorktreeMetadata {
	version: 1;
	id: string;
	path: string;
	sourceRepo: string;
	sourceRevision: string;
	baseBranch?: string;
	branch: string;
	generatedBranch: string;
	createdAt: string;
	ownerAgentId: string;
}

function metadataPath(worktreePath: string): string {
	return join(dirname(worktreePath), "worktree.json");
}

/**
 * Creates a managed worktree for one writing teammate. The metadata deliberately
 * extends (without changing) Desktop's managed-worktree handoff contract.
 */
export async function createWriterWorktree(
	cwd: string,
	agentId: string,
	worktreesRoot = join(resolveClineDir(), "worktrees"),
): Promise<WriterWorktreeMetadata> {
	const { stdout } = await execFile("git", ["rev-parse", "--show-toplevel"], {
		cwd,
		encoding: "utf8",
		windowsHide: true,
	}).catch(() => {
		throw new Error(
			`Cannot create an isolated writer: not a git repository: ${cwd}`,
		);
	});
	const sourceRepo = realpathSync.native(stdout.trim());
	const [{ stdout: revisionOut }, { stdout: branchOut }] = await Promise.all([
		execFile("git", ["-C", sourceRepo, "rev-parse", "HEAD"], {
			encoding: "utf8",
			windowsHide: true,
		}),
		execFile("git", ["-C", sourceRepo, "branch", "--show-current"], {
			encoding: "utf8",
			windowsHide: true,
		}),
	]);
	const id = randomUUID().replaceAll("-", "").slice(0, 8);
	const branch = `cline/team-${id}`;
	const requestedPath = join(
		worktreesRoot,
		id,
		basename(sourceRepo) || "workspace",
	);
	mkdirSync(dirname(requestedPath), { recursive: true });
	try {
		await execFile(
			"git",
			[
				"-C",
				sourceRepo,
				"worktree",
				"add",
				"-b",
				branch,
				requestedPath,
				revisionOut.trim(),
			],
			{ encoding: "utf8", windowsHide: true },
		);
	} catch (error) {
		rmSync(dirname(requestedPath), { recursive: true, force: true });
		throw error;
	}
	const path = realpathSync.native(requestedPath);
	const metadata: WriterWorktreeMetadata = {
		version: 1,
		id,
		path,
		sourceRepo,
		sourceRevision: revisionOut.trim(),
		...(branchOut.trim() ? { baseBranch: branchOut.trim() } : {}),
		branch,
		generatedBranch: branch,
		createdAt: new Date().toISOString(),
		ownerAgentId: agentId,
	};
	writeFileSync(metadataPath(path), `${JSON.stringify(metadata, null, 2)}\n`, {
		encoding: "utf8",
		mode: 0o600,
	});
	return metadata;
}

/** Return repository-relative paths changed in a writer worktree. */
export async function listWriterWorktreeChanges(
	worktreePath: string,
): Promise<string[]> {
	const { stdout } = await execFile(
		"git",
		[
			"-C",
			worktreePath,
			"status",
			"--porcelain=v1",
			"-z",
			"--untracked-files=all",
		],
		{ encoding: "utf8", windowsHide: true, maxBuffer: 4 * 1024 * 1024 },
	);
	const paths = new Set<string>();
	const entries = stdout.split("\0");
	for (let index = 0; index < entries.length; index += 1) {
		const entry = entries[index];
		if (!entry || entry.length < 4) continue;
		const status = entry.slice(0, 2);
		const path = entry.slice(3).replaceAll("\\", "/");
		if (path) paths.add(path);
		if (status.includes("R") || status.includes("C")) {
			const destination = entries[index + 1]?.replaceAll("\\", "/");
			if (destination) paths.add(destination);
			index += 1;
		}
	}
	return [...paths].sort();
}
