import { opendir } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { performance } from "node:perf_hooks";

export const WORKSPACE_FILE_LIMIT = 2_000;
const IGNORED = new Set([
	".git",
	"node_modules",
	".next",
	".turbo",
	"build",
	"coverage",
	"dist",
	"target",
]);
const CONFIG_DIRECTORIES = new Set([
	".github",
	".agents",
	".cline",
	".clinerules",
	".vscode",
	".codex",
	".claude",
	".changeset",
]);
export type WorkspaceSearchStop =
	| "result-limit"
	| "entry-budget"
	| "directory-budget"
	| "time-budget"
	| "cancelled";
export type WorkspaceFileSearchResult = {
	root: string;
	files: string[];
	limit: number;
	complete: boolean;
	stopReason?: WorkspaceSearchStop;
	visitedEntries: number;
	visitedDirectories: number;
	inaccessibleDirectories: number;
};
/** Directory streaming bounds work and memory independently of matching results.
 * Discovered symbolic links are not enqueued. Hidden internal directories stay excluded;
 * only known project configuration directories are admitted.
 */
export async function listWorkspaceFiles(
	baseDir: string,
	queryValue: unknown,
	options: {
		signal?: AbortSignal;
		maxEntries?: number;
		maxDirectories?: number;
		maxDurationMs?: number;
		maxResults?: number;
	} = {},
): Promise<WorkspaceFileSearchResult> {
	const root = resolve(baseDir),
		query = String(queryValue ?? "")
			.trim()
			.toLowerCase();
	const bounded = (
		value: number | undefined,
		fallback: number,
		maximum: number,
	) =>
		value === undefined
			? fallback
			: Number.isFinite(value)
				? Math.max(1, Math.min(maximum, Math.floor(value)))
				: fallback;
	const maxEntries = bounded(options.maxEntries, 25_000, 25_000);
	const maxDirectories = bounded(options.maxDirectories, 2_000, 2_000);
	const maxDuration = bounded(options.maxDurationMs, 250, 1_000);
	const limit = bounded(
		options.maxResults,
		WORKSPACE_FILE_LIMIT,
		WORKSPACE_FILE_LIMIT,
	);
	const result: WorkspaceFileSearchResult = {
		root,
		files: [],
		limit,
		complete: true,
		visitedEntries: 0,
		visitedDirectories: 0,
		inaccessibleDirectories: 0,
	};
	const started = performance.now(),
		pending = [root];
	const stop = () => {
		const reason: WorkspaceSearchStop | undefined = options.signal?.aborted
			? "cancelled"
			: result.files.length >= limit
				? "result-limit"
				: result.visitedEntries >= maxEntries
					? "entry-budget"
					: performance.now() - started >= maxDuration
						? "time-budget"
						: undefined;
		if (reason) {
			result.complete = false;
			result.stopReason = reason;
		}
		return reason !== undefined;
	};
	search: while (pending.length > 0) {
		if (stop()) break;
		if (result.visitedDirectories >= maxDirectories) {
			result.complete = false;
			result.stopReason = "directory-budget";
			break;
		}
		const directory = pending.pop();
		if (!directory) break;
		result.visitedDirectories++;
		try {
			const entries = await opendir(directory);
			for await (const entry of entries) {
				if (stop()) break search;
				result.visitedEntries++;
				if (entry.isSymbolicLink()) continue;
				const absolute = join(directory, entry.name);
				if (entry.isDirectory()) {
					if (
						!IGNORED.has(entry.name) &&
						(!entry.name.startsWith(".") || CONFIG_DIRECTORIES.has(entry.name))
					) {
						// Queue growth is bounded even when a root has thousands of subdirectories.
						if (pending.length + result.visitedDirectories < maxDirectories)
							pending.push(absolute);
						else {
							result.complete = false;
							result.stopReason ??= "directory-budget";
						}
					}
				} else if (entry.isFile()) {
					const path = relative(root, absolute);
					if (!query || path.toLowerCase().includes(query))
						result.files.push(path);
				}
			}
		} catch (error) {
			if (options.signal?.aborted) {
				result.complete = false;
				result.stopReason = "cancelled";
				break;
			}
			const code = (error as NodeJS.ErrnoException).code;
			if (
				code !== "ENOENT" &&
				code !== "ENOTDIR" &&
				code !== "EACCES" &&
				code !== "EPERM"
			)
				throw error;
			result.inaccessibleDirectories++;
			result.complete = false;
		}
	}
	result.files.sort((a, b) => a.localeCompare(b));
	return result;
}
