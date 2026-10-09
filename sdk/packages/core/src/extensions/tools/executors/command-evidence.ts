import { lstat, realpath } from "node:fs/promises";
import type { Stats } from "node:fs";
import { resolve } from "node:path";

/** Bounded, redacted process facts. No argv or environment is persisted here. */
export interface CommandExecutionReceipt {
	schemaVersion: 1;
	executable: string;
	cwd: string;
	pid?: number;
	exitCode: number | null;
	status:
		| "completed"
		| "failed"
		| "cancelled"
		| "timed_out"
		| "running"
		| "launch_failed";
	stdout: string;
	stderr: string;
	outputTruncated: boolean;
	durationMs: number;
	terminationConfirmed: boolean;
}

export interface CommandArtifactReceipt {
	path: string;
	bytes: number;
	fingerprint: string;
}

/** Explicit file contracts only; never infer inputs/outputs from a shell string. */
export async function inspectCommandArtifacts(
	paths: readonly string[] | undefined,
	cwd: string,
): Promise<CommandArtifactReceipt[]> {
	if (!paths) return [];
	if (paths.length > 32)
		throw new Error("At most 32 command artifacts allowed");
	return Promise.all(
		paths.map(async (path) => {
			const absolute = resolve(cwd, path);
			let info: Stats;
			try {
				info = await lstat(absolute);
			} catch {
				throw new Error(`Required command artifact is missing: ${absolute}`);
			}
			if (!info.isFile() || info.isSymbolicLink())
				throw new Error(
					`Command artifact must be a non-linked regular file: ${absolute}`,
				);
			return {
				path: await realpath(absolute),
				bytes: info.size,
				fingerprint: `${info.dev}:${info.ino}:${info.size}:${info.mtimeMs}:${info.ctimeMs}`,
			};
		}),
	);
}
