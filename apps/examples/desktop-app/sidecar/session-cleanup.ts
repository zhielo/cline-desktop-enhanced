import { existsSync, lstatSync, realpathSync, rmSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { sessionLogPath, sharedSessionDataDir } from "./paths";

export function assertSessionCleanupId(sessionId: string): void {
	if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,239}$/.test(sessionId)) {
		throw new Error("Invalid session id for cleanup");
	}
}

/** Only a direct, non-link child of the canonical session root is owned. */
export function ownedSessionDirectory(sessionId: string): string | undefined {
	assertSessionCleanupId(sessionId);
	const root = sharedSessionDataDir();
	if (!existsSync(root)) return undefined;
	const canonicalRoot = realpathSync(root);
	const candidate = resolve(canonicalRoot, sessionId);
	if (!existsSync(candidate)) return undefined;
	if (lstatSync(candidate).isSymbolicLink())
		throw new Error("Session cleanup refuses links");
	const canonical = realpathSync(candidate);
	const rel = relative(canonicalRoot, canonical);
	if (rel !== sessionId || isAbsolute(rel) || rel.includes(sep)) {
		throw new Error("Session cleanup escaped its owned root");
	}
	return canonical;
}

/** Stored messagesPath is NOT authority to recursively delete its parent. */
export function removeOwnedSessionArtifacts(sessionId: string): boolean {
	const directory = ownedSessionDirectory(sessionId);
	let removed = false;
	if (directory) {
		rmSync(directory, { recursive: true, force: true });
		removed = true;
	}
	// The log filename is derived from a validated ID, never persisted metadata.
	const log = sessionLogPath(sessionId);
	if (existsSync(log)) {
		if (!lstatSync(log).isFile())
			throw new Error("Session log is not a regular file");
		const parent = realpathSync(dirname(log));
		if (realpathSync(log) !== resolve(parent, `${sessionId}.jsonl`)) {
			throw new Error("Session log escaped its owned root");
		}
		rmSync(log, { force: true });
		removed = true;
	}
	return removed;
}
