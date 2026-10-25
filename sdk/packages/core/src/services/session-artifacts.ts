import {
	existsSync,
	lstatSync,
	realpathSync,
	mkdirSync,
	readdirSync,
	rmdirSync,
	rmSync,
	unlinkSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import {
	parseSubSessionId,
	parseTeamTaskSubSessionId,
} from "../session/models/session-graph";

export function nowIso(): string {
	return new Date().toISOString();
}

export function unlinkIfExists(path: string | null | undefined): void {
	if (!path || !existsSync(path)) {
		return;
	}
	try {
		unlinkSync(path);
	} catch {
		// Best effort cleanup.
	}
}

export interface SessionArtifactPaths {
	messagesPath: string;
}

function childArtifactFileStem(sessionId: string): {
	rootSessionId: string;
	fileStem: string;
} {
	const teamTask = parseTeamTaskSubSessionId(sessionId);
	if (teamTask) {
		return {
			rootSessionId: teamTask.rootSessionId,
			fileStem: `${teamTask.agentId}__${teamTask.teamTaskId}`,
		};
	}

	const subagent = parseSubSessionId(sessionId);
	if (subagent) {
		return {
			rootSessionId: subagent.rootSessionId,
			fileStem: subagent.agentId,
		};
	}

	return {
		rootSessionId: sessionId,
		fileStem: sessionId,
	};
}

export class SessionArtifacts {
	constructor(private readonly ensureSessionsDir: () => string) {}

	public sessionArtifactsDir(sessionId: string): string {
		return join(this.ensureSessionsDir(), sessionId);
	}

	public ensureSessionArtifactsDir(sessionId: string): string {
		const dir = this.sessionArtifactsDir(sessionId);
		if (!existsSync(dir)) {
			mkdirSync(dir, { recursive: true });
		}
		return dir;
	}

	public sessionMessagesPath(sessionId: string): string {
		return join(
			this.sessionArtifactsDir(sessionId),
			`${sessionId}.messages.json`,
		);
	}

	public sessionCompactionPath(sessionId: string): string {
		return join(
			this.sessionArtifactsDir(sessionId),
			`${sessionId}.compaction.json`,
		);
	}

	public sessionManifestPath(sessionId: string, ensureDir = false): string {
		const base = ensureDir
			? this.ensureSessionArtifactsDir(sessionId)
			: this.sessionArtifactsDir(sessionId);
		return join(base, `${sessionId}.json`);
	}

	public removeSessionDirIfEmpty(sessionId: string): void {
		let dir = this.sessionArtifactsDir(sessionId);
		const sessionsDir = this.ensureSessionsDir();
		while (dir.startsWith(sessionsDir) && dir !== sessionsDir) {
			if (!existsSync(dir)) {
				dir = dirname(dir);
				continue;
			}
			try {
				if (readdirSync(dir).length > 0) {
					break;
				}
				rmdirSync(dir);
			} catch {
				// Best-effort cleanup.
				break;
			}
			dir = dirname(dir);
		}
	}

	public removeSessionDir(sessionId: string): void {
		this.removeDir(this.sessionArtifactsDir(sessionId));
	}

	/** Canonical identity must match the lexical owned path; no junction aliases. */
	public isOwnedArtifactPath(path: string): boolean {
		const root = this.ensureSessionsDir();
		if (!existsSync(root) || !existsSync(path)) return false;
		const lexical = relative(resolve(root), resolve(path));
		if (
			!lexical ||
			lexical === ".." ||
			lexical.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) ||
			isAbsolute(lexical)
		)
			return false;
		if (lstatSync(path).isSymbolicLink()) return false;
		return relative(realpathSync(root), realpathSync(path)) === lexical;
	}

	public removeOwnedFile(path: string): void {
		if (this.isOwnedArtifactPath(path) && lstatSync(path).isFile())
			unlinkIfExists(path);
	}

	public removeSessionMessages(sessionId: string): void {
		if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,239}$/.test(sessionId)) return;
		// Derive identities from the session, never arbitrary persisted messagesPath.
		this.removeOwnedFile(this.sessionMessagesPath(sessionId));
		this.removeOwnedFile(
			this.subagentArtifactPaths(sessionId, "").messagesPath,
		);
	}

	public removeDir(dir: string): void {
		if (!this.isOwnedArtifactPath(dir)) {
			return;
		}
		try {
			rmSync(dir, { recursive: true, force: true });
		} catch {
			// Best-effort cleanup.
		}
	}

	public subagentArtifactPaths(
		sessionId: string,
		subAgentId: string,
		activeTeamTaskSessionId?: string,
	): SessionArtifactPaths {
		void subAgentId;
		void activeTeamTaskSessionId;
		const { rootSessionId, fileStem } = childArtifactFileStem(sessionId);
		const dir = this.sessionArtifactsDir(rootSessionId);
		return {
			messagesPath: join(dir, `${fileStem}.messages.json`),
		};
	}
}
