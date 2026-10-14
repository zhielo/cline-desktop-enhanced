import { createHash, randomUUID } from "node:crypto";
import { createReadStream, mkdirSync, realpathSync } from "node:fs";
import { stat } from "node:fs/promises";
import { dirname, relative, resolve, sep } from "node:path";
import { loadSqliteDb, type SqliteDb } from "@cline/shared/db";
export type WorkflowScope = { sessionId: string; workspace: string };
export type OpenArtifact = {
	id: string;
	path: string;
	sha256: string;
	bytes: number;
	openedAt: string;
};
export async function confinedArtifact(workspace: string, target: string) {
	// Match the task planner's native resolver, including Windows 8.3 aliases.
	// Both sides must resolve before containment; lexical aliases are not roots.
	const root = realpathSync.native(workspace),
		file = realpathSync.native(resolve(root, target)),
		rel = relative(root, file);
	if (
		!rel ||
		rel.startsWith(`..${sep}`) ||
		rel === ".." ||
		rel.startsWith(sep) ||
		resolve(root, rel) !== file
	)
		throw new Error("Artifact must be a file confined to the owning workspace");
	const before = await stat(file);
	if (!before.isFile() || before.size > 512 * 1024 * 1024)
		throw new Error("Artifact byte budget exceeded");
	const hash = createHash("sha256");
	let size = 0;
	for await (const chunk of createReadStream(file)) {
		size += chunk.length;
		if (size > 512 * 1024 * 1024)
			throw new Error("Artifact grew beyond budget");
		hash.update(chunk);
	}
	const after = await stat(file);
	if (
		realpathSync.native(resolve(root, target)) !== file ||
		after.ino !== before.ino ||
		after.dev !== before.dev ||
		size !== before.size ||
		after.size !== before.size ||
		after.mtimeMs !== before.mtimeMs ||
		after.ctimeMs !== before.ctimeMs
	)
		throw new Error("Artifact changed during hashing");
	return { path: file, sha256: hash.digest("hex"), bytes: size };
}
export class AnalysisWorkflowStore {
	private db?: SqliteDb;
	constructor(private file: string) {}
	private database() {
		if (!this.db) {
			mkdirSync(dirname(this.file), { recursive: true, mode: 0o700 });
			this.db = loadSqliteDb(this.file);
			const version=Number(this.db.prepare("PRAGMA user_version").get()?.user_version??0);
            if(version>1){this.db.close?.();this.db=undefined;throw new Error("Unsupported workflow database version; existing data preserved");}
            this.db.exec(
				"PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA user_version=1; CREATE TABLE IF NOT EXISTS workflow_items(id TEXT PRIMARY KEY,session TEXT NOT NULL,workspace TEXT NOT NULL,kind TEXT NOT NULL,body TEXT NOT NULL); CREATE INDEX IF NOT EXISTS workflow_scope ON workflow_items(session,workspace);",
			);
		}
		return this.db;
	}
	private scope(scope: WorkflowScope) {
		return [scope.sessionId, realpathSync(scope.workspace)] as const;
	}
	put(
		scope: WorkflowScope,
		kind: "artifact" | "scenario",
		body: Record<string, unknown>,
	) {
		const [session, workspace] = this.scope(scope);
		const rows = this.database()
			.prepare(
				"SELECT COUNT(*) AS total FROM workflow_items WHERE session=? AND workspace=?",
			)
			.get(session, workspace);
		if (Number(rows?.total) >= 200)
			throw new Error(
				"Workflow item budget reached; existing records are preserved",
			);
		const item = { ...body, id: randomUUID() };
		if (Buffer.byteLength(JSON.stringify(item)) > 2 * 1024 * 1024)
			throw new Error("Workflow record byte budget");
		this.database()
			.prepare(
				"INSERT INTO workflow_items(id,session,workspace,kind,body) VALUES(?,?,?,?,?)",
			)
			.run(item.id, session, workspace, kind, JSON.stringify(item));
		return item;
	}
	get(scope: WorkflowScope, id: string, kind: "artifact" | "scenario") {
		const [session, workspace] = this.scope(scope);
		const row = this.database()
			.prepare(
				"SELECT body FROM workflow_items WHERE id=? AND session=? AND workspace=? AND kind=?",
			)
			.get(id, session, workspace, kind);
		if (!row)
			throw new Error("Workflow item is unavailable in this session/workspace");
		return JSON.parse(String(row.body)) as Record<string, unknown>;
	}
	list(scope: WorkflowScope, kind: "artifact" | "scenario") {
		const [session, workspace] = this.scope(scope);
		return this.database()
			.prepare(
				"SELECT body FROM workflow_items WHERE session=? AND workspace=? AND kind=? ORDER BY rowid DESC LIMIT 40",
			)
			.all(session, workspace, kind)
			.map((r) => JSON.parse(String(r.body)));
	}
	async open(scope: WorkflowScope, target: string) {
		return this.put(scope, "artifact", {
			...(await confinedArtifact(scope.workspace, target)),
			openedAt: new Date().toISOString(),
		}) as OpenArtifact;
	}
	async verify(scope: WorkflowScope, id: string) {
		const item = this.get(scope, id, "artifact") as OpenArtifact;
		const current = await confinedArtifact(scope.workspace, item.path);
		if (current.sha256 !== item.sha256 || current.bytes !== item.bytes)
			throw new Error(
				"Artifact changed since opening; open a new immutable handle",
			);
		return item;
	}
	close() {
		this.db?.close?.();
		this.db = undefined;
	}
}
