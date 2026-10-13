import { mkdirSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { loadSqliteDb, type SqliteDb } from "@cline/shared/db";
import { resolveClineDataDir } from "@cline/shared/storage";
import { z } from "zod";
import { digest, canonical, type AnalysisResult } from "./contracts";
const Hash = z.string().regex(/^[a-f0-9]{64}$/);
const Completion = z
	.object({
		id: z.string().uuid(),
		workspaceRoot: z.string(),
		kind: z.enum([
			"static",
			"debugger",
			"gui",
			"dynamic",
			"device",
			"execution",
		]),
		operation: z.string().max(120),
		status: z.literal("completed"),
		requestHash: Hash,
		targetIdentity: z
			.object({ sha256: Hash.optional() })
			.passthrough()
			.optional(),
		evidence: z
			.object({
				resultHash: Hash,
				requestHash: Hash,
				tool: z.string().max(120),
			})
			.passthrough(),
		completedAt: z.string().datetime(),
	})
	.passthrough();
export type TaskEvidenceSnapshot = {
	id: string;
	sessionId: string;
	workspace: string;
	taskId: string;
	domain: string;
	operation: string;
	tool: string;
	targetSha256?: string;
	resultHash: string;
	requestHash: string;
	at: string;
	result: unknown;
	snapshotHash: string;
};
/** Immutable host-completed task snapshots. Remote claims are not authenticated by storage. */
export class UnifiedEvidenceStore {
	private db?: SqliteDb;
	constructor(
		private file = join(
			resolveClineDataDir(),
			"analysis-workspace",
			"task-evidence.sqlite",
		),
	) {}
	private database() {
		if (!this.db) {
			mkdirSync(dirname(this.file), { recursive: true, mode: 0o700 });
			this.db = loadSqliteDb(this.file);
			this.db.exec(
				"PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS task_evidence(id TEXT PRIMARY KEY,session TEXT NOT NULL,workspace TEXT NOT NULL,body TEXT NOT NULL); CREATE INDEX IF NOT EXISTS task_evidence_scope ON task_evidence(session,workspace); CREATE TABLE IF NOT EXISTS task_evidence_owners(task_id TEXT PRIMARY KEY,session TEXT NOT NULL,workspace TEXT NOT NULL,request_hash TEXT NOT NULL);",
			);
		}
		return this.db;
	}
	close() {
		this.db?.close?.();
		this.db = undefined;
	}
	bind(sessionId: string, workspace: string, planValue: unknown) {
		const plan = z
			.object({
				id: z.string().uuid(),
				workspaceRoot: z.string(),
				requestHash: Hash,
				status: z.literal("awaiting-approval"),
			})
			.passthrough()
			.parse(planValue);
		const root = realpathSync(workspace);
		if (realpathSync(plan.workspaceRoot) !== root)
			throw new Error("Task ownership workspace mismatch");
		const db = this.database();
		db.exec("BEGIN IMMEDIATE");
		try {
			const old = db
				.prepare(
					"SELECT session,workspace,request_hash FROM task_evidence_owners WHERE task_id=?",
				)
				.get(plan.id);
			if (old) {
				if (
					old.session !== sessionId ||
					old.workspace !== root ||
					old.request_hash !== plan.requestHash
				)
					throw new Error("Task evidence owner is immutable");
			} else {
				if (
					Number(
						db.prepare("SELECT COUNT(*) AS n FROM task_evidence_owners").get()
							?.n,
					) >= 500
				)
					throw new Error("Task ownership capacity reached");
				db.prepare(
					"INSERT INTO task_evidence_owners(task_id,session,workspace,request_hash) VALUES(?,?,?,?)",
				).run(plan.id, sessionId, root, plan.requestHash);
			}
			db.exec("COMMIT");
		} catch (e) {
			db.exec("ROLLBACK");
			throw e;
		}
	}
	record(
		sessionId: string,
		workspace: string,
		planValue: unknown,
		result: unknown,
	) {
		const plan = Completion.parse(planValue),
			root = realpathSync(workspace),
			resultHash = digest(result);
		let planRoot: string;
		try {
			planRoot = realpathSync(plan.workspaceRoot);
		} catch {
			throw new Error("Completed-task evidence binding mismatch");
		}
		if (
			root !== planRoot ||
			resultHash !== plan.evidence.resultHash ||
			plan.requestHash !== plan.evidence.requestHash
		)
			throw new Error("Completed-task evidence binding mismatch");
		if (Buffer.byteLength(canonical(result)) > 1048576)
			throw new Error(
				"Task evidence retention byte budget exceeded; original result must not be replayed",
			);
		const raw = {
			id: digest({ sessionId, taskId: plan.id, resultHash }),
			sessionId,
			workspace: root,
			taskId: plan.id,
			domain: plan.kind,
			operation: plan.operation,
			tool: plan.evidence.tool,
			targetSha256: plan.targetIdentity?.sha256,
			resultHash,
			requestHash: plan.requestHash,
			at: plan.completedAt,
			result,
		};
		const owner = this.database()
			.prepare(
				"SELECT session,workspace,request_hash FROM task_evidence_owners WHERE task_id=?",
			)
			.get(plan.id);
		if (
			!owner ||
			owner.session !== sessionId ||
			owner.workspace !== root ||
			owner.request_hash !== plan.requestHash
		)
			throw new Error("Task evidence is not bound to this owning session");
		const snapshot: TaskEvidenceSnapshot = {
				...raw,
				snapshotHash: digest(raw),
			},
			db = this.database();
		db.exec("BEGIN IMMEDIATE");
		try {
			const old = db
				.prepare("SELECT body FROM task_evidence WHERE id=?")
				.get(snapshot.id);
			if (old) {
				if (digest(JSON.parse(String(old.body))) !== digest(snapshot))
					throw new Error("Conflicting immutable task snapshot");
				db.exec("COMMIT");
				return snapshot;
			}
			if (
				Number(
					db.prepare("SELECT COUNT(*) AS n FROM task_evidence").get()?.n,
				) >= 250
			)
				throw new Error(
					"Task evidence ledger capacity reached; no automatic deletion",
				);
			db.prepare(
				"INSERT INTO task_evidence(id,session,workspace,body) VALUES(?,?,?,?)",
			).run(snapshot.id, sessionId, root, JSON.stringify(snapshot));
			db.exec("COMMIT");
			return snapshot;
		} catch (e) {
			db.exec("ROLLBACK");
			throw e;
		}
	}
	list(sessionId: string, workspace: string) {
		return this.database()
			.prepare(
				"SELECT body FROM task_evidence WHERE session=? AND workspace=? ORDER BY rowid DESC LIMIT 100",
			)
			.all(sessionId, realpathSync(workspace))
			.map((row) => {
				const s = JSON.parse(String(row.body)) as TaskEvidenceSnapshot,
					{ snapshotHash, ...raw } = s;
				if (digest(raw) !== snapshotHash || digest(s.result) !== s.resultHash)
					throw new Error("Unified task evidence integrity mismatch");
				return s;
			});
	}
}
const object = (v: unknown): Record<string, unknown> =>
	v && typeof v === "object" && !Array.isArray(v)
		? (v as Record<string, unknown>)
		: {};
export function unifiedEvidenceView(
	staticResult: AnalysisResult | undefined,
	snapshots: TaskEvidenceSnapshot[],
) {
	const artifacts = new Set(staticResult?.artifacts.map((a) => a.sha256) ?? []);
	return snapshots.map((s) => {
		const outer = object(s.result),
			report = object(outer.result ?? outer),
			providerHash = object(report.input).sha256;
		const contradictions: Array<Record<string, unknown>> = [];
		if (
			typeof providerHash === "string" &&
			s.targetSha256 &&
			providerHash !== s.targetSha256
		)
			contradictions.push({
				kind: "provider-input-byte-mismatch",
				approvedHash: s.targetSha256,
				reportedHash: providerHash,
			});
		if (report.reconciliation === "loaded-source-byte-mismatch")
			contradictions.push({
				kind: "runtime-loaded-source-byte-mismatch",
				staticHash: s.targetSha256,
				note: "Loaded source bytes differ from selected file; no behavioral contradiction is inferred",
			});
		return {
			id: s.id,
			taskId: s.taskId,
			domain: s.domain,
			operation: s.operation,
			tool: s.tool,
			at: s.at,
			targetSha256: s.targetSha256,
			resultHash: s.resultHash,
			snapshotHash: s.snapshotHash,
			staticIdentity: s.targetSha256
				? artifacts.has(s.targetSha256)
					? "exact-byte-match"
					: "not-in-static-inventory"
				: "unknown",
			supporting:
				s.targetSha256 && artifacts.has(s.targetSha256)
					? [
							{
								kind: "exact-artifact-byte-identity",
								artifactHash: s.targetSha256,
								snapshotId: s.id,
							},
						]
					: [],
			contradictions,
			authority: "host-completed-approved-task-result",
			verifiedBehavior: false,
			evidence: s.result,
			limitations: [
				"Snapshot integrity is not authentication of external provider claims. Match is byte identity, not observed execution or cross-domain equivalence.",
			],
			nextTest:
				s.targetSha256 && artifacts.has(s.targetSha256)
					? "Inspect provider scope and directly test the claimed behavior with separate authorization"
					: "Obtain matching artifact bytes and a separately approved exact-target observation before reconciling claims",
		};
	});
}
/** Engine-qualified selected-function dossiers; missing components stay explicitly unknown. */
export function nativeDossiers(snapshots: TaskEvidenceSnapshot[]) {
	const dossiers: Array<Record<string, unknown>> = [];
	for (const s of snapshots) {
		const outer = object(s.result),
			report = object(outer.result ?? outer),
			evidence = object(report.evidence),
			input = object(report.input);
		if (!s.targetSha256 || input.sha256 !== s.targetSha256) continue;
		const selected = Array.isArray(evidence.selectedFunctions)
			? evidence.selectedFunctions
			: [];
		for (const item of selected.slice(0, 50)) {
			const f = object(item),
				address = f.addressHex;
			if (
				typeof address !== "string" ||
				!/^0x[a-f0-9]+$/i.test(address) ||
				typeof report.engine !== "string"
			)
				continue;
			const identity = {
				sha256: s.targetSha256,
				engine: report.engine,
				engineVersion: report.engineVersion ?? null,
				address: address.toLowerCase(),
			};
			dossiers.push({
				id: digest(identity),
				identity,
				snapshotId: s.id,
				snapshotHash: s.snapshotHash,
				at: s.at,
				name: f.name ?? "unknown",
				imageBase: object(f.image).base ?? "unknown",
				disassembly: f.disassembly ?? "unknown",
				pseudocode: f.pseudocode ?? "unknown",
				references: f.references ?? "unknown",
				strings: f.strings ?? "unknown",
				callers: f.callers ?? "unknown",
				callees: f.callees ?? "unknown",
				limitations: [
					"Engine-qualified exact address; no automatic relocation, symbol equivalence or missing-component inference. Unavailable fields are unknown.",
				],
			});
		}
	}
	return dossiers.slice(0, 250);
}
export function dossierDisagreements(dossiers: Array<Record<string, unknown>>) {
	const groups = new Map<string, Array<Record<string, unknown>>>();
	for (const d of dossiers) {
		const i = object(d.identity);
		const key = canonical([i.sha256, i.address]);
		const g = groups.get(key) ?? [];
		g.push(d);
		groups.set(key, g);
	}
	return [...groups.values()]
		.filter((g) => g.length > 1)
		.map((g) => ({
			identity: object(g[0].identity),
			snapshots: g.map((d) => d.snapshotId),
			disagreement:
				new Set(g.map((d) => digest(d.disassembly))).size > 1
					? "different-engine-output"
					: "same-retained-output",
			interpretation:
				"Output difference, not proof either engine is wrong; image base and execution remain separately unverified",
			nextTest:
				"Confirm image base and byte range before an independently approved second-engine test",
		}));
}
