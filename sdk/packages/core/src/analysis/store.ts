import { mkdirSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { loadSqliteDb, type SqliteDb } from "@cline/shared/db";
import { resolveClineDataDir } from "@cline/shared/storage";
import {
	type AnalysisMode,
	AnalysisModeSchema,
	type AnalysisReceipt,
	digest,
} from "./contracts";
import { digestCanonicalValue } from "./semantic-engine/upstream/src/domain/canonicalDigest";

/** Private, cross-process durable receipts; never writes into the inspected target. */
export class FirstPartyAnalysisStore {
	private db?: SqliteDb;
	constructor(
		private path = join(
			resolveClineDataDir(),
			"analysis-workspace",
			"evidence.sqlite",
		),
	) {}
	private database() {
		if (!this.db) {
			mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
			this.db = loadSqliteDb(this.path);
			this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
				CREATE TABLE IF NOT EXISTS analysis_sessions(id TEXT PRIMARY KEY, workspace TEXT NOT NULL, mode TEXT NOT NULL);
				CREATE TABLE IF NOT EXISTS analysis_receipts(id TEXT PRIMARY KEY, session_id TEXT NOT NULL, status TEXT NOT NULL, body TEXT NOT NULL);
				CREATE INDEX IF NOT EXISTS analysis_receipt_session ON analysis_receipts(session_id);
 CREATE TABLE IF NOT EXISTS analysis_recovery(receipt_id TEXT PRIMARY KEY, body_hash TEXT NOT NULL, at TEXT NOT NULL, audit_hash TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS analysis_semantic_graphs(receipt_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, body TEXT NOT NULL);`);
		}
		return this.db;
	}
	close() {
		this.db?.close?.();
		this.db = undefined;
	}
	session(id: string): { workspace: string; mode: AnalysisMode } | undefined {
		const row = this.database()
			.prepare("SELECT workspace,mode FROM analysis_sessions WHERE id=?")
			.get(id);
		return row
			? {
					workspace: String(row.workspace),
					mode: AnalysisModeSchema.parse(row.mode),
				}
			: undefined;
	}
	setMode(id: string, workspace: string, mode: AnalysisMode) {
		mode = AnalysisModeSchema.parse(mode);
		const root = realpathSync(workspace),
			db = this.database();
		db.exec("BEGIN IMMEDIATE");
		try {
			const existing = this.session(id);
			if (existing && existing.workspace !== root)
				throw new Error("Session workspace identity changed");
			if (
				db
					.prepare(
						"SELECT id FROM analysis_receipts WHERE session_id=? AND status IN ('running','termination-unconfirmed') AND NOT EXISTS (SELECT 1 FROM analysis_recovery WHERE receipt_id=analysis_receipts.id)",
					)
					.get(id)
			)
				throw new Error(
					"Analysis work is active or termination is unconfirmed",
				);
			db.prepare(
				"INSERT INTO analysis_sessions(id,workspace,mode) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET mode=excluded.mode",
			).run(id, root, mode);
			db.exec("COMMIT");
		} catch (e) {
			db.exec("ROLLBACK");
			throw e;
		}
		return { workspace: root, mode };
	}
	start(receipt: AnalysisReceipt) {
		const db = this.database();
		db.exec("BEGIN IMMEDIATE");
		try {
			const session = this.session(receipt.sessionId);
			if (
				!session ||
				session.mode === "off" ||
				session.workspace !== receipt.workspace
			)
				throw new Error(
					"Enable Analysis mode for this exact session workspace first",
				);
			const retained = db
				.prepare("SELECT COUNT(*) AS n FROM analysis_receipts")
				.get();
			if (Number(retained?.n) >= 250)
				throw new Error(
					"Analysis ledger capacity reached; no automatic evidence deletion",
				);
			const active = db
				.prepare(
					"SELECT id FROM analysis_receipts WHERE status IN ('running','termination-unconfirmed') AND NOT EXISTS (SELECT 1 FROM analysis_recovery WHERE receipt_id=analysis_receipts.id)",
				)
				.all();
			if (active.length >= 2)
				throw new Error(
					"Two analysis workers are already reserved; no automatic retry",
				);
			db.prepare(
				"INSERT INTO analysis_receipts(id,session_id,status,body) VALUES(?,?,?,?)",
			).run(
				receipt.id,
				receipt.sessionId,
				receipt.status,
				JSON.stringify(receipt),
			);
			db.exec("COMMIT");
		} catch (e) {
			db.exec("ROLLBACK");
			throw e;
		}
	}
	save(receipt: AnalysisReceipt, semanticGraph?: unknown) {
		if (receipt.result && receipt.resultHash !== digest(receipt.result))
			throw new Error("Evidence result hash mismatch");
		const db = this.database();
		db.exec("BEGIN IMMEDIATE");
		try {
			if (receipt.result?.semanticGraph) {
				if (
					semanticGraph === undefined ||
					digestCanonicalValue(semanticGraph) !==
						receipt.result.semanticGraph.graphHash
				)
					throw new Error("Semantic evidence integrity mismatch");
				const body = JSON.stringify(semanticGraph);
				if (Buffer.byteLength(body) > 128 * 1024 * 1024)
					throw new Error("Semantic graph exceeds storage budget");
				const used = db
					.prepare(
						"SELECT COALESCE(SUM(length(CAST(body AS BLOB))),0) AS n FROM analysis_semantic_graphs",
					)
					.get();
				if (Number(used?.n) + Buffer.byteLength(body) > 512 * 1024 * 1024)
					throw new Error(
						"Semantic ledger capacity reached; no automatic evidence deletion",
					);
				db.prepare(
					"INSERT INTO analysis_semantic_graphs(receipt_id,session_id,body) VALUES(?,?,?)",
				).run(receipt.id, receipt.sessionId, body);
			} else if (semanticGraph !== undefined)
				throw new Error("Unbound semantic evidence");
			const updated = db
				.prepare(
					"UPDATE analysis_receipts SET status=?,body=? WHERE id=? AND session_id=? AND status='running' AND NOT EXISTS (SELECT 1 FROM analysis_recovery WHERE receipt_id=analysis_receipts.id)",
				)
				.run(
					receipt.status,
					JSON.stringify(receipt),
					receipt.id,
					receipt.sessionId,
				);
			if (updated.changes !== 1)
				throw new Error("Final evidence receipts are immutable");
			db.exec("COMMIT");
		} catch (error) {
			db.exec("ROLLBACK");
			throw error;
		}
	}
	/** Read scoped, receipt-bound graph data. Integrity is not producer authentication. */
	semanticGraph(
		sessionId: string,
		id: string,
	): Record<string, unknown> | undefined {
		const receipt = this.get(sessionId, id);
		if (!receipt.result?.semanticGraph) return undefined;
		const row = this.database()
			.prepare(
				"SELECT body FROM analysis_semantic_graphs WHERE receipt_id=? AND session_id=?",
			)
			.get(id, sessionId);
		if (!row || Buffer.byteLength(String(row.body)) > 128 * 1024 * 1024)
			throw new Error("Semantic evidence missing or oversized");
		const graph = JSON.parse(String(row.body)) as Record<string, unknown>;
		if (
			digestCanonicalValue(graph) !== receipt.result.semanticGraph.graphHash ||
			graph.graph_id !== receipt.result.semanticGraph.graphId
		)
			throw new Error("Stored semantic evidence integrity mismatch");
		return graph;
	}
	recovery(id: string) {
		const row = this.database()
			.prepare(
				"SELECT body_hash,at,audit_hash FROM analysis_recovery WHERE receipt_id=?",
			)
			.get(id);
		if (!row) return undefined;
		const value = {
			receiptId: id,
			bodyHash: String(row.body_hash),
			at: String(row.at),
			action: "reservation-released-without-replay",
		};
		if (digest(value) !== row.audit_hash)
			throw new Error("Recovery journal integrity mismatch");
		return { ...value, auditHash: String(row.audit_hash) };
	}
	releaseReservation(receipt: AnalysisReceipt, expectedHash: string) {
		const db = this.database();
		db.exec("BEGIN IMMEDIATE");
		try {
			const current = this.get(receipt.sessionId, receipt.id);
			if (
				digest(current) !== expectedHash ||
				!["running", "termination-unconfirmed"].includes(current.status)
			)
				throw new Error("Reservation changed during recovery");
			if (this.recovery(receipt.id))
				throw new Error("Reservation was already released");
			const event = {
				receiptId: receipt.id,
				bodyHash: expectedHash,
				at: new Date().toISOString(),
				action: "reservation-released-without-replay",
			};
			db.prepare(
				"INSERT INTO analysis_recovery(receipt_id,body_hash,at,audit_hash) VALUES(?,?,?,?)",
			).run(receipt.id, expectedHash, event.at, digest(event));
			db.exec("COMMIT");
			return { ...event, auditHash: digest(event) };
		} catch (e) {
			db.exec("ROLLBACK");
			throw e;
		}
	}

	summaries(sessionId: string) {
		return this.database()
			.prepare(`SELECT id,status,
			json_extract(body,'$.createdAt') AS createdAt,
			json_extract(body,'$.input.target') AS target,
			json_extract(body,'$.resultHash') AS resultHash,
			json_extract(body,'$.error') AS error,
 (SELECT at FROM analysis_recovery WHERE receipt_id=analysis_receipts.id) AS reservationReleasedAt
			FROM analysis_receipts WHERE session_id=? ORDER BY rowid DESC LIMIT 100`)
			.all(sessionId);
	}
	get(sessionId: string, id: string) {
		const row = this.database()
			.prepare("SELECT body FROM analysis_receipts WHERE id=? AND session_id=?")
			.get(id, sessionId);
		if (!row) throw new Error("Evidence receipt not found in this session");
		const value = JSON.parse(String(row.body)) as AnalysisReceipt;
		if (value.result && digest(value.result) !== value.resultHash)
			throw new Error("Stored evidence integrity mismatch");
		const recovery = this.recovery(id);
		if (recovery && recovery.bodyHash !== digest(value))
			throw new Error("Recovered receipt integrity mismatch");
		return value;
	}
}
