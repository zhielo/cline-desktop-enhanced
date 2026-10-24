import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, realpathSync } from "node:fs";
import { dirname } from "node:path";
import { loadSqliteDb, type SqliteDb } from "@cline/shared/db";
import { z } from "zod";
import type { AnalysisTaskPlan } from "./analysis-task-orchestrator";
const digest = (value: unknown) =>
	createHash("sha256").update(JSON.stringify(value)).digest("hex");
const Id = z.string().uuid();
const EvidenceReference = z
	.object({
		id: Id,
		resultHash: z.string().regex(/^[a-f0-9]{64}$/),
	})
	.strict();
const UnknownFields = {
	supporting: z.array(EvidenceReference).max(20).default([]),
	contradicting: z.array(EvidenceReference).max(20).default([]),
};
export type InvestigationUnknown = {
	id: string;
	revision: number;
	question: string;
	status: "open" | "needs-review" | "deferred";
	note: string;
	supporting: Array<{ id: string; resultHash: string }>;
	contradicting: Array<{ id: string; resultHash: string }>;
};
export const InvestigationMutation = z.discriminatedUnion("action", [
	z
		.object({
			action: z.literal("record_unknown"),
			id: Id,
			revision: z.number().int().nonnegative(),
			question: z.string().trim().min(1).max(1000),
			...UnknownFields,
			confirmWrite: z.literal(true),
		})
		.strict(),
	z
		.object({
			action: z.literal("update_unknown"),
			id: Id,
			revision: z.number().int().nonnegative(),
			unknownId: Id,
			unknownRevision: z.number().int().nonnegative(),
			status: z.enum(["open", "needs-review", "deferred"]),
			note: z.string().trim().min(1).max(2000),
			...UnknownFields,
			confirmWrite: z.literal(true),
		})
		.strict(),
	z
		.object({
			action: z.literal("create"),
			title: z.string().min(1).max(160),
			confirmWrite: z.literal(true),
		})
		.strict(),
	z
		.object({
			action: z.literal("checkpoint"),
			id: Id,
			revision: z.number().int().nonnegative(),
			summary: z.string().max(20000),
			questions: z.array(z.string().max(1000)).max(50),
			state: z.enum([
				"active",
				"paused",
				"authentication-required",
				"worker-disconnected",
				"closed",
			]),
			confirmWrite: z.literal(true),
		})
		.strict(),
	z
		.object({
			action: z.literal("fork"),
			id: Id,
			revision: z.number().int().nonnegative(),
			title: z.string().min(1).max(160),
			confirmWrite: z.literal(true),
		})
		.strict(),
]);
export type Investigation = {
	id: string;
	workspace: string;
	title: string;
	parentId?: string;
	revision: number;
	state: string;
	summary: string;
	questions: string[];
	/** Absent on historical cases. Never synthesize it before verifying old hashes. */
	unknowns?: InvestigationUnknown[];
	evidence: Array<Record<string, unknown>>;
	transformations: Array<Record<string, unknown>>;
	jobs: Array<{ id: string; requestHash: string; status: string }>;
	events: Array<{
		id: string;
		at: string;
		action: string;
		previous: string;
		contentHash: string;
		hash: string;
	}>;
	updatedAt: string;
};
export class InvestigationStore {
	private db?: SqliteDb;
	constructor(private path: string) {}
	private database() {
		if (!this.db) {
			mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
			this.db = loadSqliteDb(this.path);
			this.db.exec(
				"PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS investigations(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,revision INTEGER NOT NULL,body TEXT NOT NULL); CREATE INDEX IF NOT EXISTS investigations_workspace ON investigations(workspace);",
			);
		}
		return this.db;
	}
	close() {
		this.db?.close?.();
		this.db = undefined;
	}
	list(root: string) {
		return this.database()
			.prepare(
				"SELECT body FROM investigations WHERE workspace=? ORDER BY rowid DESC LIMIT 100",
			)
			.all(realpathSync(root))
			.map((r) => {
				const c = JSON.parse(String(r.body)) as Investigation;
				return {
					id: c.id,
					title: c.title,
					revision: c.revision,
					state: c.state,
					parentId: c.parentId,
					updatedAt: c.updatedAt,
				};
			});
	}
	get(root: string, id: string): Investigation {
		Id.parse(id);
		const row = this.database()
			.prepare("SELECT body FROM investigations WHERE id=? AND workspace=?")
			.get(id, realpathSync(root));
		if (!row)
			throw new Error("Investigation does not belong to this workspace");
		const c = JSON.parse(String(row.body)) as Investigation;
		let previous = "0".repeat(64);
		for (const event of c.events) {
			const { hash, ...stamped } = event;
			if (event.previous !== previous || digest(stamped) !== hash)
				throw new Error("Investigation audit chain mismatch");
			previous = hash;
		}
		if (c.events.at(-1)?.contentHash !== digest({ ...c, events: undefined }))
			throw new Error("Investigation metadata hash mismatch");
		return c;
	}
	private event(c: Investigation, action: string) {
		if (c.events.length >= 1024)
			throw new Error("Investigation audit budget reached; fork a new case");
		const previous = c.events.at(-1)?.hash ?? "0".repeat(64),
			event = {
				id: randomUUID(),
				at: new Date().toISOString(),
				action,
				previous,
			};
		c.updatedAt = event.at;
		const stamped = {
			...event,
			contentHash: digest({ ...c, events: undefined }),
		};
		c.events.push({ ...stamped, hash: digest(stamped) });
	}
	private save(c: Investigation) {
		const body = JSON.stringify(c);
		if (Buffer.byteLength(body) > 1048576)
			throw new Error("Investigation metadata budget exceeded");
		this.database()
			.prepare(
				"INSERT INTO investigations(id,workspace,revision,body) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,body=excluded.body",
			)
			.run(c.id, c.workspace, c.revision, body);
		return c;
	}
	private transaction<T>(run: () => T) {
		const db = this.database();
		db.exec("BEGIN IMMEDIATE");
		try {
			const value = run();
			db.exec("COMMIT");
			return value;
		} catch (e) {
			db.exec("ROLLBACK");
			throw e;
		}
	}
	mutate(root: string, value: unknown) {
		const m = InvestigationMutation.parse(value);
		return this.transaction(() => {
			if (m.action === "create") {
				if (this.list(root).length >= 100)
					throw new Error("Workspace investigation budget reached");
				const c: Investigation = {
					id: randomUUID(),
					workspace: realpathSync(root),
					title: m.title,
					revision: 0,
					state: "active",
					summary: "",
					questions: [],
					evidence: [],
					transformations: [],
					jobs: [],
					events: [],
					updatedAt: "",
				};
				this.event(c, "created");
				return this.save(c);
			}
			const old = this.get(root, m.id);
			if (old.revision !== m.revision)
				throw new Error("Investigation changed; reload before writing");
			if (m.action === "fork") {
				if (this.list(root).length >= 100)
					throw new Error("Workspace investigation budget reached");
				const c = {
					...structuredClone(old),
					id: randomUUID(),
					parentId: old.id,
					title: m.title,
					revision: 0,
					state: "active",
					jobs: [],
					events: [],
				};
				this.event(c, "forked-with-inherited-evidence");
				return this.save(c);
			}
			if (m.action === "record_unknown" || m.action === "update_unknown") {
				const references = [...m.supporting, ...m.contradicting];
				const seen = new Set<string>();
				for (const reference of references) {
					if (
						seen.has(reference.id) ||
						!old.evidence.some(
							(e) => e.id === reference.id && e.resultHash === reference.resultHash,
						)
					)
						throw new Error(
							"Unknown references require distinct retained case evidence with exact result hashes",
						);
					seen.add(reference.id);
				}
				const unknowns = (old.unknowns ??= []);
				if (m.action === "record_unknown") {
					if (unknowns.length >= 100)
						throw new Error("Investigation unknown budget reached");
					unknowns.push({
						id: randomUUID(),
						revision: 0,
						question: m.question,
						status: "open",
						note: "",
						supporting: m.supporting,
						contradicting: m.contradicting,
					});
				} else {
					const selected = unknowns.find((u) => u.id === m.unknownId);
					if (!selected || selected.revision !== m.unknownRevision)
						throw new Error("Unknown changed or unavailable; reload before writing");
					// Evidence links accumulate: a status update cannot erase a contradiction.
					const merge = (
						left: InvestigationUnknown["supporting"],
						right: InvestigationUnknown["supporting"],
					) => {
						const result = [...left];
						for (const reference of right)
							if (!result.some((r) => r.id === reference.id)) result.push(reference);
						if (result.length > 20) throw new Error("Unknown reference budget reached");
						return result;
					};
					if (
						m.supporting.some((r) => selected.contradicting.some((c) => c.id === r.id)) ||
						m.contradicting.some((r) => selected.supporting.some((s) => s.id === r.id))
					)
						throw new Error("Retained evidence role cannot be silently changed");
					selected.supporting = merge(selected.supporting, m.supporting);
					selected.contradicting = merge(selected.contradicting, m.contradicting);
					selected.status = m.status;
					selected.note = m.note;
					selected.revision++;
				}
				old.revision++;
				this.event(old, m.action);
				return this.save(old);
			}
			old.revision++;
			old.summary = m.summary;
			old.questions = m.questions;
			old.state = m.state;
			this.event(old, "checkpoint");
			return this.save(old);
		});
	}
	bind(root: string, id: string, plan: AnalysisTaskPlan) {
		return this.transaction(() => {
			const c = this.get(root, id);
			if (plan.workspaceRoot !== c.workspace)
				throw new Error("Task workspace mismatch");
			if (c.jobs.some((j) => j.id === plan.id)) return c;
			if (c.jobs.length >= 100)
				throw new Error("Investigation job budget reached");
			c.jobs.push({
				id: plan.id,
				requestHash: plan.requestHash,
				status: plan.status,
			});
			c.revision++;
			this.event(c, "task-bound");
			return this.save(c);
		});
	}
	record(
		root: string,
		id: string,
		plan: AnalysisTaskPlan,
		value: unknown,
		signedWorker = false,
	) {
		return this.transaction(() => {
			const c = this.get(root, id),
				resultHash = plan.evidence?.resultHash ?? digest(value),
				job = c.jobs.find((j) => j.id === plan.id);
			if (
				!job ||
				job.requestHash !== plan.requestHash ||
				plan.workspaceRoot !== c.workspace
			)
				throw new Error("Task was not bound to this investigation");
			job.status = plan.status;
			if (
				c.evidence.some(
					(e) => e.taskId === plan.id && e.resultHash === resultHash,
				)
			)
				return c;
			if (c.evidence.length >= 256)
				throw new Error("Evidence metadata budget reached");
			const outer = value as Record<string, unknown>,
				result = (outer?.result ?? outer) as Record<string, unknown>,
				data = (result?.evidence ?? {}) as Record<string, unknown>;
			// Only bounded metadata is retained. Decryption plaintext, prompts, credentials and binary buffers are not copied.
			const selected = (name: string) =>
				Array.isArray(data[name])
					? (data[name] as Record<string, unknown>[])
							.slice(0, 64)
							.map((r) =>
								Object.fromEntries(
									Object.entries(r).filter(([k]) =>
										[
											"id",
											"artifactId",
											"methodId",
											"nativeSymbolId",
											"processId",
											"classHandle",
											"classLoaderIdentity",
											"classLoaderIdentityBasis",
											"captureSessionNonce",
											"nativeArtifactId",
											"shortName",
											"longName",
											"confidence",
											"overloadAmbiguous",
											"native",
											"timestamp",
											"codeOffset",
											"name",
											"symbol",
											"classDescriptor",
											"descriptor",
											"addressHex",
											"sha256",
											"format",
											"kind",
											"verifiedBinding",
											"relativeAddress",
											"module",
											"moduleSha256",
											"moduleHashBasis",
										].includes(k),
									),
								),
							)
					: [];
			const evidence: Record<string, unknown> = {
				id: randomUUID(),
				taskId: plan.id,
				requestHash: plan.requestHash,
				resultHash,
				sourceArtifactSha256: plan.targetIdentity?.sha256,
				sourcePath: plan.target,
				engine: result.engine,
				status: result.status,
				checks:
					result.engine === "android-static-readiness" &&
					plan.request.advanced_action === "analysis_readiness"
						? data.checks
						: undefined,
				engineExecution: signedWorker
					? "reported-by-signed-worker-not-device-validated"
					: outer.succeeded === true && outer.artifactVerified === true
						? "executed-on-this-approved-input"
						: "not-established",
				provenance: signedWorker
					? "signed-worker-report-not-hardware-attestation"
					: "static-or-imported-report",
				device: signedWorker ? data.device : undefined,
				artifacts: selected("artifacts"),
				methods: selected("selectedMethods"),
				functions: selected("selectedFunctions"),
				metadataCoverage: Object.fromEntries(
					[
						"artifacts",
						"selectedMethods",
						"selectedFunctions",
						"relationships",
						"registrations",
					].map((k) => [
						k,
						{
							available: Array.isArray(data[k]) ? data[k].length : 0,
							retained: Array.isArray(data[k])
								? Math.min(data[k].length, 64)
								: 0,
						},
					]),
				),
				outputPaths:
					plan.evidence?.outputPaths.slice(0, 32) ??
					(Array.isArray(result.outputPaths)
						? result.outputPaths
								.filter(
									(p): p is string => typeof p === "string" && p.length <= 4096,
								)
								.slice(0, 32)
						: []),
				relationships: selected("relationships"),
				registrations: signedWorker ? selected("registrations") : [],
				limitations: Array.isArray(result.limitations)
					? result.limitations.slice(0, 20)
					: [],
			};
			if (Buffer.byteLength(JSON.stringify(evidence)) > 65536)
				throw new Error("Evidence metadata entry exceeds limit");
			c.evidence.push(evidence);
			if (
				[
					"compare_expressions",
					"simplify_expression",
					"deobfuscation_pass",
					"cfg_analyze",
				].includes(String(plan.request.advanced_action))
			) {
				c.transformations.push({
					id: randomUUID(),
					taskId: plan.id,
					inputSha256: plan.targetIdentity?.sha256,
					resultHash,
					pass: plan.request.advanced_action,
					verdict:
						result.engine === "z3" &&
						result.status === "completed" &&
						(result.input as { sha256?: string } | undefined)?.sha256 ===
							plan.targetIdentity?.sha256 &&
						data.equivalence === "unsat"
							? "equivalent-under-expression-model-only"
							: "heuristic-or-inconclusive",
					scope: "Expressions/IR only; not whole-method or binary equivalence",
					originalPreserved: true,
					rollback: "No original binary was modified",
					assumptions: "See approved input and exported task evidence",
				});
			}
			c.revision++;
			this.event(c, "result-linked");
			return this.save(c);
		});
	}
}
