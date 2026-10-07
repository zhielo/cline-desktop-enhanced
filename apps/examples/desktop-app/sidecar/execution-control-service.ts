import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, realpathSync } from "node:fs";
import { mkdir, realpath, stat, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join } from "node:path";
import { promisify } from "node:util";
import {
	LiveDebuggerInputSchema,
	type ProcessSessionManager,
	probeProcessStartTokenAsync,
	ReverseEngineeringInputSchema,
} from "@cline/core";
import { loadSqliteDb, type SqliteDb } from "@cline/shared/db";
import { z } from "zod";
import type { AnalysisTaskOrchestrator } from "./analysis-task-orchestrator";
import { digest, ownedFile } from "./incident-artifacts";
import { windowsJobInvocation } from "./windows-job-launcher";

const Id = z.string().uuid();
export const PipelineInput = z
	.object({
		operation: z.literal("execution_pipeline"),
		operation_id: Id,
		title: z.string().min(1).max(120),
		trusted_host_work: z.literal(true),
		parallel: z.number().int().min(1).max(2).default(1),
		archive_logs: z.boolean().default(false),
		stages: z
			.array(
				z
					.object({
						id: z.string().regex(/^[A-Za-z0-9_-]{1,50}$/),
						backend: z.enum(["shell", "static", "debugger"]),
						depends_on: z.array(z.string().max(50)).max(12).default([]),
						request: z.record(z.string(), z.unknown()),
						timeout_ms: z.number().int().min(1000).max(1200000).default(120000),
						resource: z.string().max(150).optional(),
					})
					.strict(),
			)
			.min(1)
			.max(12),
	})
	.strict();
const Shell = z
	.object({
		executable: z.string().min(1).max(1000),
		args: z.array(z.string().max(8192)).max(100).default([]),
		interactive: z.boolean().default(false),
		replay_safety: z
			.enum(["inspection-declared", "side-effects"])
			.default("side-effects"),
		native_job: z.boolean().default(false),
		memory_mib: z.number().int().min(128).max(4096).default(512),
		max_processes: z.number().int().min(1).max(32).default(16),
	})
	.strict();
type Stage = z.infer<typeof PipelineInput>["stages"][number] & {
	target_sha256?: string;
	compare_sha256?: string;
	executable_sha256?: string;
};
type Pipeline = Omit<z.infer<typeof PipelineInput>, "stages"> & {
	stages: Stage[];
};
type Job = {
	id: string;
	status:
		| "queued"
		| "starting"
		| "running"
		| "awaiting-input"
		| "completed"
		| "failed"
		| "cancelled"
		| "uncertain";
	processId?: string;
	startedAt?: string;
	completedAt?: string;
	exitCode?: number | null;
	error?: string;
	result?: unknown;
	stdoutHash?: string;
	stderrHash?: string;
	outputComplete?: boolean;
	droppedBytes?: number;
	firstOutputMs?: number;
	durationMs?: number;
	outputBytes?: number;
	logPath?: string;
	backend?: string;
	logTruncated?: boolean;
	resultTruncated?: boolean;
	resultHash?: string;
};
export type ExecutionReceipt = {
	id: string;
	workspace: string;
	owner: string;
	planId: string;
	requestHash: string;
	operationId: string;
	revision: number;
	status:
		| "accepted"
		| "starting"
		| "running"
		| "completed"
		| "failed"
		| "cancelled"
		| "uncertain";
	request: Pipeline;
	jobs: Job[];
	events: { at: string; action: string }[];
	createdAt: string;
	error?: string;
	hash?: string;
};
type Adapter = (
	input: Record<string, unknown>,
	signal: AbortSignal,
) => Promise<unknown>;
const safe = (s: unknown) =>
	String(s instanceof Error ? s.message : s)
		.replace(
			/((?:token|secret|password|authorization|cookie)\s*[:=])\s*[^\s,;]+/gi,
			"$1[REDACTED]",
		)
		.slice(0, 1000);
function validateGraph(p: Pipeline) {
	const ids = new Set(p.stages.map((s) => s.id));
	if (ids.size !== p.stages.length) throw new Error("Duplicate stage IDs");
	const visiting = new Set<string>(),
		done = new Set<string>();
	const visit = (id: string) => {
		if (visiting.has(id)) throw new Error("Stage dependency cycle");
		if (done.has(id)) return;
		const s = p.stages.find((s) => s.id === id);
		if (!s) throw new Error("Missing stage dependency");
		visiting.add(id);
		for (const dep of s.depends_on) visit(dep);
		visiting.delete(id);
		done.add(id);
	};
	for (const id of ids) visit(id);
}
async function executablePath(value: string) {
	let path = value;
	if (!isAbsolute(path)) {
		const { stdout } = await promisify(execFile)(
			process.platform === "win32" ? "where.exe" : "which",
			[value],
			{ timeout: 5000, maxBuffer: 8192 },
		);
		path = stdout.trim().split(/\r?\n/)[0];
	}
	const result = await realpath(path);
	if (!(await stat(result)).isFile())
		throw new Error("Executable is not a regular file");
	return result;
}
async function fileHash(path: string) {
	const fs = await import("node:fs");
	const s = await stat(path);
	if (s.size > 512 * 1024 * 1024)
		throw new Error("Executable hash budget exceeded");
	return new Promise<string>((res, rej) => {
		const h = createHash("sha256"),
			r = fs.createReadStream(path);
		r.on("data", (d) => h.update(d));
		r.on("error", rej);
		r.on("end", () => res(h.digest("hex")));
	});
}
export class ExecutionControlService {
	private db?: SqliteDb;
	private owner = randomUUID();
	private active = new Set<string>();
	private resources = new Set<string>();
	private workspaceUse = new Map<string, number>();
	private workspaceWriters = new Set<string>();
	constructor(
		private options: {
			dbPath: string;
			logRoot: string;
			tasks: AnalysisTaskOrchestrator;
			processes: ProcessSessionManager;
			static: Adapter;
			debugger: Adapter;
		},
	) {}
	private database() {
		if (!this.db) {
			mkdirSync(dirname(this.options.dbPath), { recursive: true, mode: 0o700 });
			this.db = loadSqliteDb(this.options.dbPath);
			this.db.exec(
				"PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS execution_receipts(id TEXT PRIMARY KEY,workspace TEXT NOT NULL,operation_id TEXT NOT NULL,revision INTEGER NOT NULL,body TEXT NOT NULL,UNIQUE(workspace,operation_id));",
			);
		}
		return this.db;
	}
	close() {
		this.db?.close?.();
		this.db = undefined;
	}
	private save(c: ExecutionReceipt, previous?: number) {
		const plain = { ...c, hash: undefined },
			body = JSON.stringify({ ...plain, hash: digest(JSON.stringify(plain)) });
		if (Buffer.byteLength(body) > 2 * 1024 * 1024)
			throw new Error("Execution receipt budget exceeded");
		if (previous === undefined)
			this.database()
				.prepare("INSERT INTO execution_receipts VALUES(?,?,?,?,?)")
				.run(c.id, c.workspace, c.operationId, c.revision, body);
		else {
			const r = this.database()
				.prepare(
					"UPDATE execution_receipts SET revision=?,body=? WHERE id=? AND workspace=? AND revision=?",
				)
				.run(c.revision, body, c.id, c.workspace, previous);
			if (!r.changes) throw new Error("Execution receipt changed");
		}
	}
	private checkpoint(c: ExecutionReceipt, action: string) {
		const r = c.revision;
		c.revision++;
		if (c.events.length >= 300) c.events.shift();
		c.events.push({ at: new Date().toISOString(), action });
		this.save(c, r);
	}
	get(root: string, id: string) {
		Id.parse(id);
		const row = this.database()
			.prepare("SELECT body FROM execution_receipts WHERE workspace=? AND id=?")
			.get(realpathSync(root), id);
		if (!row) throw new Error("Execution receipt is not in this workspace");
		const c = JSON.parse(String(row.body)) as ExecutionReceipt;
		const { hash, ...plain } = c;
		if (hash !== digest(JSON.stringify({ ...plain, hash: undefined })))
			throw new Error("Execution receipt integrity mismatch");
		return {
			...c,
			controlUnavailable:
				(c.owner !== this.owner || !this.active.has(id)) &&
				["accepted", "starting", "running"].includes(c.status),
		};
	}
	list(root: string) {
		return this.database()
			.prepare(
				"SELECT id FROM execution_receipts WHERE workspace=? ORDER BY rowid DESC LIMIT 100",
			)
			.all(realpathSync(root))
			.map((r) => {
				const c = this.get(root, String(r.id));
				return {
					id: c.id,
					title: c.request.title,
					status: c.controlUnavailable ? "uncertain" : c.status,
					revision: c.revision,
					operationId: c.operationId,
				};
			});
	}
	async prepare(root: string, value: unknown) {
		const p: Pipeline = PipelineInput.parse(value);
		validateGraph(p);
		for (const stage of p.stages) {
			if (stage.backend === "shell") {
				const s = Shell.parse(stage.request);
				if (
					s.args.some(
						(arg, i) =>
							/(?:^--?(?:password|token|secret|api-key)|(?:password|token|secret|api[_-]?key)\s*=)/i.test(
								arg,
							) ||
							(i > 0 &&
								/^(--?(password|token|secret|api-key))$/i.test(s.args[i - 1])),
					)
				)
					throw new Error(
						"Credential-bearing argv is not permitted in durable receipts",
					);
				s.executable = await executablePath(s.executable);
				if (
					!/^(node|bun|python(?:3(?:\.\d+)?)?|git|cargo|rustc|powershell|pwsh|cmd|bash|sh)(\.exe)?$/i.test(
						basename(s.executable),
					)
				)
					throw new Error(
						"Only reviewed host runtime commands are allowed here; unknown binaries require an isolated worker",
					);
				if (s.native_job && s.interactive)
					throw new Error(
						"Native job wrapper interactive PTY is not validated; use a non-interactive native job or the existing terminal",
					);
				if (s.native_job && process.platform !== "win32")
					throw new Error(
						"Native Windows job limits are unavailable; use an isolated worker for hard Linux resource limits",
					);
				stage.executable_sha256 = await fileHash(s.executable);
				stage.request = s;
			} else {
				const request =
					stage.backend === "static"
						? ReverseEngineeringInputSchema.parse(stage.request)
						: LiveDebuggerInputSchema.parse(stage.request);
				if (
					stage.backend === "static" &&
					(![
						"inspect",
						"scan_strings",
						"forensic_report",
						"apk_security_report",
						"verify_apk_signature",
						"compare_apks",
						"advanced_analysis",
						"analyze",
						"decompile",
						"disassemble_smali",
					].includes(request.operation) ||
						("script_path" in request && request.script_path))
				)
					throw new Error(
						"Static pipeline accepts fixed built-in operations only",
					);
				if ("target" in request && request.target) {
					const f = await ownedFile(root, request.target);
					request.target = f.path;
					stage.target_sha256 = f.sha256;
				}
				if (
					stage.backend === "debugger" &&
					"pid" in request &&
					typeof request.pid === "number" &&
					request.operation !== "process_identity"
				) {
					const identity = await probeProcessStartTokenAsync(request.pid);
					if (identity.status !== "found")
						throw new Error("Debugger process identity unavailable");
					(request as Record<string, unknown>).pid_start_token = identity.token;
				}
				if (
					"compare_target" in request &&
					typeof request.compare_target === "string"
				) {
					const f = await ownedFile(root, request.compare_target);
					request.compare_target = f.path;
					(stage as Stage & { compare_sha256?: string }).compare_sha256 =
						f.sha256;
				}
				stage.request = request;
			}
			// Canonical shared resource prevents conflicting writers even if callers omit a label.
			stage.resource =
				stage.backend === "shell"
					? `workspace:${realpathSync(root)}`
					: stage.backend === "debugger"
						? `debugger:${stage.request.pid ?? stage.request.target ?? "discovery"}`
						: `analysis:${stage.request.output_directory ?? stage.request.target ?? "health"}`;
		}
		return this.options.tasks.prepare({
			workspaceRoot: root,
			kind: "execution",
			request: p,
			timeoutMs: Math.min(
				1200000,
				p.stages.reduce((n, s) => n + s.timeout_ms, 0) + 30000,
			),
			maxOutputBytes: 2 * 1024 * 1024,
		});
	}
	async start(root: string, planId: string, token: string) {
		const plan = this.options.tasks
			.list(root)
			.find((p) => p.id === planId && p.kind === "execution");
		if (!plan) throw new Error("Execution plan unavailable");
		const p = plan.request as unknown as Pipeline;
		const prior = this.database()
			.prepare(
				"SELECT id,body FROM execution_receipts WHERE workspace=? AND operation_id=?",
			)
			.get(realpathSync(root), p.operation_id);
		if (prior) {
			const c = this.get(root, String(prior.id));
			if (c.requestHash !== plan.requestHash)
				throw new Error("Operation ID was reused with different content");
			return {
				accepted: true,
				id: c.id,
				existing: true,
				completed: ["completed", "failed", "cancelled"].includes(c.status),
			};
		}
		await this.options.tasks.consume({
			workspaceRoot: root,
			planId,
			executionToken: token,
			kind: "execution",
			request: plan.request,
		});
		const c: ExecutionReceipt = {
			id: randomUUID(),
			workspace: realpathSync(root),
			owner: this.owner,
			planId,
			requestHash: plan.requestHash,
			operationId: p.operation_id,
			revision: 0,
			status: "accepted",
			request: p,
			jobs: p.stages.map((s) => ({ id: s.id, status: "queued" })),
			events: [],
			createdAt: new Date().toISOString(),
		};
		try {
			if (this.list(root).length >= 100)
				throw new Error("Execution receipt capacity reached");
			this.save(c);
		} catch (error) {
			this.options.tasks.fail(planId, error);
			throw error;
		}
		this.active.add(c.id);
		void this.run(c).catch(() => {
			this.active.delete(
				c.id,
			); /* An interrupted journal is uncertain and never replayed. */
		});
		return { accepted: true, id: c.id, completed: false };
	}
	private async run(c: ExecutionReceipt) {
		const running = new Map<string, Promise<void>>(),
			resources = this.resources;
		try {
			c.status = "running";
			this.checkpoint(c, "accepted-by-executor");
			for (;;) {
				this.options.tasks.signal(c.planId).throwIfAborted();
				const ready = c.request.stages.filter(
					(s) =>
						c.jobs.find((j) => j.id === s.id)?.status === "queued" &&
						s.depends_on.every(
							(d) => c.jobs.find((j) => j.id === d)?.status === "completed",
						),
				);
				for (const s of ready) {
					if (running.size >= c.request.parallel) break;
					if (
						resources.has(s.resource!) ||
						this.workspaceWriters.has(c.workspace) ||
						(s.backend === "shell" &&
							(this.workspaceUse.get(c.workspace) ?? 0) > 0)
					)
						continue;
					resources.add(s.resource!);
					this.workspaceUse.set(
						c.workspace,
						(this.workspaceUse.get(c.workspace) ?? 0) + 1,
					);
					if (s.backend === "shell") this.workspaceWriters.add(c.workspace);
					const promise = this.runStage(c, s).finally(() => {
						running.delete(s.id);
						resources.delete(s.resource!);
						this.workspaceUse.set(
							c.workspace,
							(this.workspaceUse.get(c.workspace) ?? 1) - 1,
						);
						if (s.backend === "shell")
							this.workspaceWriters.delete(c.workspace);
					});
					running.set(s.id, promise);
				}
				if (!running.size) {
					if (ready.length) {
						await new Promise((r) => setTimeout(r, 100));
						continue;
					}
					break;
				}
				await Promise.race(running.values());
				if (
					c.jobs.some((j) =>
						["failed", "uncertain", "cancelled"].includes(j.status),
					)
				)
					break;
			}
			if (running.size) {
				await this.options.tasks.cancel(c.planId);
				await Promise.allSettled(running.values());
			}
			for (const job of c.jobs)
				if (job.status === "queued") {
					job.status = "cancelled";
					job.error = "Dependency failed or pipeline cancelled; not executed";
				}
			c.status = c.jobs.every((j) => j.status === "completed")
				? "completed"
				: c.jobs.some((j) => j.status === "uncertain")
					? "uncertain"
					: c.jobs.some((j) => j.status === "failed")
						? "failed"
						: "cancelled";
			this.checkpoint(c, "terminal-receipt");
			if (c.status === "completed")
				this.options.tasks.complete(c.planId, c, "execution-control");
			else this.options.tasks.fail(c.planId, c.status);
		} catch (error) {
			for (const j of c.jobs) {
				if (
					j.processId &&
					["starting", "running", "awaiting-input"].includes(j.status)
				)
					await this.options.processes
						.signal(`execution:${c.id}`, j.processId, "kill")
						.catch(() => {});
			}
			await Promise.allSettled(running.values());
			for (const j of c.jobs) if (j.status === "queued") j.status = "cancelled";
			c.status = c.jobs.some(
				(j) =>
					j.status === "uncertain" ||
					["starting", "running"].includes(j.status),
			)
				? "uncertain"
				: "cancelled";
			c.error = safe(error);
			try {
				this.checkpoint(c, "cancelled-or-budget-exhausted");
				this.options.tasks.fail(c.planId, error);
			} catch {}
		} finally {
			this.active.delete(c.id);
		}
	}
	private async runStage(c: ExecutionReceipt, stage: Stage) {
		const j = c.jobs.find((j) => j.id === stage.id)!;
		j.status = "starting";
		j.startedAt = new Date().toISOString();
		this.checkpoint(c, `stage-start:${j.id}`);
		const started = Date.now(),
			parent = this.options.tasks.signal(c.planId),
			signal = AbortSignal.any([parent, AbortSignal.timeout(stage.timeout_ms)]);
		try {
			signal.throwIfAborted();
			if (
				stage.target_sha256 &&
				(await ownedFile(c.workspace, String(stage.request.target))).sha256 !==
					stage.target_sha256
			)
				throw new Error("Stage artifact changed after approval");
			if (
				stage.compare_sha256 &&
				(await ownedFile(c.workspace, String(stage.request.compare_target)))
					.sha256 !== stage.compare_sha256
			)
				throw new Error("Comparison artifact changed after approval");
			if (stage.backend !== "shell") {
				const result = await (stage.backend === "static"
					? this.options.static
					: this.options.debugger)(stage.request, signal);
				signal.throwIfAborted();
				const encoded = JSON.stringify(result);
				j.resultHash = digest(encoded);
				j.resultTruncated = Buffer.byteLength(encoded) > 65536;
				j.result = j.resultTruncated
					? {
							notice: "Result exceeds retained receipt budget",
							sha256: j.resultHash,
						}
					: result;
				j.status =
					(result as { succeeded?: boolean })?.succeeded === false ||
					(result as { exitCode?: number | null })?.exitCode === null ||
					(typeof (result as { exitCode?: number })?.exitCode === "number" &&
						(result as { exitCode: number }).exitCode !== 0) ||
					(
						result as {
							cancelled?: boolean;
							timedOut?: boolean;
							outputDrainTimedOut?: boolean;
						}
					)?.cancelled ||
					(result as { timedOut?: boolean })?.timedOut ||
					(result as { outputDrainTimedOut?: boolean })?.outputDrainTimedOut ||
					["failed", "blocked", "cancelled"].includes(
						(result as { result?: { status?: string } })?.result?.status ?? "",
					)
						? "failed"
						: "completed";
				j.outputComplete = true;
			} else {
				const s = Shell.parse(stage.request);
				if ((await fileHash(s.executable)) !== stage.executable_sha256)
					throw new Error("Executable changed after approval");
				const launch = s.native_job
					? windowsJobInvocation(
							s.executable,
							s.args,
							c.workspace,
							s.memory_mib,
							s.max_processes,
						)
					: {
							executable: s.executable,
							args: s.args,
							containment: "process-tree-control-not-OS-sandbox",
						};
				j.backend = launch.containment;
				const process = await this.options.processes.start({
					ownerSessionId: `execution:${c.id}`,
					toolCallId: stage.id,
					executable: launch.executable,
					args: launch.args,
					cwd: c.workspace,
					interactive: s.interactive,
				});
				j.processId = process.processId;
				j.status = "running";
				this.checkpoint(c, `process-start:${stage.id}`);
				let cursor = 0,
					bytes = 0,
					dropped = 0,
					log = "";
				const stdout = createHash("sha256"),
					stderr = createHash("sha256");
				for (;;) {
					if (signal.aborted) {
						await this.options.processes.signal(
							`execution:${c.id}`,
							process.processId,
							"kill",
						);
						await this.confirmStopped(c, j);
						break;
					}
					const read = this.options.processes.read(
						`execution:${c.id}`,
						process.processId,
						cursor,
					);
					cursor = read.nextCursor;
					dropped = Math.max(dropped, read.droppedOutputBytes);
					for (const chunk of read.chunks) {
						if (j.firstOutputMs === undefined)
							j.firstOutputMs = Date.now() - started;
						(chunk.stream === "stdout" ? stdout : stderr).update(chunk.text);
						bytes += Buffer.byteLength(chunk.text);
						if (
							c.request.archive_logs &&
							Buffer.byteLength(log) < 1024 * 1024
						) {
							const remaining = 1024 * 1024 - Buffer.byteLength(log),
								buf = Buffer.from(chunk.text);
							let end = Math.min(remaining, buf.length);
							while (end > 0 && end < buf.length && (buf[end] & 0xc0) === 0x80)
								end--;
							log += buf.subarray(0, end).toString("utf8");
							if (end < buf.length) j.logTruncated = true;
						}
					}
					if (
						c.request.archive_logs &&
						Buffer.byteLength(log) >= 1024 * 1024 &&
						bytes > Buffer.byteLength(log)
					)
						j.logTruncated = true;
					const snap = this.options.processes.get(
						`execution:${c.id}`,
						process.processId,
					);
					if (!snap) {
						j.status = "uncertain";
						throw new Error(
							"Process identity unavailable; execution outcome is uncertain",
						);
					}
					if (["exited", "failed", "cancelled"].includes(snap.state)) {
						j.exitCode = snap.exitCode;
						j.status =
							snap.state === "cancelled"
								? "cancelled"
								: snap.state === "exited" &&
										snap.exitCode === 0 &&
										!snap.outputDrainTimedOut
									? "completed"
									: "failed";
						j.outputComplete = !dropped && !snap.outputDrainTimedOut;
						break;
					}
					await new Promise((r) => setTimeout(r, 100));
				}
				j.stdoutHash = stdout.digest("hex");
				j.stderrHash = stderr.digest("hex");
				j.outputBytes = bytes;
				j.droppedBytes = dropped;
				if (c.request.archive_logs) {
					const root = join(this.options.logRoot, c.id);
					await mkdir(root, { recursive: true, mode: 0o700 });
					j.logPath = join(root, `${stage.id}.log`);
					await writeFile(j.logPath, log, { flag: "wx", mode: 0o600 });
				}
			}
		} catch (error) {
			j.status = signal.aborted ? "cancelled" : "failed";
			j.error = safe(error);
			if (j.processId) {
				await this.options.processes
					.signal(`execution:${c.id}`, j.processId, "kill")
					.catch(() => {
						j.status = "uncertain";
					});
				await this.confirmStopped(
					c,
					j,
					signal.aborted ? "cancelled" : "failed",
				);
			}
		} finally {
			j.durationMs = Date.now() - started;
			j.completedAt = new Date().toISOString();
			this.checkpoint(c, `stage-finish:${stage.id}`);
		}
	}
	private async confirmStopped(
		c: ExecutionReceipt,
		j: Job,
		terminal: "cancelled" | "failed" = "cancelled",
	) {
		const deadline = Date.now() + 3000;
		for (;;) {
			const snap = this.options.processes.get(
				`execution:${c.id}`,
				j.processId!,
			);
			if (!snap) {
				j.status = "uncertain";
				throw new Error(
					"Process identity unavailable; execution outcome is uncertain",
				);
			}
			if (["exited", "failed", "cancelled"].includes(snap.state)) {
				j.exitCode = snap.exitCode;
				j.status = terminal;
				j.outputComplete = false;
				return;
			}
			if (Date.now() >= deadline) {
				j.status = "uncertain";
				j.error = "Termination requested but exit was not confirmed";
				return;
			}
			await new Promise((r) => setTimeout(r, 50));
		}
	}
	resize(
		root: string,
		id: string,
		stageId: string,
		columns: number,
		rows: number,
	) {
		const c = this.get(root, id),
			j = c.jobs.find((j) => j.id === stageId);
		if (
			c.owner !== this.owner ||
			!this.active.has(id) ||
			!j?.processId ||
			j.status !== "running"
		)
			throw new Error("PTY control unavailable");
		return this.options.processes.resize(
			`execution:${id}`,
			j.processId,
			columns,
			rows,
		);
	}
	async input(root: string, id: string, stageId: string, text: string) {
		const c = this.get(root, id);
		if (c.owner !== this.owner || !this.active.has(id))
			throw new Error("Input unavailable after owner loss; no process replay");
		const j = c.jobs.find((j) => j.id === stageId);
		if (!j?.processId || !["running", "awaiting-input"].includes(j.status))
			throw new Error("Stage is not accepting input");
		if (text.length > 8192) throw new Error("Input budget exceeded");
		await this.options.processes.writeStdin(
			`execution:${id}`,
			j.processId,
			text,
		);
		return { sent: true, retained: false };
	}
	cancel(root: string, id: string) {
		const c = this.get(root, id);
		if (c.owner !== this.owner || !this.active.has(id))
			throw new Error(
				"Owner control unavailable; use explicit process-identity recovery, never replay",
			);
		return this.options.tasks.cancel(c.planId);
	}
	async reconcile(root: string, id: string) {
		const c = this.get(root, id);
		await this.options.processes.initializeRecovery();
		return {
			receipt: c,
			status: c.controlUnavailable ? "uncertain" : c.status,
			processes: c.jobs
				.filter((j) => j.processId)
				.map((j) => {
					try {
						return this.options.processes.get(`execution:${id}`, j.processId!);
					} catch {
						return {
							processId: j.processId,
							status: "unknown",
							exitCode: "unavailable",
						};
					}
				}),
			notice:
				"Reconciliation is read-only. Missing exit evidence does not prove completion; recovered stdin/output are unavailable.",
		};
	}
}
