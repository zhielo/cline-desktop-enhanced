import { randomUUID } from "node:crypto";
import { constants, mkdirSync, realpathSync } from "node:fs";
import {
	lstat,
	open,
	readFile,
	realpath,
	rm,
	writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { loadSqliteDb, type SqliteDb } from "@cline/shared/db";
import { z } from "zod";
import type { AnalysisTaskOrchestrator } from "./analysis-task-orchestrator";
import { parseAndroidDebugEvidence } from "./android-debug-evidence";
import { apkPackage, digest, ownedFile } from "./incident-artifacts";

const Hash = z.string().regex(/^[a-f0-9]{64}$/);
export const IncidentRequest = z
	.object({
		operation: z.enum([
			"observe_apk",
			"collect_apk_debug",
			"launch_apk",
			"validate_apk_patch",
			"rollback_apk",
		]),
		debug_report_paths: z
			.array(
				z
					.string()
					.regex(
						/^(?:\/data\/tombstones\/tombstone_\d{2}|\/data\/anr\/anr_[A-Za-z0-9_.-]{1,120})$/,
					),
			)
			.min(1)
			.max(6)
			.optional(),
		use_root: z.boolean().default(false),
		target: z.string().min(1),
		compare_target: z.string().min(1).optional(),
		package: z.string().regex(/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/),
		device_serial: z.string().min(1).max(200),
		reproduction: z.string().min(1).max(4000),
		expected: z.string().min(1).max(2000),
		duration_seconds: z.number().int().min(2).max(120).default(30),
		rollback_case_id: z.string().uuid().optional(),
		target_sha256: Hash.optional(),
		candidate_sha256: Hash.optional(),
	})
	.strict();
type Request = z.infer<typeof IncidentRequest>;
type Result = Record<string, unknown>;
type Execute = (
	input: Record<string, unknown>,
	signal?: AbortSignal,
) => Promise<Result>;
export type IncidentCase = {
	id: string;
	workspace: string;
	owner: string;
	planId: string;
	revision: number;
	status: "accepted" | "running" | "completed" | "incomplete";
	request: Request;
	stage: string;
	events: { at: string; stage: string }[];
	observations: Result[];
	failures: { kind: string; text: string; sha256: string }[];
	coverage: string[];
	result?: string;
	error?: string;
	review?: {
		reproductionCompleted: boolean;
		regressionPassed: boolean;
		notes: string;
		at: string;
	};
	correlations: Result[];
	hash?: string;
};
function redact(text: string) {
	return text
		.replace(
			/((?:authorization|token|secret|password|cookie|api[_-]?key)\s*[:=]\s*)[^\s,;]+/gi,
			"$1[REDACTED]",
		)
		.replace(/\bBearer\s+[A-Za-z0-9_.-]+/gi, "Bearer [REDACTED]")
		.slice(0, 32000);
}
export function packageProcesses(text: string, pkg: string) {
	const rows = text
			.trim()
			.split(/\r?\n/)
			.map((line) => line.trim().split(/\s+/)),
		column = rows[0]?.indexOf("PID") ?? -1;
	if (column < 0)
		throw new Error(
			"Unsupported Android process table; cannot scope log collection",
		);
	return rows
		.slice(1)
		.filter((row) => row.at(-1) === pkg || row.at(-1)?.startsWith(`${pkg}:`))
		.map((row) => ({ pid: Number(row[column]), name: row.at(-1)! }))
		.filter((row) => Number.isSafeInteger(row.pid) && row.pid > 0)
		.slice(0, 8);
}
export function packageFailures(text: string, pkg: string) {
	const escaped = pkg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
		marker = new RegExp(
			`(?:Process:\\s*${escaped}(?=[:,\\s]|$)|>>>\\s*${escaped}(?=[:\\s]|$)|ANR in\\s+${escaped}(?=[:\\s]|$))`,
		);
	// Never persist the unfiltered global crash buffer. Separate exception/tombstone records first.
	return text
		.split(/(?=^.*(?:FATAL EXCEPTION:|\*\*\* \*\*\* \*\*\*|ANR in ))/m)
		.filter((block) => marker.test(block))
		.slice(0, 20)
		.map((block) => {
			const safe = redact(block),
				kind = /ANR in /.test(safe)
					? "anr"
					: /signal \d+|>>>/.test(safe)
						? "native-crash"
						: /FATAL EXCEPTION:/.test(safe)
							? "java-crash"
							: "unclassified-failure";
			return { kind, text: safe, sha256: digest(safe) };
		});
}
async function readDiagnosticBytes(expected: string, hash: string) {
	const path = await realpath(expected);
	if (path !== expected)
		throw new Error("Diagnostic report symlink not permitted");
	const before = await lstat(path);
	if (!before.isFile() || before.isSymbolicLink() || before.size > 524288)
		throw new Error("Diagnostic report integrity/budget mismatch");
	const handle = await open(
		path,
		constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
	);
	try {
		const info = await handle.stat();
		if (
			!info.isFile() ||
			info.size !== before.size ||
			info.ino !== before.ino ||
			info.dev !== before.dev
		)
			throw new Error("Diagnostic report identity changed");
		const buffer = Buffer.alloc(info.size + 1);
		let size = 0;
		while (size < buffer.length) {
			const part = await handle.read(buffer, size, buffer.length - size, size);
			if (!part.bytesRead) break;
			size += part.bytesRead;
		}
		const after = await handle.stat(),
			raw = buffer.subarray(0, size);
		if (size !== info.size || after.size !== info.size || digest(raw) !== hash)
			throw new Error("Diagnostic report integrity mismatch");
		return raw;
	} finally {
		await handle.close();
	}
}
export class ApkIncidentService {
	private db?: SqliteDb;
	private readonly owner = randomUUID();
	private readonly active = new Set<string>();
	constructor(
		private options: {
			dbPath: string;
			cacheRoot: string;
			tasks: AnalysisTaskOrchestrator;
			android: Execute;
			reverse: Execute;
			sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
		},
	) {}
	private database() {
		if (!this.db) {
			mkdirSync(dirname(this.options.dbPath), { recursive: true, mode: 0o700 });
			this.db = loadSqliteDb(this.options.dbPath);
			this.db.exec(
				"PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS apk_incidents(id TEXT PRIMARY KEY, workspace TEXT NOT NULL, revision INTEGER NOT NULL, body TEXT NOT NULL);",
			);
		}
		return this.db;
	}
	close() {
		this.db?.close?.();
		this.db = undefined;
	}
	private save(c: IncidentCase, previous?: number) {
		const clean = { ...c, hash: undefined },
			body = JSON.stringify({ ...clean, hash: digest(JSON.stringify(clean)) });
		if (Buffer.byteLength(body) > 1024 * 1024)
			throw new Error("Incident evidence budget exceeded");
		if (previous === undefined)
			this.database()
				.prepare(
					"INSERT INTO apk_incidents(id,workspace,revision,body) VALUES(?,?,?,?)",
				)
				.run(c.id, c.workspace, c.revision, body);
		else {
			const changed = this.database()
				.prepare(
					"UPDATE apk_incidents SET revision=?,body=? WHERE id=? AND workspace=? AND revision=?",
				)
				.run(c.revision, body, c.id, c.workspace, previous);
			if (!changed.changes)
				throw new Error("Incident changed; reload before writing");
		}
		return c;
	}
	get(
		root: string,
		id: string,
	): IncidentCase & { controlUnavailable: boolean } {
		z.string().uuid().parse(id);
		const row = this.database()
			.prepare("SELECT body FROM apk_incidents WHERE id=? AND workspace=?")
			.get(id, realpathSync(root));
		if (!row) throw new Error("Incident not in this workspace");
		const c = JSON.parse(String(row.body)) as IncidentCase;
		const { hash, ...clean } = c;
		if (hash !== digest(JSON.stringify({ ...clean, hash: undefined })))
			throw new Error("Incident evidence integrity mismatch");
		// A different process may still own the operation. Reading must never reclaim or replay it.
		return {
			...c,
			controlUnavailable:
				c.owner !== this.owner && ["accepted", "running"].includes(c.status),
		};
	}
	list(root: string) {
		return this.database()
			.prepare(
				"SELECT id FROM apk_incidents WHERE workspace=? ORDER BY rowid DESC LIMIT 100",
			)
			.all(realpathSync(root))
			.map((row) => {
				const c = this.get(root, String(row.id));
				return {
					id: c.id,
					status: c.status,
					stage: c.stage,
					package: c.request.package,
					revision: c.revision,
					controlUnavailable: c.controlUnavailable,
				};
			});
	}
	private checkpoint(c: IncidentCase, stage: string) {
		const previous = c.revision;
		c.revision++;
		c.stage = stage;
		c.events.push({ at: new Date().toISOString(), stage });
		this.save(c, previous);
	}
	async prepare(root: string, value: unknown) {
		const request = IncidentRequest.parse(value),
			original = await ownedFile(root, request.target);
		if (apkPackage(original.bytes) !== request.package)
			throw new Error("Original APK manifest/package mismatch");
		request.target = original.path;
		request.target_sha256 = original.sha256;
		if (
			request.operation === "collect_apk_debug" &&
			!request.debug_report_paths?.length
		)
			throw new Error("Explicit diagnostic report paths required");
		if (
			request.operation !== "collect_apk_debug" &&
			(request.use_root || request.debug_report_paths)
		)
			throw new Error(
				"Root diagnostic reads belong to a separate collect_apk_debug plan",
			);

		if (request.compare_target) {
			const candidate = await ownedFile(root, request.compare_target);
			if (apkPackage(candidate.bytes) !== request.package)
				throw new Error("Candidate APK manifest/package mismatch");
			request.compare_target = candidate.path;
			request.candidate_sha256 = candidate.sha256;
		}
		if (
			["validate_apk_patch", "rollback_apk"].includes(request.operation) &&
			!request.compare_target
		)
			throw new Error("Original and candidate APKs required");
		if (request.operation === "rollback_apk") {
			if (!request.rollback_case_id)
				throw new Error(
					"Prior patch-validation incident required for rollback",
				);
			const prior = this.get(root, request.rollback_case_id);
			if (
				prior.request.operation !== "validate_apk_patch" ||
				prior.request.target_sha256 !== request.target_sha256 ||
				prior.request.candidate_sha256 !== request.candidate_sha256 ||
				prior.request.package !== request.package ||
				prior.request.device_serial !== request.device_serial ||
				!prior.events.some((e) => e.stage === "candidate-installed")
			)
				throw new Error(
					"Rollback identity differs from the recorded installation",
				);
		}
		return this.options.tasks.prepare({
			workspaceRoot: root,
			kind: "device",
			request,
			timeoutMs: request.duration_seconds * 1000 + 180000,
			maxOutputBytes: 1024 * 1024,
		});
	}
	async start(root: string, planId: string, token: string) {
		const plan = this.options.tasks
			.list(root)
			.find((p) => p.id === planId && p.kind === "device");
		if (!plan) throw new Error("Device incident plan not found");
		const request = IncidentRequest.parse(plan.request);
		// consume revalidates original target; independently bind the secondary candidate too.
		if (
			request.compare_target &&
			(await ownedFile(root, request.compare_target)).sha256 !==
				request.candidate_sha256
		)
			throw new Error("Candidate changed after approval");
		await this.options.tasks.consume({
			workspaceRoot: root,
			planId,
			executionToken: token,
			kind: "device",
			request,
		});
		let c: IncidentCase;
		try {
			if (this.list(root).length >= 100)
				throw new Error(
					"Incident limit reached; archive evidence before starting more cases",
				);
			c = {
				id: randomUUID(),
				workspace: realpathSync(root),
				owner: this.owner,
				planId,
				revision: 0,
				status: "accepted",
				request,
				stage: "accepted",
				events: [],
				observations: [],
				failures: [],
				coverage: [],
				correlations: [],
			};
			this.save(c);
			this.active.add(c.id);
		} catch (error) {
			this.options.tasks.fail(planId, error);
			throw error;
		}
		void this.run(c).catch(() => {
			/* run persists all terminal failures; never replay from a status read. */
		});
		return {
			accepted: true,
			id: c.id,
			planId,
			status: "accepted",
			completed: false,
		};
	}
	private async call(c: IncidentCase, operation: string, extra: Result = {}) {
		const signal = this.options.tasks.signal(c.planId);
		signal.throwIfAborted();
		const result = await this.options.android(
			{
				operation,
				device_serial: c.request.device_serial,
				package: c.request.package,
				timeout_ms: 15000,
				...extra,
			},
			signal,
		);
		if (
			result.cancelled ||
			result.timedOut ||
			(result.exitCode !== undefined && result.exitCode !== 0)
		)
			throw new Error(`Android ${operation} incomplete`);
		signal.throwIfAborted();
		return result;
	}
	private async installedHash(c: IncidentCase) {
		const directory = join(this.options.cacheRoot, c.id);
		mkdirSync(directory, { recursive: true, mode: 0o700 });
		const output = join(directory, `${randomUUID()}.apk`);
		try {
			const receipt = await this.call(c, "pull_apk_bounded", {
				output_path: output,
			});
			if (receipt.succeeded !== true || receipt.coverage !== "base-apk-only")
				throw new Error("Installed package identity incomplete");
			const bytes = await readFile(output);
			const sha256 = digest(bytes);
			if (receipt.sha256 !== sha256 || apkPackage(bytes) !== c.request.package)
				throw new Error("Installed APK identity mismatch");
			c.coverage.push(
				"Installed identity covers base APK only; split contents and app data are not attested.",
			);
			return sha256;
		} finally {
			await rm(output, { force: true });
		}
	}
	private async install(c: IncidentCase, path: string, expectedHash: string) {
		// Copy an approved snapshot into private storage to avoid source mutation during installation.
		const f = await ownedFile(c.workspace, path);
		if (f.sha256 !== expectedHash)
			throw new Error("APK changed before installation");
		const { writeFile } = await import("node:fs/promises");
		const snapshot = join(this.options.cacheRoot, c.id, `${randomUUID()}.apk`);
		await writeFile(snapshot, f.bytes, { flag: "wx", mode: 0o600 });
		try {
			const verified = await this.options.reverse(
				{
					engine: "auto",
					operation: "verify_apk_signature",
					target: snapshot,
					timeout_ms: 30000,
				},
				this.options.tasks.signal(c.planId),
			);
			if (verified.verified !== true || verified.sha256 !== expectedHash)
				throw new Error(
					"APK signing verification unavailable or failed; no installation performed",
				);
			await this.call(c, "install", {
				path: snapshot,
				confirm_package_change: true,
				replace_existing: true,
				timeout_ms: 60000,
			});
		} finally {
			await rm(snapshot, { force: true });
		}
	}
	private async run(c: IncidentCase) {
		try {
			c.status = "running";
			this.checkpoint(c, "device-preflight");
			c.observations.push({
				stage: "device-preflight",
				device: await this.call(c, "device_info"),
			});
			this.checkpoint(c, "installed-identity");
			const before = await this.installedHash(c),
				expected =
					c.request.operation === "rollback_apk"
						? c.request.candidate_sha256
						: c.request.target_sha256;
			if (before !== expected)
				throw new Error(
					"Installed base APK differs from approved baseline; capture/installation blocked",
				);
			c.observations.push({ stage: "installed-identity", sha256: before });
			if (c.request.operation === "collect_apk_debug") {
				this.checkpoint(c, "explicit-diagnostic-report-read");
				const result = await this.call(c, "debug_reports", {
					debug_report_paths: c.request.debug_report_paths,
					use_root: c.request.use_root,
					acknowledge_root_read: c.request.use_root,
					confirm_sensitive_reports: true,
					timeout_ms: 120000,
				});
				if (
					result.succeeded !== true ||
					result.coverage !== "explicit-path-package-scoped-adb-observations" ||
					result.deviceSerialSha256 !== digest(c.request.device_serial)
				)
					throw new Error(
						"Diagnostic capture identity or coverage unavailable",
					);
				const reports = Array.isArray(result.reports)
					? (result.reports as Result[])
					: [];
				for (const report of reports) {
					const { text: raw, ...metadata } = report,
						text = typeof raw === "string" ? raw : "";
					if (text) {
						if (
							Buffer.byteLength(text) > 524288 ||
							digest(text) !== report.sha256
						)
							throw new Error("Diagnostic report integrity/budget mismatch");
						const output = join(
							this.options.cacheRoot,
							c.id,
							`${report.sha256}.report.txt`,
						);
						try {
							await writeFile(output, text, { flag: "wx", mode: 0o600 });
						} catch (error) {
							if ((error as NodeJS.ErrnoException).code !== "EEXIST")
								throw error;
							await readDiagnosticBytes(output, String(report.sha256));
						}
						const parsed = parseAndroidDebugEvidence(text, c.request.package);
						c.observations.push({
							stage: "diagnostic-report",
							...metadata,
							outputPath: output,
							summary: {
								nativeFrames: parsed.nativeFrames.length,
								threads: parsed.threads.length,
								deaths: parsed.deaths.length,
								findings: parsed.findings,
							},
						});
					} else
						c.observations.push({ stage: "diagnostic-report", ...metadata });
				}
				if ((await this.installedHash(c)) !== before)
					throw new Error(
						"Installed identity changed during diagnostic collection",
					);
				const initial = c.observations.find(
					(o) => o.stage === "device-preflight",
				)?.device;
				if (
					JSON.stringify(await this.call(c, "device_info")) !==
					JSON.stringify(initial)
				)
					throw new Error(
						"Device identity changed during diagnostic collection",
					);
				c.coverage.push(
					...(Array.isArray(result.limitations)
						? result.limitations.map(String)
						: []),
				);
				c.status = "completed";
				c.result =
					"Selected diagnostic reports collected as package-scoped observations. Age, root cause and absence of failures are not proven.";
				this.checkpoint(c, "diagnostic-report-completed");
				this.options.tasks.complete(c.planId, c, "apk-diagnostic-reports");
				return;
			}

			if (
				c.request.operation === "validate_apk_patch" ||
				c.request.operation === "rollback_apk"
			) {
				const rollback = c.request.operation === "rollback_apk",
					target = rollback ? c.request.target : c.request.compare_target!,
					hash = rollback
						? c.request.target_sha256!
						: c.request.candidate_sha256!;
				this.checkpoint(
					c,
					rollback
						? "rollback-install-requested"
						: "candidate-install-requested",
				);
				await this.install(c, target, hash);
				// A timeout or ambiguous install is never retried or automatically uninstalled.
				if ((await this.installedHash(c)) !== hash)
					throw new Error(
						"Post-install identity could not be confirmed; manual device inspection required",
					);
				this.checkpoint(
					c,
					rollback ? "original-restored" : "candidate-installed",
				);
				if (rollback) {
					c.status = "completed";
					c.result =
						"Original base APK restored. App data and regression behavior not verified.";
					this.checkpoint(c, "rollback-completed");
					this.options.tasks.complete(c.planId, c, "apk-incident-rollback");
					return;
				}
			}
			const baseline = await this.call(c, "crash_logs", { lines: 500 });
			if (baseline.truncated)
				c.coverage.push("Baseline crash buffer truncated");
			const known = new Set(
				packageFailures(String(baseline.stdout ?? ""), c.request.package).map(
					(f) => f.sha256,
				),
			);
			if (c.request.operation !== "observe_apk") {
				this.checkpoint(c, "explicit-launch");
				await this.call(c, "launch");
			}
			this.checkpoint(c, "reproduction-window");
			const signal = this.options.tasks.signal(c.planId),
				polls = Math.min(30, Math.ceil(c.request.duration_seconds / 2)),
				windowEnd = Date.now() + c.request.duration_seconds * 1000;
			for (let i = 0; i < polls && Date.now() < windowEnd; i++) {
				const processResult = await this.call(c, "processes");
				if (processResult.truncated)
					throw new Error(
						"Process inventory truncated; log ownership cannot be established",
					);
				const processes = packageProcesses(
						String(processResult.stdout ?? ""),
						c.request.package,
					),
					logs: Result[] = [];
				for (const process of processes) {
					try {
						const result = await this.call(c, "logcat", {
							process_id: process.pid,
							lines: 200,
						});
						logs.push({
							pid: process.pid,
							name: process.name,
							text: redact(String(result.stdout ?? "")),
							truncated: !!result.truncated,
						});
					} catch (_error) {
						signal.throwIfAborted();
						logs.push({
							pid: process.pid,
							coverage: "PID changed or log query failed; not proof of a crash",
						});
					}
				}
				const crash = await this.call(c, "crash_logs", { lines: 500 });
				if (crash.truncated && !c.coverage.includes("Crash buffer truncated"))
					c.coverage.push("Crash buffer truncated");
				for (const failure of packageFailures(
					String(crash.stdout ?? ""),
					c.request.package,
				)) {
					if (!known.has(failure.sha256) && c.failures.length < 20) {
						known.add(failure.sha256);
						c.failures.push(failure);
					}
				}
				c.observations.push({
					stage: "reproduction-window",
					at: new Date().toISOString(),
					processes,
					logs,
				});
				// Aggregate log budget; preserve ownership and truncation metadata instead of retaining unlimited repeats.
				while (
					Buffer.byteLength(JSON.stringify(c.observations)) > 256000 &&
					c.observations.length > 3
				) {
					c.observations.splice(2, 1);
					if (
						!c.coverage.includes(
							"Old process snapshots evicted at 256 KiB log budget",
						)
					)
						c.coverage.push(
							"Old process snapshots evicted at 256 KiB log budget",
						);
				}
				this.checkpoint(c, `observation-${i + 1}`);
				if (i < polls - 1)
					await (
						this.options.sleep ??
						((ms, s) =>
							new Promise<void>((res, rej) => {
								const timer = setTimeout(() => {
									s.removeEventListener("abort", abort);
									res();
								}, ms);
								const abort = () => {
									clearTimeout(timer);
									rej(new Error("Capture cancelled"));
								};
								s.addEventListener("abort", abort, { once: true });
								if (s.aborted) abort();
							}))
					)(
						Math.max(
							0,
							Math.min(
								(c.request.duration_seconds * 1000) / polls,
								windowEnd - Date.now(),
							),
						),
						signal,
					);
			}
			const finalDevice = await this.call(c, "device_info");
			const initialDevice = c.observations.find(
				(o) => o.stage === "device-preflight",
			)?.device;
			if (JSON.stringify(finalDevice) !== JSON.stringify(initialDevice))
				throw new Error("Device identity changed during reproduction");
			const finalExpected =
				c.request.operation === "validate_apk_patch"
					? c.request.candidate_sha256
					: c.request.target_sha256;
			if ((await this.installedHash(c)) !== finalExpected)
				throw new Error("APK identity changed during reproduction");
			c.coverage.push(
				"Log buffer/PID snapshots are bounded observations, not a complete tombstone/ANR trace or proof of absence. Disappearing processes do not prove OS kills. Root/Frida remain unverified.",
			);
			c.status = "completed";
			c.result = c.failures.length
				? "Matching failure evidence observed; review classification and correlation."
				: "No new matching failure observed in the bounded window. Not a verified fix; confirm reproduction and regression manually.";
			this.checkpoint(c, "capture-completed");
			this.options.tasks.complete(c.planId, c, "apk-incident-capture");
		} catch (error) {
			c.status = "incomplete";
			c.error = redact(error instanceof Error ? error.message : String(error));
			c.result =
				"Incomplete. Do not infer a fix, replay execution, or repeat an ambiguous package change.";
			try {
				this.checkpoint(c, "incomplete");
				this.options.tasks.fail(c.planId, c.error);
			} catch {
				/* original evidence remains readable if persistence itself fails */
			}
		} finally {
			this.active.delete(c.id);
		}
	}
	async diagnosticReport(root: string, id: string, hash: string) {
		Hash.parse(hash);
		const c = this.get(root, id);
		if (
			c.request.operation !== "collect_apk_debug" ||
			!c.observations.some(
				(o) => o.stage === "diagnostic-report" && o.sha256 === hash,
			)
		)
			throw new Error("Report is not bound to this incident");
		const expected = join(this.options.cacheRoot, c.id, `${hash}.report.txt`),
			raw = await readDiagnosticBytes(expected, hash);
		const text = raw.toString("utf8");
		return {
			sha256: hash,
			text,
			parsed: {
				...parseAndroidDebugEvidence(text, c.request.package),
				scope:
					"selected-device-package-scoped-adb-file-observation-not-hardware-attestation",
			},
			notice:
				"Historical report age and immutable runtime provenance are not proven",
		};
	}

	review(root: string, value: unknown) {
		const input = z
				.object({
					id: z.string().uuid(),
					revision: z.number().int(),
					reproductionCompleted: z.boolean(),
					regressionPassed: z.boolean(),
					notes: z.string().min(1).max(4000),
				})
				.strict()
				.parse(value),
			c = this.get(root, input.id);
		if (
			c.revision !== input.revision ||
			c.status !== "completed" ||
			this.active.has(c.id)
		)
			throw new Error("Reload a completed case before review");
		c.review = {
			reproductionCompleted: input.reproductionCompleted,
			regressionPassed: input.regressionPassed,
			notes: redact(input.notes),
			at: new Date().toISOString(),
		};
		delete (c as Partial<typeof c>).controlUnavailable;
		this.checkpoint(c, "operator-review");
		return c;
	}
	async correlate(root: string, id: string, revision: number, input: unknown) {
		const c = this.get(root, id);
		if (
			c.revision !== revision ||
			c.status !== "completed" ||
			this.active.has(id)
		)
			throw new Error("Reload completed case before correlation");
		const { correlateIncident } = await import("./incident-correlation");
		const result = await correlateIncident(root, c.request, input);
		const latest = this.get(root, id);
		if (latest.revision !== revision)
			throw new Error("Incident changed during correlation");
		delete (latest as Partial<typeof latest>).controlUnavailable;
		if (latest.correlations.length >= 20)
			throw new Error("Correlation budget exceeded");
		latest.correlations.push(result);
		this.checkpoint(latest, "source-correlation");
		return latest;
	}
}
