import { randomUUID } from "node:crypto";
import {
	appendFileSync,
	openSync,
	readSync,
	closeSync,
	writeFileSync,
	mkdirSync,
	renameSync,
	readdirSync,
	lstatSync,
	unlinkSync,
} from "node:fs";
import { join } from "node:path";
import { resolveClineDataDir } from "@cline/shared/storage";
import { runSupervised } from "./supervised-process";
import {
	redactSensitiveText,
	prepareProcessEnvironment,
} from "./process-environment-policy";

type JobRecord = {
	id: string;
	pid: number | null;
	status: string;
	startedAt: string;
	executable: string;
	receiptPath: string;
	scriptProgressPath: string;
	exitCode?: number | null;
	signal?: string | null;
	timeoutMs?: number;
	phaseTimeoutMs?: number;
	scriptPhasesExpected?: boolean;
	lastHostUpdateAt?: string;
	endedAt?: string;
	timeoutPhase?: string;
	phaseDeadlineAt?: string;
	elapsedMs?: number;
	phaseRemainingMs?: number;
	autoAnalysisElapsedMs?: number;
	autoAnalysisRemainingMs?: number;
	autoAnalysisState?: "pending" | "running" | "finished";
	timedOut?: boolean;
};
// A complete analysis hour plus bounded startup/decompile/save/export headroom.
export const DEFAULT_IDA_TIMEOUT_MS = 75 * 60 * 1000;
export const DEFAULT_IDA_PHASE_TIMEOUT_MS = 60 * 60 * 1000;
export const IDA_STOP_GRACE_MS = 5_000;
const activeClocks = new Map<
	string,
	{
		started: number;
		phaseStarted: number;
		autoStarted?: number;
		autoElapsed?: number;
	}
>();

const jobs = new Map<string, JobRecord>();

const SCRIPT_PHASES = [
	"input-loaded",
	"auto-analysis-waiting",
	"analysis-complete",
	"decompiler-initialized",
	"decompilation-started",
	"output-written",
	"script-failed",
	"script-exiting",
	"database-saving",
	"database-saved",
];

function readScriptPhases(job: JobRecord) {
	const phases: string[] = [];
	let lastPhaseAt: string | undefined;
	try {
		const info = lstatSync(job.scriptProgressPath);
		if (!info.isFile() || info.isSymbolicLink()) return { phases, lastPhaseAt };
		const fd = openSync(job.scriptProgressPath, "r");
		try {
			const data = Buffer.alloc(64 * 1024);
			const size = readSync(fd, data, 0, data.length, 0);
			for (const line of data.subarray(0, size).toString("utf8").split("\n")) {
				try {
					const event = JSON.parse(line);
					if (!SCRIPT_PHASES.includes(event.phase)) continue;
					phases.push(event.phase);
					const timestamp = Date.parse(event.timestamp);
					if (Number.isFinite(timestamp) && timestamp <= Date.now() + 60_000)
						lastPhaseAt = new Date(timestamp).toISOString();
				} catch {
					/* Incomplete final line is not evidence. */
				}
			}
		} finally {
			closeSync(fd);
		}
	} catch {
		/* Missing phases never prove a hung process. */
	}
	return { phases, lastPhaseAt };
}

export function describeObservedIdaJob(job: JobRecord, now = Date.now()) {
	const { phases, lastPhaseAt } = readScriptPhases(job);
	const started = Date.parse(job.startedAt);
	const clock = activeClocks.get(job.id);
	const ended = Date.parse(
		job.endedAt ?? job.lastHostUpdateAt ?? job.startedAt,
	);
	const elapsedMs =
		job.endedAt && job.elapsedMs !== undefined
			? job.elapsedMs
			: clock
				? Math.max(0, performance.now() - clock.started)
				: (job.elapsedMs ??
					(Number.isFinite(started) && Number.isFinite(ended)
						? Math.max(0, ended - started)
						: 0));
	const remainingMs =
		typeof job.timeoutMs === "number" && Number.isFinite(job.timeoutMs)
			? Math.max(0, job.timeoutMs - elapsedMs)
			: null;
	const autoElapsed =
		clock?.autoStarted === undefined
			? job.autoAnalysisElapsedMs
			: (clock.autoElapsed ??
				Math.max(0, performance.now() - clock.autoStarted));
	return {
		...job,
		observedAt: clock
			? new Date(now).toISOString()
			: (job.lastHostUpdateAt ?? job.endedAt ?? job.startedAt),
		clockSource: clock ? "live-host-monotonic" : "recorded-host-snapshot",
		phaseRemainingMs:
			clock && job.phaseDeadlineAt
				? Math.min(
						remainingMs ?? 0,
						Math.max(
							0,
							(job.phaseTimeoutMs ?? 0) -
								(performance.now() - clock.phaseStarted),
						),
					)
				: (job.phaseRemainingMs ?? null),
		autoAnalysisElapsedMs: autoElapsed ?? null,
		autoAnalysisRemainingMs:
			autoElapsed === undefined
				? null
				: Math.min(
						remainingMs ?? 0,
						Math.max(
							0,
							(job.phaseTimeoutMs ?? DEFAULT_IDA_PHASE_TIMEOUT_MS) -
								autoElapsed,
						),
					),
		resultLabel: job.timedOut
			? "Timed out — partial results; database save is not guaranteed"
			: undefined,
		phases,
		lastPhaseAt,
		lastPhase:
			phases.at(-1) ??
			(job.scriptPhasesExpected === false
				? "Script phase monitoring not supported; overall deadline enforced"
				: "No script phase observed"),
		elapsedMs,
		remainingMs,
		deadlineAt:
			typeof job.timeoutMs === "number" &&
			Number.isFinite(job.timeoutMs) &&
			job.timeoutMs > 0 &&
			job.timeoutMs <= DEFAULT_IDA_TIMEOUT_MS &&
			Number.isFinite(started)
				? new Date(started + job.timeoutMs).toISOString()
				: null,
		stateMeaning:
			"Last recorded host state; not a fresh process-identity or liveness check",
	};
}

export function formatIdaProgress(
	job: ReturnType<typeof describeObservedIdaJob>,
) {
	const seconds = Math.floor(job.elapsedMs / 1000);
	const remaining =
		job.remainingMs === null
			? "unknown"
			: `${Math.ceil(job.remainingMs / 1000)}s`;
	const phaseRemaining =
		job.phaseRemainingMs === null
			? "unknown"
			: `${Math.ceil(job.phaseRemainingMs / 1000)}s`;
	const autoRemaining =
		job.autoAnalysisRemainingMs === null
			? "not started"
			: `${Math.ceil(job.autoAnalysisRemainingMs / 1000)}s`;
	return `[IDA progress] ${job.status}; PID ${job.pid ?? "not launched"}; phase: ${job.lastPhase}; elapsed ${seconds}s; deadline remaining ${remaining}; phase budget remaining ${phaseRemaining}; auto-analysis budget remaining ${autoRemaining} (${job.autoAnalysisState ?? "pending"}); ${job.resultLabel ?? "completion percentage unavailable"}; job ${job.id}`;
}

/** Host-written PID receipts, not process-name polling or CPU-as-progress. */
export async function runObservedIda(
	command: string,
	args: string[],
	outputDir: string,
	timeoutMs: number,
	signal?: AbortSignal,
	options: {
		phaseTimeoutMs?: number;
		scriptPhasesExpected?: boolean;
		onProgress?: (job: ReturnType<typeof describeObservedIdaJob>) => void;
	} = {},
) {
	const phaseTimeoutMs = Math.min(
		options.phaseTimeoutMs ?? DEFAULT_IDA_PHASE_TIMEOUT_MS,
		timeoutMs,
	);
	if (
		!Number.isFinite(timeoutMs) ||
		timeoutMs <= 0 ||
		timeoutMs > DEFAULT_IDA_TIMEOUT_MS ||
		!Number.isFinite(phaseTimeoutMs) ||
		phaseTimeoutMs <= 0 ||
		(options.phaseTimeoutMs ?? phaseTimeoutMs) > DEFAULT_IDA_PHASE_TIMEOUT_MS
	)
		throw new Error("Invalid IDA execution deadline");
	const secretValues = prepareProcessEnvironment().secretValues;
	if (
		Array.from(jobs.values()).filter((job) =>
			["starting", "running", "termination-unconfirmed"].includes(job.status),
		).length >= 32
	)
		throw new Error(
			"IDA job diagnostics capacity reached; inspect active or uncertain jobs before starting more.",
		);
	const id = randomUUID();
	const receiptPath = join(outputDir, `ida-job-${id}.jsonl`);
	const scriptProgressPath = join(outputDir, `ida-script-progress-${id}.jsonl`);
	const stopPath = join(outputDir, `ida-stop-${id}.json`);
	const job: JobRecord = {
		id,
		pid: null as number | null,
		status: "starting",
		startedAt: new Date().toISOString(),
		executable: redactSensitiveText(command, secretValues),
		receiptPath,
		scriptProgressPath,
		timeoutMs,
		phaseTimeoutMs,
		autoAnalysisState: "pending",
		scriptPhasesExpected: options.scriptPhasesExpected !== false,
		lastHostUpdateAt: new Date().toISOString(),
		endedAt: undefined as string | undefined,
		timeoutPhase: undefined as string | undefined,
		phaseDeadlineAt:
			options.scriptPhasesExpected === false
				? undefined
				: new Date(Date.now() + phaseTimeoutMs).toISOString(),
	};
	const indexRoot = join(resolveClineDataDir(), "analysis", "ida-job-index");
	mkdirSync(indexRoot, { recursive: true, mode: 0o700 });
	const indexPath = join(indexRoot, `${Date.now()}-${id}.json`);
	const publishIndex = () => {
		const stage = `${indexPath}.${process.pid}.stage`;
		writeFileSync(stage, JSON.stringify({ ...job, hostPid: process.pid }), {
			mode: 0o600,
		});
		renameSync(stage, indexPath);
	};
	// No command arguments, script source, target bytes, or credentials in receipts.
	writeFileSync(receiptPath, "", { flag: "wx", mode: 0o600 });
	writeFileSync(scriptProgressPath, "", { mode: 0o600 });
	const record = (event: Record<string, unknown>) => {
		job.lastHostUpdateAt = new Date().toISOString();
		appendFileSync(
			receiptPath,
			`${JSON.stringify({ timestamp: new Date().toISOString(), ...event })}\n`,
			{ mode: 0o600 },
		);
		publishIndex();
	};
	const phaseAbort = new AbortController();
	const forwardAbort = () => phaseAbort.abort();
	if (signal?.aborted) forwardAbort();
	else signal?.addEventListener("abort", forwardAbort, { once: true });
	let observedPhase = "No script phase observed";
	const clock: {
		started: number;
		phaseStarted: number;
		autoStarted?: number;
		autoElapsed?: number;
	} = {
		started: performance.now(),
		phaseStarted: performance.now(),
	};
	activeClocks.set(id, clock);
	let stopTimer: ReturnType<typeof setTimeout> | undefined;
	const requestPhaseStop = () => {
		// Fixed owned scripts can save if they reach a cancellation boundary in time.
		// auto_wait itself may not return; the grace never promises a saved database.
		try {
			writeFileSync(stopPath, JSON.stringify({ stop: true }), {
				flag: "wx",
				mode: 0o600,
			});
		} catch {
			/* Deadline still enforced. */
		}
		stopTimer = setTimeout(() => phaseAbort.abort(), IDA_STOP_GRACE_MS);
	};
	let lastPublished = 0;
	let phaseTimedOut = false;
	const publishProgress = () => {
		const snapshot = describeObservedIdaJob(job);
		const changed = snapshot.lastPhase !== observedPhase;
		if (changed) {
			observedPhase = snapshot.lastPhase;
			clock.phaseStarted = performance.now();
			if (options.scriptPhasesExpected !== false)
				job.phaseDeadlineAt = new Date(
					Date.now() +
						Math.min(phaseTimeoutMs, snapshot.remainingMs ?? phaseTimeoutMs),
				).toISOString();
			if (
				observedPhase === "auto-analysis-waiting" &&
				clock.autoStarted === undefined
			) {
				clock.autoStarted = performance.now();
				job.autoAnalysisState = "running";
			} else if (
				observedPhase !== "auto-analysis-waiting" &&
				clock.autoStarted !== undefined &&
				clock.autoElapsed === undefined
			) {
				clock.autoElapsed = Math.max(0, performance.now() - clock.autoStarted);
				job.autoAnalysisState = "finished";
			}
			try {
				record({ phase: "script-phase-observed", scriptPhase: observedPhase });
			} catch {
				/* Journal I/O must not crash the host's timer callback. */
			}
		}
		const current = describeObservedIdaJob(job);
		job.elapsedMs = current.elapsedMs;
		job.phaseRemainingMs = current.phaseRemainingMs ?? undefined;
		job.autoAnalysisElapsedMs = current.autoAnalysisElapsedMs ?? undefined;
		job.autoAnalysisRemainingMs = current.autoAnalysisRemainingMs ?? undefined;
		if (changed || performance.now() - lastPublished >= 30_000) {
			lastPublished = performance.now();
			try {
				record({
					phase: "budget-snapshot",
					elapsedMs: current.elapsedMs,
					autoAnalysisRemainingMs: current.autoAnalysisRemainingMs,
				});
			} catch {
				/* Snapshot storage cannot alter the supervised job. */
			}
			try {
				options.onProgress?.({
					...current,
					phaseDeadlineAt: job.phaseDeadlineAt,
				});
			} catch {
				/* Observer cannot alter execution. */
			}
		}
		if (
			options.scriptPhasesExpected !== false &&
			job.status === "running" &&
			performance.now() -
				(observedPhase === "auto-analysis-waiting"
					? (clock.autoStarted ?? clock.phaseStarted)
					: clock.phaseStarted) >=
				phaseTimeoutMs &&
			!phaseTimedOut &&
			!phaseAbort.signal.aborted
		) {
			phaseTimedOut = true;
			job.timeoutPhase = observedPhase;
			try {
				record({
					phase: "phase-deadline-exceeded",
					lastScriptPhase: observedPhase,
					phaseTimeoutMs,
				});
			} catch {
				/* The deadline remains enforced even if diagnostic storage fails. */
			} finally {
				requestPhaseStop();
			}
		}
	};
	let progressTimer: ReturnType<typeof setInterval> | undefined;
	jobs.set(id, job);
	// Never evict an active or uncertain job to make room.
	for (const [key, value] of jobs) {
		if (jobs.size <= 32) break;
		if (["process-exited", "failed", "cancelled"].includes(value.status))
			jobs.delete(key);
	}
	try {
		record({ phase: "starting", id, executable: job.executable });
		publishProgress();
		progressTimer = setInterval(publishProgress, 1000);
		const result = await runSupervised(
			command,
			args,
			timeoutMs,
			phaseAbort.signal,
			(pid) => {
				job.pid = pid;
				job.status = "running";
				record({ phase: "launched", id, pid });
				clock.phaseStarted = performance.now();
				lastPublished = 0;
				publishProgress();
			},
			{
				CLINE_IDA_PROGRESS_PATH: scriptProgressPath,
				CLINE_IDA_STOP_PATH: stopPath,
			},
		);
		if (phaseTimedOut) {
			result.timedOut = true;
			result.cancelled = signal?.aborted === true;
		}
		result.stderr = redactSensitiveText(result.stderr, secretValues);
		result.stdout = redactSensitiveText(result.stdout, secretValues);
		job.timedOut = result.timedOut;
		if (result.timedOut && !job.timeoutPhase) job.timeoutPhase = observedPhase;
		job.status = result.outputDrainTimedOut
			? "termination-unconfirmed"
			: result.cancelled
				? "cancelled"
				: result.timedOut || result.exitCode !== 0
					? "failed"
					: "process-exited";
		// Freeze completed snapshots; a desktop restart must never invent a live countdown.
		const finalSnapshot = describeObservedIdaJob(job);
		job.elapsedMs = finalSnapshot.elapsedMs;
		clock.autoElapsed = finalSnapshot.autoAnalysisElapsedMs ?? undefined;
		job.autoAnalysisElapsedMs =
			finalSnapshot.autoAnalysisElapsedMs ?? undefined;
		job.autoAnalysisRemainingMs =
			finalSnapshot.autoAnalysisRemainingMs ?? undefined;
		job.phaseRemainingMs = finalSnapshot.phaseRemainingMs ?? undefined;
		if (clock.autoStarted !== undefined) job.autoAnalysisState = "finished";
		Object.assign(job, {
			endedAt: new Date().toISOString(),
			exitCode: result.exitCode,
			signal: result.signal ?? null,
		});
		record({
			phase: job.status,
			id,
			pid: job.pid,
			exitCode: result.exitCode,
			signal: result.signal ?? null,
			timedOut: result.timedOut,
			cancelled: result.cancelled,
			stderrTail: result.stderr.slice(-16_384),
			timeoutPhase: job.timeoutPhase,
		});
		try {
			options.onProgress?.(describeObservedIdaJob(job));
		} catch {
			/* Read-only observer. */
		}
		listObservedIdaJobs();
		return {
			...result,
			idaJob: { ...job },
			progressMeaning:
				"Explicit script phases only; process CPU and missing output are not progress proof.",
		};
	} catch (error) {
		job.status = job.pid === null ? "failed" : "termination-unconfirmed";
		job.endedAt = new Date().toISOString();
		try {
			record({
				phase: "launch-or-observer-failure",
				id,
				reason: redactSensitiveText(
					error instanceof Error ? error.message : String(error),
					secretValues,
				).slice(-2000),
			});
		} catch {
			/* Keep the original error and termination uncertainty, not an observer error. */
		}
		throw Object.assign(
			error instanceof Error ? error : new Error(String(error)),
			{
				terminationUnconfirmed: job.pid !== null,
			},
		);
	} finally {
		clearInterval(progressTimer);
		clearTimeout(stopTimer);
		activeClocks.delete(id);
		signal?.removeEventListener("abort", forwardAbort);
	}
}

export function listObservedIdaJobs() {
	const recorded = new Map(jobs);
	try {
		const root = join(resolveClineDataDir(), "analysis", "ida-job-index");
		const files = readdirSync(root)
			.filter((name) => /^\d+-[0-9a-f-]{36}\.json$/.test(name))
			.sort()
			.reverse();
		for (const name of files.slice(0, 64)) {
			const path = join(root, name),
				info = lstatSync(path);
			if (!info.isFile() || info.isSymbolicLink() || info.size > 8192) continue;
			const fd = openSync(path, "r");
			let value: Record<string, unknown>;
			try {
				const buffer = Buffer.alloc(8192);
				value = JSON.parse(
					buffer
						.subarray(0, readSync(fd, buffer, 0, buffer.length, 0))
						.toString("utf8"),
				);
			} finally {
				closeSync(fd);
			}
			if (
				typeof value.id !== "string" ||
				!name.endsWith(`${value.id}.json`) ||
				typeof value.receiptPath !== "string" ||
				typeof value.scriptProgressPath !== "string" ||
				typeof value.status !== "string"
			)
				continue;
			if (!recorded.has(value.id))
				recorded.set(value.id, value as unknown as JobRecord);
		}
		// Only completed history is pruned; running/uncertain records require review.
		for (const name of files.slice(32)) {
			const path = join(root, name);
			try {
				if (lstatSync(path).isSymbolicLink()) continue;
				const old = recorded.get(name.slice(name.indexOf("-") + 1, -5));
				if (
					old &&
					["process-exited", "failed", "cancelled"].includes(old.status)
				)
					unlinkSync(path);
			} catch {
				/* Retention must not block read-only diagnostics. */
			}
		}
	} catch {
		/* Host may not have started any IDA jobs yet. */
	}
	return Array.from(recorded.values(), (job) => describeObservedIdaJob(job));
}

/** Included in fixed IDA scripts; a phase is an observation, not semantic proof. */
export function idaProgressPrelude(outputDir: string) {
	return `import json, datetime, os
PROGRESS_PATH = os.environ.get("CLINE_IDA_PROGRESS_PATH", ${JSON.stringify(join(outputDir, "ida-script-progress.jsonl"))})
def cline_check_stop():
    stop_path = os.environ.get("CLINE_IDA_STOP_PATH")
    if not stop_path or not os.path.isfile(stop_path):
        return
    # No arbitrary script or path from the request; only this owned database.
    import ida_loader, idc
    cline_phase("database-saving")
    if ida_loader.save_database(idc.get_idb_path(), ida_loader.DBFL_COMP):
        cline_phase("database-saved")
    # The fixed outer handler records failure and qexit(1), never success.
    raise RuntimeError("IDA analysis deadline exceeded; partial database only")
def cline_phase(phase):
    try:
        with open(PROGRESS_PATH, "a", encoding="utf-8") as progress:
            progress.write(json.dumps({"phase":phase,"timestamp":datetime.datetime.now(datetime.timezone.utc).isoformat()})+"\\n")
    except OSError:
        pass # Observability must not replace the original error or prevent idc.qexit.
`;
}
