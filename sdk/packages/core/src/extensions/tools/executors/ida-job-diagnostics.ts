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
};
const jobs = new Map<string, JobRecord>();

/** Host-written PID receipts, not process-name polling or CPU-as-progress. */
export async function runObservedIda(
	command: string,
	args: string[],
	outputDir: string,
	timeoutMs: number,
	signal?: AbortSignal,
) {
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
	const job = {
		id,
		pid: null as number | null,
		status: "starting",
		startedAt: new Date().toISOString(),
		executable: redactSensitiveText(command, secretValues),
		receiptPath,
		scriptProgressPath,
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
		appendFileSync(
			receiptPath,
			`${JSON.stringify({ timestamp: new Date().toISOString(), ...event })}\n`,
			{ mode: 0o600 },
		);
		publishIndex();
	};
	jobs.set(id, job);
	// Never evict an active or uncertain job to make room.
	for (const [key, value] of jobs) {
		if (jobs.size <= 32) break;
		if (["process-exited", "failed", "cancelled"].includes(value.status))
			jobs.delete(key);
	}
	try {
		record({ phase: "starting", id, executable: job.executable });
		const result = await runSupervised(
			command,
			args,
			timeoutMs,
			signal,
			(pid) => {
				job.pid = pid;
				job.status = "running";
				record({ phase: "launched", id, pid });
			},
			{ CLINE_IDA_PROGRESS_PATH: scriptProgressPath },
		);
		result.stderr = redactSensitiveText(result.stderr, secretValues);
		result.stdout = redactSensitiveText(result.stdout, secretValues);
		job.status = result.outputDrainTimedOut
			? "termination-unconfirmed"
			: result.cancelled
				? "cancelled"
				: result.timedOut || result.exitCode !== 0
					? "failed"
					: "process-exited";
		Object.assign(job, {
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
		});
		listObservedIdaJobs();
		return {
			...result,
			idaJob: { ...job },
			progressMeaning:
				"Explicit script phases only; process CPU and missing output are not progress proof.",
		};
	} catch (error) {
		job.status = job.pid === null ? "failed" : "termination-unconfirmed";
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
	return Array.from(recorded.values(), (job) => {
		let phases: string[] = [];
		try {
			const fd = openSync(job.scriptProgressPath, "r");
			try {
				const data = Buffer.alloc(64 * 1024);
				const size = readSync(fd, data, 0, data.length, 0);
				phases = data
					.subarray(0, size)
					.toString("utf8")
					.split("\n")
					.flatMap((line) => {
						try {
							const phase = JSON.parse(line).phase;
							return [
								"input-loaded",
								"auto-analysis-waiting",
								"analysis-complete",
								"decompiler-initialized",
								"output-written",
								"script-failed",
								"script-exiting",
							].includes(phase)
								? [phase]
								: [];
						} catch {
							return [];
						}
					});
			} finally {
				closeSync(fd);
			}
		} catch {
			/* No script evidence yet; never infer a hang. */
		}
		return {
			...job,
			phases,
			lastPhase: phases.at(-1) ?? "No script phase observed",
			stateMeaning:
				"Last recorded host state; not a fresh process-identity or liveness check",
		};
	});
}

/** Included in fixed IDA scripts; a phase is an observation, not semantic proof. */
export function idaProgressPrelude(outputDir: string) {
	return `import json, datetime, os
PROGRESS_PATH = os.environ.get("CLINE_IDA_PROGRESS_PATH", ${JSON.stringify(join(outputDir, "ida-script-progress.jsonl"))})
def cline_phase(phase):
    try:
        with open(PROGRESS_PATH, "a", encoding="utf-8") as progress:
            progress.write(json.dumps({"phase":phase,"timestamp":datetime.datetime.now(datetime.timezone.utc).isoformat()})+"\\n")
    except OSError:
        pass # Observability must not replace the original error or prevent idc.qexit.
`;
}
