import { randomUUID } from "node:crypto";
import {
	mkdirSync,
	readFileSync,
	renameSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { resolveClineDataDir } from "@cline/shared/storage";

const BASELINE_VERSION = 1;
const MAX_SAMPLES_PER_MODE = 200;
export const MIN_SHELL_BASELINE_SAMPLES = 50;
export const MIN_DIRECT_BASELINE_SAMPLES = 20;
export const MIN_STARTUP_ADVANTAGE_MS = 150;
export const MIN_SHELL_STARTUP_RATIO = 0.6;

type ExecutionMode = "direct" | "shell";

export interface CommandLatencyObservation {
	executionMode: ExecutionMode;
	durationMs: number;
	timeToFirstOutputMs?: number;
	outputChunkCount: number;
	outputChars: number;
	success: boolean;
}

interface StoredCommandLatencySample {
	durationMs: number;
	timeToFirstOutputMs?: number;
	outputChunkCount: number;
	outputChars: number;
	success: boolean;
	recordedAt: string;
}

export interface CommandLatencyBaselineSnapshot {
	version: 1;
	direct: StoredCommandLatencySample[];
	shell: StoredCommandLatencySample[];
	updatedAt: string;
}

export interface CommandLatencyBaselineDecision {
	status: "collecting" | "not_recommended" | "eligible";
	reason: string;
	directSamples: number;
	shellSamples: number;
	directMedianFirstOutputMs?: number;
	shellMedianFirstOutputMs?: number;
	shellMedianDurationMs?: number;
	shellStartupRatio?: number;
}

function baselinePath(): string {
	return join(resolveClineDataDir(), "command-latency-baseline.json");
}

function finiteNonnegative(value: unknown): value is number {
	return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function parseSample(value: unknown): StoredCommandLatencySample | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value))
		return undefined;
	const sample = value as Partial<StoredCommandLatencySample>;
	if (
		!finiteNonnegative(sample.durationMs) ||
		!finiteNonnegative(sample.outputChunkCount) ||
		!finiteNonnegative(sample.outputChars) ||
		typeof sample.success !== "boolean" ||
		typeof sample.recordedAt !== "string" ||
		(sample.timeToFirstOutputMs !== undefined &&
			!finiteNonnegative(sample.timeToFirstOutputMs))
	) {
		return undefined;
	}
	return sample as StoredCommandLatencySample;
}

function emptySnapshot(now = new Date()): CommandLatencyBaselineSnapshot {
	return {
		version: BASELINE_VERSION,
		direct: [],
		shell: [],
		updatedAt: now.toISOString(),
	};
}

export function readCommandLatencyBaseline(
	path = baselinePath(),
): CommandLatencyBaselineSnapshot {
	try {
		const parsed = JSON.parse(
			readFileSync(path, "utf8"),
		) as Partial<CommandLatencyBaselineSnapshot>;
		if (parsed.version !== BASELINE_VERSION) return emptySnapshot();
		return {
			version: BASELINE_VERSION,
			direct: (Array.isArray(parsed.direct) ? parsed.direct : [])
				.map(parseSample)
				.filter((sample): sample is StoredCommandLatencySample =>
					Boolean(sample),
				)
				.slice(-MAX_SAMPLES_PER_MODE),
			shell: (Array.isArray(parsed.shell) ? parsed.shell : [])
				.map(parseSample)
				.filter((sample): sample is StoredCommandLatencySample =>
					Boolean(sample),
				)
				.slice(-MAX_SAMPLES_PER_MODE),
			updatedAt:
				typeof parsed.updatedAt === "string"
					? parsed.updatedAt
					: new Date().toISOString(),
		};
	} catch {
		return emptySnapshot();
	}
}

function writeSnapshot(
	path: string,
	snapshot: CommandLatencyBaselineSnapshot,
): void {
	mkdirSync(dirname(path), { recursive: true });
	const temporaryPath = `${path}.${randomUUID()}.tmp`;
	try {
		writeFileSync(temporaryPath, `${JSON.stringify(snapshot, null, 2)}\n`, {
			encoding: "utf8",
			mode: 0o600,
		});
		try {
			renameSync(temporaryPath, path);
		} catch (error) {
			if (
				error instanceof Error &&
				"code" in error &&
				["EEXIST", "EPERM"].includes(
					String((error as NodeJS.ErrnoException).code),
				)
			) {
				rmSync(path, { force: true });
				renameSync(temporaryPath, path);
			} else {
				throw error;
			}
		}
	} finally {
		rmSync(temporaryPath, { force: true });
	}
}

/**
 * Persist one privacy-safe Windows timing sample. Command text, executable,
 * arguments, cwd, environment, output, and user/session identity are excluded.
 */
export function recordWindowsCommandLatencyObservation(
	observation: CommandLatencyObservation,
	options?: { path?: string; platform?: NodeJS.Platform; now?: Date },
): CommandLatencyBaselineSnapshot | undefined {
	if ((options?.platform ?? process.platform) !== "win32") return undefined;
	if (
		!finiteNonnegative(observation.durationMs) ||
		!finiteNonnegative(observation.outputChunkCount) ||
		!finiteNonnegative(observation.outputChars) ||
		(observation.timeToFirstOutputMs !== undefined &&
			!finiteNonnegative(observation.timeToFirstOutputMs))
	) {
		return undefined;
	}
	const path = options?.path ?? baselinePath();
	const now = options?.now ?? new Date();
	const snapshot = readCommandLatencyBaseline(path);
	const samples = snapshot[observation.executionMode];
	samples.push({
		durationMs: observation.durationMs,
		timeToFirstOutputMs: observation.timeToFirstOutputMs,
		outputChunkCount: observation.outputChunkCount,
		outputChars: observation.outputChars,
		success: observation.success,
		recordedAt: now.toISOString(),
	});
	if (samples.length > MAX_SAMPLES_PER_MODE) {
		samples.splice(0, samples.length - MAX_SAMPLES_PER_MODE);
	}
	snapshot.updatedAt = now.toISOString();
	writeSnapshot(path, snapshot);
	return snapshot;
}

function median(values: number[]): number | undefined {
	if (values.length === 0) return undefined;
	const sorted = [...values].sort((a, b) => a - b);
	const middle = Math.floor(sorted.length / 2);
	return sorted.length % 2 === 0
		? ((sorted[middle - 1] ?? 0) + (sorted[middle] ?? 0)) / 2
		: sorted[middle];
}

export function evaluatePowerShellWorkerEligibility(
	snapshot: CommandLatencyBaselineSnapshot,
): CommandLatencyBaselineDecision {
	const directFirstOutput = snapshot.direct.flatMap((sample) =>
		sample.success && sample.timeToFirstOutputMs !== undefined
			? [sample.timeToFirstOutputMs]
			: [],
	);
	const shellWithOutput = snapshot.shell.filter(
		(sample) => sample.success && sample.timeToFirstOutputMs !== undefined,
	);
	const shellFirstOutput = shellWithOutput.map(
		(sample) => sample.timeToFirstOutputMs as number,
	);
	const directMedianFirstOutputMs = median(directFirstOutput);
	const shellMedianFirstOutputMs = median(shellFirstOutput);
	const shellMedianDurationMs = median(
		shellWithOutput.map((sample) => sample.durationMs),
	);
	const base = {
		directSamples: directFirstOutput.length,
		shellSamples: shellFirstOutput.length,
		directMedianFirstOutputMs,
		shellMedianFirstOutputMs,
		shellMedianDurationMs,
	};
	if (
		directFirstOutput.length < MIN_DIRECT_BASELINE_SAMPLES ||
		shellFirstOutput.length < MIN_SHELL_BASELINE_SAMPLES
	) {
		return {
			...base,
			status: "collecting",
			reason: `Need at least ${MIN_DIRECT_BASELINE_SAMPLES} successful direct and ${MIN_SHELL_BASELINE_SAMPLES} successful shell samples with output.`,
		};
	}
	const shellStartupRatio =
		shellMedianFirstOutputMs !== undefined && shellMedianDurationMs
			? shellMedianFirstOutputMs / shellMedianDurationMs
			: undefined;
	const startupAdvantageMs =
		shellMedianFirstOutputMs !== undefined &&
		directMedianFirstOutputMs !== undefined
			? shellMedianFirstOutputMs - directMedianFirstOutputMs
			: 0;
	const eligible =
		(shellStartupRatio ?? 0) >= MIN_SHELL_STARTUP_RATIO &&
		startupAdvantageMs >= MIN_STARTUP_ADVANTAGE_MS;
	return {
		...base,
		shellStartupRatio,
		status: eligible ? "eligible" : "not_recommended",
		reason: eligible
			? "Shell startup dominates measured latency; a feature-flagged PowerShell worker may be evaluated."
			: "Measured shell startup does not dominate enough to justify a persistent PowerShell worker.",
	};
}

export function getPowerShellWorkerBaselineDecision(
	path = baselinePath(),
): CommandLatencyBaselineDecision {
	return evaluatePowerShellWorkerEligibility(readCommandLatencyBaseline(path));
}
