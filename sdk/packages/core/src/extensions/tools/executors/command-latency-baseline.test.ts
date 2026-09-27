import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	evaluatePowerShellWorkerEligibility,
	MIN_DIRECT_BASELINE_SAMPLES,
	MIN_SHELL_BASELINE_SAMPLES,
	readCommandLatencyBaseline,
	recordWindowsCommandLatencyObservation,
} from "./command-latency-baseline";

function baselinePath(): string {
	return join(
		mkdtempSync(join(tmpdir(), "cline-command-baseline-")),
		"baseline.json",
	);
}

function record(
	path: string,
	executionMode: "direct" | "shell",
	durationMs: number,
	timeToFirstOutputMs: number,
): void {
	recordWindowsCommandLatencyObservation(
		{
			executionMode,
			durationMs,
			timeToFirstOutputMs,
			outputChunkCount: 1,
			outputChars: 2,
			success: true,
		},
		{ path, platform: "win32", now: new Date("2026-09-27T00:00:00.000Z") },
	);
}

describe("Windows command latency baseline", () => {
	it("collects only numeric timing metadata and requires enough evidence", () => {
		const path = baselinePath();
		record(path, "direct", 30, 10);
		record(path, "shell", 400, 300);
		const snapshot = readCommandLatencyBaseline(path);
		expect(evaluatePowerShellWorkerEligibility(snapshot)).toMatchObject({
			status: "collecting",
			directSamples: 1,
			shellSamples: 1,
		});
		const stored = readFileSync(path, "utf8");
		expect(stored).not.toContain("command");
		expect(stored).not.toContain("cwd");
		expect(stored).not.toContain('output":');
	});

	it("marks a worker eligible only when shell startup dominates", () => {
		const path = baselinePath();
		for (let index = 0; index < MIN_DIRECT_BASELINE_SAMPLES; index += 1) {
			record(path, "direct", 40, 20);
		}
		for (let index = 0; index < MIN_SHELL_BASELINE_SAMPLES; index += 1) {
			record(path, "shell", 500, 350);
		}
		expect(
			evaluatePowerShellWorkerEligibility(readCommandLatencyBaseline(path)),
		).toMatchObject({
			status: "eligible",
			directMedianFirstOutputMs: 20,
			shellMedianFirstOutputMs: 350,
			shellMedianDurationMs: 500,
			shellStartupRatio: 0.7,
		});
	});

	it("rejects prewarming when execution time, not startup, dominates", () => {
		const path = baselinePath();
		for (let index = 0; index < MIN_DIRECT_BASELINE_SAMPLES; index += 1) {
			record(path, "direct", 40, 20);
		}
		for (let index = 0; index < MIN_SHELL_BASELINE_SAMPLES; index += 1) {
			record(path, "shell", 1000, 120);
		}
		expect(
			evaluatePowerShellWorkerEligibility(readCommandLatencyBaseline(path)),
		).toMatchObject({ status: "not_recommended", shellStartupRatio: 0.12 });
	});

	it("does not persist observations outside Windows", () => {
		const path = baselinePath();
		expect(
			recordWindowsCommandLatencyObservation(
				{
					executionMode: "shell",
					durationMs: 1,
					outputChunkCount: 0,
					outputChars: 0,
					success: true,
				},
				{ path, platform: "linux" },
			),
		).toBeUndefined();
		expect(readCommandLatencyBaseline(path).shell).toEqual([]);
	});
});
