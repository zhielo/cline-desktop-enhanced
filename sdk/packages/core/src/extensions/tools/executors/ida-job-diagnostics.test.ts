import { writeFileSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi, afterEach } from "vitest";
const run = vi.hoisted(() => vi.fn());
vi.mock("./supervised-process", () => ({ runSupervised: run }));
import {
	DEFAULT_IDA_PHASE_TIMEOUT_MS,
	DEFAULT_IDA_TIMEOUT_MS,
	IDA_STOP_GRACE_MS,
	idaProgressPrelude,
	listObservedIdaJobs,
	runObservedIda,
	describeObservedIdaJob,
	formatIdaProgress,
} from "./ida-job-diagnostics";
it("reserves a complete analysis hour plus separate startup/save/export headroom", () => {
	expect(DEFAULT_IDA_TIMEOUT_MS).toBe(4_500_000);
	expect(DEFAULT_IDA_PHASE_TIMEOUT_MS).toBe(3_600_000);
});
afterEach(() => {
	vi.unstubAllEnvs();
	vi.useRealTimers();
	run.mockReset();
});
it("records exact PID, bounded diagnostics and uncertain termination without guessing progress", async () => {
	const root = await mkdtemp(join(tmpdir(), "ida-job-"));
	vi.stubEnv("CLINE_DATA_DIR", root);
	vi.stubEnv("OPENAI_API_KEY", "owned-private-key-value");
	run.mockImplementation(async (_command, _args, _timeout, _signal, spawn) => {
		spawn(123);
		return {
			exitCode: null,
			stderr: "bounded owned-private-key-value",
			stdout: "",
			outputDrainTimedOut: true,
			timedOut: true,
			cancelled: false,
		};
	});
	try {
		const result = await runObservedIda(
			"/owned/idat",
			["-Sprivate-script"],
			root,
			100,
		);
		expect(result.idaJob).toMatchObject({
			pid: 123,
			status: "termination-unconfirmed",
		});
		const receipt = await readFile(result.idaJob.receiptPath, "utf8");
		expect(receipt).toContain('"pid":123');
		expect(receipt).not.toContain("private-script");
		expect(receipt).not.toContain("owned-private-key-value");
		expect(result.stderr).toContain("[REDACTED]");
		expect(
			listObservedIdaJobs().find((job) => job.id === result.idaJob.id)
				?.lastPhase,
		).toBe("No script phase observed");
		expect(idaProgressPrelude(root)).toContain("datetime.timezone.utc");
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
it("keeps phases bound to a unique job even when a database directory is reused", async () => {
	const root = await mkdtemp(join(tmpdir(), "ida-reuse-"));
	vi.stubEnv("CLINE_DATA_DIR", root);
	run.mockImplementation(
		async (_command, _args, _timeout, _signal, spawn, env) => {
			spawn(456);
			await writeFile(
				env.CLINE_IDA_PROGRESS_PATH,
				'{"phase":"analysis-complete"}\n',
			);
			return {
				exitCode: 0,
				stderr: "",
				stdout: "",
				timedOut: false,
				cancelled: false,
			};
		},
	);
	try {
		const first = await runObservedIda("/owned/idat", [], root, 100);
		const second = await runObservedIda("/owned/idat", [], root, 100);
		expect(first.idaJob.scriptProgressPath).not.toBe(
			second.idaJob.scriptProgressPath,
		);
		await writeFile(
			second.idaJob.scriptProgressPath,
			'{"phase":"script-failed"}\n',
		);
		expect(
			listObservedIdaJobs().find((job) => job.id === first.idaJob.id)
				?.lastPhase,
		).toBe("analysis-complete");
		expect(
			listObservedIdaJobs().find((job) => job.id === second.idaJob.id)
				?.lastPhase,
		).toBe("script-failed");
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
it("phase recording cannot replace IDA's original error or suppress qexit", () => {
	expect(idaProgressPrelude("/owned")).toContain("except OSError:");
});

it("streams exact phases and enforces unchanged-phase budget without classifying it as user cancellation", async () => {
	const root = await mkdtemp(join(tmpdir(), "ida-deadline-"));
	vi.stubEnv("CLINE_DATA_DIR", root);
	vi.useFakeTimers();
	const updates: ReturnType<typeof describeObservedIdaJob>[] = [];
	run.mockImplementation(
		async (_command, _args, _timeout, signal, spawn, env) => {
			spawn(789);
			writeFileSync(
				env.CLINE_IDA_PROGRESS_PATH,
				JSON.stringify({
					phase: "auto-analysis-waiting",
					timestamp: new Date().toISOString(),
				}) + "\n",
			);
			await new Promise((resolve) =>
				signal.addEventListener("abort", resolve, { once: true }),
			);
			return {
				exitCode: null,
				stdout: "",
				stderr: "",
				cancelled: true,
				timedOut: false,
				outputDrainTimedOut: true,
			};
		},
	);
	try {
		const pending = runObservedIda("/owned/idat", [], root, 9000, undefined, {
			phaseTimeoutMs: 1000,
			onProgress: (job) => updates.push(job),
		});
		await vi.advanceTimersByTimeAsync(1000); // Observe the actual phase; start its budget.
		await vi.advanceTimersByTimeAsync(1000);
		expect(run.mock.calls[0][3].aborted).toBe(false);
		expect(
			await readFile(run.mock.calls[0][5].CLINE_IDA_STOP_PATH, "utf8"),
		).toContain('"stop":true');
		await vi.advanceTimersByTimeAsync(IDA_STOP_GRACE_MS);
		const result = await pending;
		expect(result).toMatchObject({
			timedOut: true,
			cancelled: false,
			outputDrainTimedOut: true,
		});
		expect(result.idaJob).toMatchObject({
			status: "termination-unconfirmed",
			timeoutPhase: "auto-analysis-waiting",
			phaseTimeoutMs: 1000,
		});
		expect(
			updates.some((job) => job.lastPhase === "auto-analysis-waiting"),
		).toBe(true);
		expect(formatIdaProgress(updates.at(-1)!)).toContain("deadline remaining");
		const frozen = describeObservedIdaJob(result.idaJob, Date.now() + 100000);
		expect(frozen.elapsedMs).toBe(2000 + IDA_STOP_GRACE_MS);
		expect(vi.getTimerCount()).toBe(0);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
it("does not let a failed progress observer change process execution", async () => {
	const root = await mkdtemp(join(tmpdir(), "ida-observer-"));
	vi.stubEnv("CLINE_DATA_DIR", root);
	run.mockImplementation(async (_command, _args, _timeout, _signal, spawn) => {
		spawn(321);
		return {
			exitCode: 0,
			stdout: "",
			stderr: "",
			timedOut: false,
			cancelled: false,
		};
	});
	try {
		const result = await runObservedIda(
			"/owned/idat",
			[],
			root,
			1000,
			undefined,
			{
				onProgress: () => {
					throw new Error("observer only");
				},
			},
		);
		expect(result.exitCode).toBe(0);
		expect(result.idaJob.status).toBe("process-exited");
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
it("does not enforce a script-phase deadline for an invocation without supported phases, retaining its overall deadline", async () => {
	const root = await mkdtemp(join(tmpdir(), "ida-no-phases-"));
	vi.stubEnv("CLINE_DATA_DIR", root);
	vi.useFakeTimers();
	run.mockImplementation(async (_cmd, _args, timeout, signal, spawn) => {
		spawn(123);
		expect(timeout).toBe(10000);
		await new Promise((resolve) => setTimeout(resolve, 4000));
		expect(signal.aborted).toBe(false);
		return {
			exitCode: 0,
			stdout: "",
			stderr: "",
			timedOut: false,
			cancelled: false,
		};
	});
	try {
		const pending = runObservedIda("owned-idat", [], root, 10000, undefined, {
			phaseTimeoutMs: 1000,
			scriptPhasesExpected: false,
		});
		await vi.advanceTimersByTimeAsync(4000);
		const result = await pending;
		expect(result.timedOut).toBe(false);
		expect(result.idaJob.phaseDeadlineAt).toBeUndefined();
		expect(describeObservedIdaJob(result.idaJob).lastPhase).toContain(
			"not supported",
		);
	} finally {
		vi.useRealTimers();
		await rm(root, { recursive: true, force: true });
	}
});

it("starts the analysis hour at observed phase entry, uses monotonic time, and freezes early completion", async () => {
	const root = await mkdtemp(join(tmpdir(), "ida-hour-"));
	vi.stubEnv("CLINE_DATA_DIR", root);
	vi.useFakeTimers();
	let progressPath = "";
	let complete!: (value: unknown) => void;
	run.mockImplementation(
		async (_command, _args, timeout, _signal, spawn, env) => {
			expect(timeout).toBe(4_500_000);
			spawn(567);
			progressPath = env.CLINE_IDA_PROGRESS_PATH;
			return new Promise((resolve) => {
				complete = resolve;
			});
		},
	);
	try {
		const pending = runObservedIda(
			"owned-idat",
			[],
			root,
			DEFAULT_IDA_TIMEOUT_MS,
		);
		await vi.advanceTimersByTimeAsync(120_000);
		writeFileSync(
			progressPath,
			JSON.stringify({
				phase: "auto-analysis-waiting",
				timestamp: new Date().toISOString(),
			}) + "\n",
		);
		await vi.advanceTimersByTimeAsync(1000);
		let snapshot = listObservedIdaJobs().find((j) => j.pid === 567)!;
		expect(snapshot.autoAnalysisRemainingMs).toBe(3_600_000);
		expect(snapshot.remainingMs).toBe(4_379_000);
		expect(snapshot.autoAnalysisState).toBe("running");
		// NTP/user wall-clock changes must not consume the phase budget.
		vi.setSystemTime(Date.now() + 24 * 60 * 60 * 1000);
		snapshot = listObservedIdaJobs().find((j) => j.pid === 567)!;
		expect(snapshot.autoAnalysisRemainingMs).toBe(3_600_000);
		await vi.advanceTimersByTimeAsync(10_000);
		snapshot = listObservedIdaJobs().find((j) => j.pid === 567)!;
		expect(snapshot.autoAnalysisRemainingMs).toBe(3_590_000);
		expect(snapshot.clockSource).toBe("live-host-monotonic");
		writeFileSync(progressPath, '{"phase":"analysis-complete"}\n');
		await vi.advanceTimersByTimeAsync(1000);
		complete({
			exitCode: 0,
			stdout: "",
			stderr: "",
			timedOut: false,
			cancelled: false,
		});
		const result = await pending;
		const frozen = describeObservedIdaJob(result.idaJob, Date.now() + 999_999);
		expect(frozen.autoAnalysisState).toBe("finished");
		expect(frozen.autoAnalysisRemainingMs).toBe(3_589_000);
		expect(frozen.elapsedMs).toBe(132_000);
		expect(frozen.clockSource).toBe("recorded-host-snapshot");
		expect(vi.getTimerCount()).toBe(0);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});

it("does not turn retained running history into a live countdown", () => {
	const snapshot = describeObservedIdaJob(
		{
			id: "retained-owned",
			pid: 456,
			status: "running",
			startedAt: "2026-01-01T00:00:00.000Z",
			lastHostUpdateAt: "2026-01-01T00:02:00.000Z",
			executable: "owned",
			receiptPath: "missing",
			scriptProgressPath: "missing",
			timeoutMs: 4_500_000,
			phaseTimeoutMs: 3_600_000,
			autoAnalysisElapsedMs: 10_000,
		},
		Date.parse("2026-01-02T00:00:00.000Z"),
	);
	expect(snapshot.elapsedMs).toBe(120_000);
	expect(snapshot.remainingMs).toBe(4_380_000);
	expect(snapshot.clockSource).toBe("recorded-host-snapshot");
});

it("rejects unbounded overall and phase deadlines before launching", async () => {
	await expect(
		runObservedIda("owned", [], "unused", 4_500_001),
	).rejects.toThrow("Invalid IDA");
	await expect(
		runObservedIda("owned", [], "unused", 1000, undefined, {
			phaseTimeoutMs: 3_600_001,
		}),
	).rejects.toThrow("Invalid IDA");
	expect(run).not.toHaveBeenCalled();
});

it("forwards explicit cancellation immediately and clears all timers", async () => {
	const root = await mkdtemp(join(tmpdir(), "ida-cancel-"));
	vi.stubEnv("CLINE_DATA_DIR", root);
	vi.useFakeTimers();
	const controller = new AbortController();
	run.mockImplementation(async (_cmd, _args, _timeout, signal, spawn) => {
		spawn(678);
		await new Promise((resolve) =>
			signal.addEventListener("abort", resolve, { once: true }),
		);
		return {
			exitCode: null,
			stdout: "",
			stderr: "",
			timedOut: false,
			cancelled: true,
		};
	});
	try {
		const pending = runObservedIda(
			"owned",
			[],
			root,
			DEFAULT_IDA_TIMEOUT_MS,
			controller.signal,
		);
		controller.abort();
		const result = await pending;
		expect(result.cancelled).toBe(true);
		expect(result.timedOut).toBe(false);
		expect(result.idaJob.status).toBe("cancelled");
		expect(vi.getTimerCount()).toBe(0);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
