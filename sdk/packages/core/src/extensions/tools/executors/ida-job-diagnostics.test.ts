import { writeFileSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi, afterEach } from "vitest";
const run = vi.hoisted(() => vi.fn());
vi.mock("./supervised-process", () => ({ runSupervised: run }));
import {
	idaProgressPrelude,
	listObservedIdaJobs,
	runObservedIda,
	describeObservedIdaJob,
	formatIdaProgress,
} from "./ida-job-diagnostics";
afterEach(() => { vi.unstubAllEnvs(); vi.useRealTimers(); run.mockReset(); });
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
  const updates = [];
  run.mockImplementation(async (_command, _args, _timeout, signal, spawn, env) => {
    spawn(789);
    writeFileSync(env.CLINE_IDA_PROGRESS_PATH, JSON.stringify({phase:"auto-analysis-waiting",timestamp:new Date().toISOString()})+"\n");
    await new Promise(resolve => signal.addEventListener("abort", resolve, {once:true}));
    return {exitCode:null,stdout:"",stderr:"",cancelled:true,timedOut:false,outputDrainTimedOut:true};
  });
  try {
    const pending = runObservedIda("/owned/idat", [], root, 9000, undefined, {phaseTimeoutMs:1000,onProgress:job=>updates.push(job)});
    await vi.advanceTimersByTimeAsync(1000); // Observe the actual phase; start its budget.
    await vi.advanceTimersByTimeAsync(1000);
    const result = await pending;
    expect(result).toMatchObject({timedOut:true,cancelled:false,outputDrainTimedOut:true});
    expect(result.idaJob).toMatchObject({status:"termination-unconfirmed",timeoutPhase:"auto-analysis-waiting",phaseTimeoutMs:1000});
    expect(updates.some(job => job.lastPhase === "auto-analysis-waiting")).toBe(true);
    expect(formatIdaProgress(updates.at(-1)!)).toContain("deadline remaining");
    const frozen = describeObservedIdaJob(result.idaJob, Date.now()+100000);
    expect(frozen.elapsedMs).toBe(2000);
    expect(vi.getTimerCount()).toBe(0);
  } finally { await rm(root,{recursive:true,force:true}); }
});
it("does not let a failed progress observer change process execution", async () => {
  const root = await mkdtemp(join(tmpdir(), "ida-observer-"));
  vi.stubEnv("CLINE_DATA_DIR",root);
  run.mockImplementation(async (_command,_args,_timeout,_signal,spawn) => {
    spawn(321);return {exitCode:0,stdout:"",stderr:"",timedOut:false,cancelled:false};
  });
  try {
    const result = await runObservedIda("/owned/idat",[],root,1000,undefined,{onProgress:()=>{throw new Error("observer only");}});
    expect(result.exitCode).toBe(0);expect(result.idaJob.status).toBe("process-exited");
  } finally { await rm(root,{recursive:true,force:true}); }
});
