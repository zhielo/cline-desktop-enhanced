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
} from "./ida-job-diagnostics";
afterEach(() => vi.unstubAllEnvs());
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
