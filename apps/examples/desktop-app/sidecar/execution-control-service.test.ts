import { randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProcessSessionManager } from "@cline/core";
import { afterEach, expect, it } from "vitest";
import { AnalysisTaskOrchestrator } from "./analysis-task-orchestrator";
import { ExecutionControlService } from "./execution-control-service";

const fixtures: {
	root: string;
	service: ExecutionControlService;
	processes: ProcessSessionManager;
}[] = [];
afterEach(async () => {
	for (const f of fixtures) {
		f.service.close();
		await f.processes.dispose();
	}
	for (const root of new Set(fixtures.map((f) => f.root)))
		await rm(root, { recursive: true, force: true });
	fixtures.length = 0;
});
async function setup() {
	const root = await mkdtemp(join(tmpdir(), "execution-workspace-")),
		tasks = new AnalysisTaskOrchestrator(),
		processes = new ProcessSessionManager({
			recoveryFilePath: join(root, "processes.json"),
		}),
		options = {
			dbPath: join(root, "receipts.sqlite"),
			logRoot: join(root, "logs"),
			tasks,
			processes,
			static: async (
				_request: Record<string, unknown>,
				_signal: AbortSignal,
			) => ({ succeeded: true }),
			debugger: async () => ({ succeeded: true }),
		},
		service = new ExecutionControlService(options);
	fixtures.push({ root, service, processes });
	return { root, tasks, processes, options, service };
}
// These real-shell correctness fixtures include executable rehashing and the
// Windows identity probe (itself bounded at 5s). They are not a 5s performance SLA.
// Deadline behavior is tested separately below with a deliberately waiting adapter.
function input(stages?: unknown[]) {
	return {
		operation: "execution_pipeline",
		operation_id: randomUUID(),
		title: "Fixture",
		trusted_host_work: true,
		parallel: 2,
		archive_logs: true,
		stages: stages ?? [
			{
				id: "first",
				backend: "shell",
				depends_on: [],
				timeout_ms: 30000,
				request: {
					executable: process.execPath,
					args: ["-e", "process.stdout.write('owned output');"],
					replay_safety: "inspection-declared",
				},
			},
			{
				id: "second",
				backend: "shell",
				depends_on: ["first"],
				timeout_ms: 30000,
				request: {
					executable: process.execPath,
					args: ["-e", "process.exit(0)"],
				},
			},
		],
	};
}
async function start(f: Awaited<ReturnType<typeof setup>>, value: unknown) {
	const p = await f.service.prepare(f.root, value),
		a = f.tasks.approve(p.id, p.requirements, p.requestHash),
		r = await f.service.start(f.root, p.id, a.executionToken);
	return { p, r };
}
async function terminal(f: Awaited<ReturnType<typeof setup>>, id: string) {
	for (let i = 0; i < 1200; i++) {
		const c = f.service.get(f.root, id);
		if (!["accepted", "starting", "running"].includes(c.status)) return c;
		await new Promise((r) => setTimeout(r, 50));
	}
	throw new Error("Fixture did not terminate");
}
it("binds approval and records staged shell results without replay on duplicate start", async () => {
	const f = await setup(),
		{ p, r } = await start(f, input()),
		c = await terminal(f, r.id);
	expect(c.status, JSON.stringify(c.jobs)).toBe("completed");
	expect(c.jobs.map((j) => j.status)).toEqual(["completed", "completed"]);
	expect(c.jobs[0].stdoutHash).toMatch(/^[a-f0-9]{64}$/);
	expect(c.jobs[0].durationMs).toBeGreaterThanOrEqual(0);
	expect(c.jobs[0].outputComplete).toBe(true);
	expect(await f.service.start(f.root, p.id, "already-used")).toMatchObject({
		id: r.id,
		existing: true,
	});
	expect(f.service.list(f.root)).toHaveLength(1);
}, 75000);
it("rejects cycles, unknown host binaries and unvalidated interactive job wrappers", async () => {
	const f = await setup();
	await expect(
		f.service.prepare(
			f.root,
			input([
				{ id: "a", backend: "shell", depends_on: ["b"], request: {} },
				{ id: "b", backend: "shell", depends_on: ["a"], request: {} },
			]),
		),
	).rejects.toThrow("cycle");
	await expect(
		f.service.prepare(
			f.root,
			input([
				{
					id: "a",
					backend: "shell",
					request: {
						executable: process.execPath,
						args: [],
						native_job: true,
						interactive: true,
					},
				},
			]),
		),
	).rejects.toThrow("not validated");
	await expect(
		f.service.prepare(
			f.root,
			input([
				{
					id: "a",
					backend: "shell",
					request: {
						executable: process.execPath,
						args: ["--token", "secret"],
					},
				},
			]),
		),
	).rejects.toThrow("Credential");
});
it("does not run dependents after failure and does not retain oversized backend results", async () => {
	const f = await setup();
	f.options.static = async () => ({
		succeeded: false,
		payload: "x".repeat(70000),
	});
	await writeFile(join(f.root, "sample.dex"), "dex\n");
	const { r } = await start(
		f,
		input([
			{
				id: "a",
				backend: "static",
				request: { operation: "inspect", engine: "auto", target: "sample.dex" },
			},
			{
				id: "b",
				backend: "shell",
				depends_on: ["a"],
				request: { executable: process.execPath, args: [] },
			},
		]),
	);
	const c = await terminal(f, r.id);
	expect(c.status).toBe("failed");
	expect(c.jobs[0].resultTruncated).toBe(true);
	expect(c.jobs[1].status).toBe("cancelled");
	expect(c.jobs[1].processId).toBeUndefined();
});
it("conservatively reconciles receipts after owner loss without re-execution", async () => {
	const f = await setup(),
		{ r } = await start(
			f,
			input([
				{
					id: "a",
					backend: "shell",
					timeout_ms: 5000,
					request: {
						executable: process.execPath,
						args: ["-e", "setTimeout(()=>{},2000)"],
					},
				},
			]),
		);
	const other = new ExecutionControlService(f.options);
	fixtures.push({ root: f.root, service: other, processes: f.processes });
	expect(other.get(f.root, r.id).controlUnavailable).toBe(true);
	const reconciliation = await other.reconcile(f.root, r.id);
	expect(reconciliation.status).toBe("uncertain");
	expect(reconciliation.notice).toContain("read-only");
	await f.service.cancel(f.root, r.id);
	const c = await terminal(f, r.id);
	expect(["cancelled", "uncertain"]).toContain(c.status);
});
it("revalidates target bytes after approval and never runs changed artifacts", async () => {
	const f = await setup();
	await writeFile(join(f.root, "a.dex"), "dex\nold");
	const p = await f.service.prepare(
			f.root,
			input([
				{
					id: "a",
					backend: "static",
					request: { operation: "inspect", engine: "auto", target: "a.dex" },
				},
			]),
		),
		a = f.tasks.approve(p.id, p.requirements, p.requestHash);
	await writeFile(join(f.root, "a.dex"), "dex\nnew");
	const r = await f.service.start(f.root, p.id, a.executionToken),
		c = await terminal(f, r.id);
	expect(c.status).toBe("failed");
	expect(c.jobs[0].error).toContain("changed after approval");
});
it.each([
	"blocked",
	"failed",
	"partial",
	"uncertain",
	"cancelled",
])("top-level adapter status %s cannot unlock dependent stages", async (status) => {
	const f = await setup();
	let calls = 0;
	f.options.static = async () => {
		calls++;
		return { status } as unknown as { succeeded: boolean };
	};
	await writeFile(join(f.root, "owned.bin"), "fixture");
	const { r } = await start(
		f,
		input([
			{
				id: "a",
				backend: "static",
				request: { operation: "inspect", target: "owned.bin" },
			},
			{
				id: "b",
				backend: "static",
				depends_on: ["a"],
				request: { operation: "inspect", target: "owned.bin" },
			},
		]),
	);
	const c = await terminal(f, r.id);
	expect(c.status).toBe("failed");
	expect(c.jobs[1].startedAt).toBeUndefined();
	expect(calls).toBe(1);
});
it("preserves returned adapter evidence when cancellation races its completion", async () => {
	const f = await setup();
	f.options.static = async () => {
		for (const p of f.tasks.list(f.root))
			if (p.kind === "execution") await f.tasks.cancel(p.id);
		return { outputFile: "candidate", succeeded: true };
	};
	await writeFile(join(f.root, "owned.bin"), "fixture");
	const { r } = await start(
		f,
		input([
			{
				id: "a",
				backend: "static",
				request: { operation: "inspect", target: "owned.bin" },
			},
		]),
	);
	const c = await terminal(f, r.id);
	expect(c.jobs[0].result).toMatchObject({ outputFile: "candidate" });
	expect(c.jobs[0].status).toBe("cancelled");
	expect(c.jobs[0].resultHash).toMatch(/^[a-f0-9]{64}$/);
});

it("does not let independent-read continuation broaden trusted pipeline effects", async () => {
	const f = await setup();
	await writeFile(join(f.root, "owned.bin"), "owned");
	for (const stage of [
		{
			id: "shell",
			backend: "shell",
			request: {
				executable: process.execPath,
				args: ["-e", "process.exit(0)"],
			},
		},
		{
			id: "runtime",
			backend: "debugger",
			request: { operation: "process_identity", pid: process.pid },
		},
		{
			id: "worker",
			backend: "static",
			request: {
				operation: "advanced_analysis",
				advanced_action: "unicorn_emulate",
				target: "owned.bin",
			},
		},
		{
			id: "write",
			backend: "static",
			request: {
				operation: "inspect",
				target: "owned.bin",
				report_output_file: "out.json",
			},
		},
	])
		await expect(
			f.service.preview(f.root, {
				...input([stage]),
				owner_session_id: "owned",
				client_request_hash: "a".repeat(64),
				continue_independent_reads: true,
			}),
		).rejects.toThrow("Independent read continuation");
});

// A generous real-process fixture budget must not disable the actual deadline.
it("enforces an approved stage deadline and never launches its dependent", async () => {
	const f = await setup();
	await writeFile(join(f.root, "deadline.bin"), "owned");
	let calls = 0;
	f.options.static = async (_request, signal) => {
		calls++;
		return new Promise<{ succeeded: boolean }>((_resolve, reject) => {
			signal.throwIfAborted();
			signal.addEventListener("abort", () => reject(signal.reason), {
				once: true,
			});
		});
	};
	const { r } = await start(
		f,
		input([
			{
				id: "wait",
				backend: "static",
				timeout_ms: 1000,
				request: { operation: "inspect", target: "deadline.bin" },
			},
			{
				id: "dependent",
				backend: "static",
				depends_on: ["wait"],
				request: { operation: "inspect", target: "deadline.bin" },
			},
		]),
	);
	const c = await terminal(f, r.id);
	expect(c.status).toBe("cancelled");
	expect(c.jobs[0].status).toBe("cancelled");
	expect(c.jobs[0].error).toMatch(/timeout|aborted/i);
	expect(c.jobs[1].status).toBe("cancelled");
	expect(c.jobs[1].startedAt).toBeUndefined();
	expect(calls).toBe(1);
});
