import { randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, expect, it } from "vitest";
import {
	createReverseEngineeringExecutor,
	ProcessSessionManager,
	ReverseEngineeringInputSchema,
} from "@cline/core";
import { ExecutionControlService } from "./execution-control-service";
import { AnalysisTaskOrchestrator } from "./analysis-task-orchestrator";
import { handleBatchInvestigation } from "./batch-investigation";
const fixtures: Array<{
	root: string;
	service: ExecutionControlService;
	processes: ProcessSessionManager;
}> = [];
afterEach(async () => {
	for (const f of fixtures) {
		f.service.close();
		await f.processes.dispose();
		await rm(f.root, { recursive: true, force: true });
	}
	fixtures.length = 0;
});
async function fixture(
	adapter?: (
		input: Record<string, unknown>,
		signal: AbortSignal,
	) => Promise<unknown>,
) {
	const root = await mkdtemp(join(tmpdir(), "ai-batch-"));
	await writeFile(
		join(root, "owned.bin"),
		"Owned bounded evidence fixture abcdefghi",
	);
	const tasks = new AnalysisTaskOrchestrator(),
		processes = new ProcessSessionManager({
			recoveryFilePath: join(root, "processes.json"),
		});
	const executor = createReverseEngineeringExecutor();
	const service = new ExecutionControlService({
		dbPath: join(root, "receipts.sqlite"),
		logRoot: join(root, "logs"),
		tasks,
		processes,
		static:
			adapter ??
			(async (input, signal) =>
				JSON.parse(
					await executor(ReverseEngineeringInputSchema.parse(input), {
						sessionId: "owned",
						toolCallId: "fixture",
						agentId: "owned",
						iteration: 0,
						signal,
					}),
				)),
		debugger: async () => {
			throw new Error("Never invoke debugger");
		},
	});
	fixtures.push({ root, service, processes });
	const call = (command: string, input: unknown, sessionId = "owned") =>
		handleBatchInvestigation(
			command,
			input,
			{ sessionId, workspace: root },
			service,
			tasks,
		);
	const req = {
		operation_id: randomUUID(),
		title: "Owned static DAG",
		parallel: 1,
		stages: [
			{ id: "inspect", request: { operation: "inspect", target: "owned.bin" } },
			{
				id: "strings",
				depends_on: ["inspect"],
				request: { operation: "scan_strings", target: "owned.bin" },
			},
		],
	};
	const run = async (command: string, input: unknown) => {
		const plan = (await call(command, {
			...(input as object),
			phase: "prepare",
		})) as { id: string; requirements: string[]; requestHash: string };
		const token = tasks.approve(plan.id, plan.requirements, plan.requestHash);
		return (await call(command, {
			...(input as object),
			phase: "run",
			planId: plan.id,
			executionToken: token.executionToken,
		})) as { id: string; completed: boolean };
	};
	return { root, tasks, service, call, req, run };
}
async function terminal(f: Awaited<ReturnType<typeof fixture>>, id: string) {
	for (let i = 0; i < 200; i++) {
		const c = f.service.get(f.root, id);
		if (!["accepted", "starting", "running"].includes(c.status)) return c;
		await new Promise((r) => setTimeout(r, 15));
	}
	throw new Error("batch did not terminate");
}
it("previews a canonical hash-bound DAG without creating a plan or executing", async () => {
	const f = await fixture();
	for (const cmd of ["plan_batch", "preview_batch"]) {
		const p = (await f.call(cmd, f.req)) as {
			status: string;
			request: { stages: Array<{ target_sha256: string }> };
		};
		expect(p.status).toBe("previewed-not-approved");
		expect(
			p.request.stages.every((s) => /^[a-f0-9]{64}$/.test(s.target_sha256)),
		).toBe(true);
	}
	expect(f.tasks.list(f.root)).toHaveLength(0);
	expect(f.service.list(f.root)).toHaveLength(0);
});
it("executes real built-in inspect and strings through durable DAG; owns checkpoint", async () => {
	const f = await fixture(),
		r = await f.run("run_batch", f.req);
	expect(r.completed).toBe(false);
	const c = await terminal(f, r.id);
	expect(c.status).toBe("completed");
	expect(c.jobs.map((j) => j.status)).toEqual(["completed", "completed"]);
	expect(JSON.stringify(c.jobs[1].result)).toContain("Owned bounded evidence");
	const read = (await f.call("checkpoint_investigation", {
		receiptId: r.id,
	})) as { receipt: { revision: number; hash: string } };
	expect(read.receipt.hash).toMatch(/^[a-f0-9]{64}$/);
	expect(read.receipt.revision).toBe(c.revision);
	await expect(
		f.call("checkpoint_investigation", { receiptId: r.id }, "foreign"),
	).rejects.toThrow("owning session");
	await expect(
		f.call("cancel_batch", { receiptId: r.id }, "foreign"),
	).rejects.toThrow("owning session");
});
it.each([
	"executionToken",
	"owner_session_id",
	"sessionId",
	"trusted_host_work",
	"mode",
])("rejects model authority field %s", async (key) => {
	const f = await fixture();
	await expect(
		f.call("plan_batch", { ...f.req, [key]: true }),
	).rejects.toThrow();
});
it.each([
	"shell",
	"debugger",
	"build_android_candidate",
	"advanced_analysis",
])("rejects non-fixed operation/backend %s", async (operation) => {
	const f = await fixture();
	await expect(
		f.call("run_batch", {
			...f.req,
			stages: [
				{
					id: "bad",
					backend: operation,
					request: { operation, target: "owned.bin" },
				},
			],
		}),
	).rejects.toThrow();
});
it("rejects missing comparison, cycles and escaping inputs", async () => {
	const f = await fixture();
	await expect(
		f.call("plan_batch", {
			...f.req,
			stages: [
				{
					id: "a",
					depends_on: ["a"],
					request: { operation: "inspect", target: "owned.bin" },
				},
			],
		}),
	).rejects.toThrow("cycle");
	await expect(
		f.call("plan_batch", {
			...f.req,
			stages: [
				{
					id: "a",
					request: { operation: "compare_apks", target: "owned.bin" },
				},
			],
		}),
	).rejects.toThrow("compare_target");
	await expect(
		f.call("plan_batch", {
			...f.req,
			stages: [
				{ id: "a", request: { operation: "inspect", target: "../escape" } },
			],
		}),
	).rejects.toThrow();
});
it("never consumes a changed request or cross-session plan", async () => {
	const f = await fixture();
	const p = (await f.call("run_batch", f.req)) as {
		id: string;
		requirements: string[];
		requestHash: string;
	};
	const a = f.tasks.approve(p.id, p.requirements, p.requestHash);
	for (const [input, owner] of [
		[{ ...f.req, title: "changed" }, "owned"],
		[f.req, "foreign"],
	] as const)
		await expect(
			f.call(
				"run_batch",
				{
					...input,
					phase: "run",
					planId: p.id,
					executionToken: a.executionToken,
				},
				owner,
			),
		).rejects.toThrow("does not match");
	expect(f.service.list(f.root)).toHaveLength(0);
});
it("requires separate token and refuses completed-stage replay", async () => {
	const f = await fixture();
	await expect(f.call("run_batch", { ...f.req, phase: "run" })).rejects.toThrow(
		"approval",
	);
	const r = await f.run("run_batch", f.req),
		c = await terminal(f, r.id);
	await expect(
		f.call("resume_investigation", { receiptId: r.id, revision: c.revision }),
	).rejects.toThrow("never-started");
});
async function cancellable() {
	let calls = 0;
	const f = await fixture(async (_input, signal) => {
		calls++;
		if (calls === 2) {
			await new Promise<void>((resolve) =>
				signal.addEventListener("abort", () => resolve(), { once: true }),
			);
			return { status: "cancelled" };
		}
		return { status: "completed", owned: calls };
	});
	f.req.stages = [
		{ id: "a", request: { operation: "inspect", target: "owned.bin" } },
		{ id: "b", request: { operation: "inspect", target: "owned.bin" } },
		{
			id: "c",
			depends_on: ["a"],
			request: { operation: "scan_strings", target: "owned.bin" },
		},
	];
	const r = await f.run("run_batch", f.req);
	for (let i = 0; i < 100 && calls < 2; i++)
		await new Promise((r) => setTimeout(r, 10));
	expect(calls).toBe(2);
	await f.call("cancel_batch", { receiptId: r.id });
	const c = await terminal(f, r.id);
	expect(c.jobs[2].startedAt).toBeUndefined();
	return { ...f, c, r, calls: () => calls };
}
it("resumes only never-started stages; completed dependencies are reused, not replayed", async () => {
	const f = await cancellable();
	const r = await f.run("resume_investigation", {
		receiptId: f.r.id,
		revision: f.c.revision,
	});
	const c = await terminal(f, r.id);
	expect(c.status).toBe("completed");
	expect(c.jobs.map((j) => j.id)).toEqual(["c"]);
	expect(c.request.resume_from?.reused).toEqual(["a"]);
	expect(f.calls()).toBe(3);
	expect(f.service.get(f.root, f.r.id).revision).toBe(f.c.revision);
	const again = await f.run("resume_investigation", {
		receiptId: f.r.id,
		revision: f.c.revision,
	});
	expect(again.id).toBe(r.id);
	expect(f.calls()).toBe(3);
});
it("resume rejects stale revision, foreign owner and changed inputs before and after approval", async () => {
	const f = await cancellable(),
		req = { receiptId: f.r.id, revision: f.c.revision };
	await expect(
		f.call("resume_investigation", { ...req, revision: req.revision - 1 }),
	).rejects.toThrow("revision");
	await expect(f.call("resume_investigation", req, "foreign")).rejects.toThrow(
		"owning session",
	);
	const p = (await f.call("resume_investigation", req)) as {
		id: string;
		requirements: string[];
		requestHash: string;
	};
	const token = f.tasks.approve(p.id, p.requirements, p.requestHash);
	await writeFile(join(f.root, "owned.bin"), "changed");
	await expect(f.call("resume_investigation", req)).rejects.toThrow("changed");
	await expect(
		f.call("resume_investigation", {
			...req,
			phase: "run",
			planId: p.id,
			executionToken: token.executionToken,
		}),
	).rejects.toThrow("changed");
	expect(f.calls()).toBe(2);
});
it("a failed started dependency blocks continuation, never repairs by replay", async () => {
	const f = await fixture(async () => ({ status: "blocked" })),
		r = await f.run("run_batch", f.req),
		c = await terminal(f, r.id);
	expect(c.status).toBe("failed");
	await expect(
		f.call("resume_investigation", { receiptId: r.id, revision: c.revision }),
	).rejects.toThrow("Unresolved started dependency");
});

it("retains real source evidence as partial while independent reads finish and dependents never run", async () => {
	const f = await fixture();
	const source =
		'export function owned(){ return "evidence"; }\n(globalThis as any).__batchMustNotRun = true;';
	await writeFile(join(f.root, "owned.ts"), source);
	const req = {
		...f.req,
		parallel: 1,
		stages: [
			{
				id: "source",
				request: {
					operation: "explain_behavior",
					target: "owned.ts",
					workflow_query: { symbol: "owned" },
				},
			},
			{
				id: "dependent",
				depends_on: ["source"],
				request: { operation: "inspect", target: "owned.bin" },
			},
			{
				id: "independent",
				request: { operation: "scan_strings", target: "owned.bin" },
			},
		],
	};
	const r = await f.run("run_batch", req),
		c = await terminal(f, r.id);
	expect(c.status).toBe("partial");
	expect(c.jobs.map((j) => j.status)).toEqual([
		"partial",
		"cancelled",
		"completed",
	]);
	expect(c.jobs[0].result).toMatchObject({
		status: "partial",
		observedExecution: false,
		selectedFunction: { text: expect.stringContaining('return "evidence"') },
	});
	expect(c.jobs[0].resultHash).toMatch(/^[a-f0-9]{64}$/);
	expect(c.jobs[1].startedAt).toBeUndefined();
	expect((globalThis as any).__batchMustNotRun).toBeUndefined();
	const { readFile } = await import("node:fs/promises");
	expect(await readFile(join(f.root, "owned.ts"), "utf8")).toBe(source);
	await expect(
		f.call("resume_investigation", { receiptId: r.id, revision: c.revision }),
	).rejects.toThrow("Unresolved started dependency");
});
it("runs saved graph analysis with no worker, shell or target execution", async () => {
	const f = await fixture();
	await writeFile(
		join(f.root, "saved.json"),
		JSON.stringify({
			schemaVersion: 1,
			nodes: [
				{
					id: "owned",
					kind: "artifact",
					label: "owned",
					artifactSha256: "a".repeat(64),
					confidence: "reported",
					evidenceIndex: 0,
				},
			],
			edges: [],
			coverage: [],
			sourceHashes: ["a".repeat(64)],
		}),
	);
	const r = await f.run("run_batch", {
		...f.req,
		stages: [
			{
				id: "graph",
				request: {
					operation: "advanced_analysis",
					advanced_action: "graph_query",
					target: "saved.json",
					advanced_options: { graph_query: { kind: "artifact", limit: 2 } },
				},
			},
		],
	});
	const c = await terminal(f, r.id);
	expect(c.jobs[0].error).toBeUndefined();
	expect(["completed", "partial"]).toContain(c.status);
	expect(c.jobs[0].resultHash).toMatch(/^[a-f0-9]{64}$/);
	expect(JSON.stringify(c.jobs[0].result)).toContain(
		"content-identity-not-authentication",
	);
});
it("hash-binds both source comparison inputs, rejecting a changed comparison after approval", async () => {
	const f = await fixture();
	await writeFile(join(f.root, "a.ts"), "export const a=1;");
	await writeFile(join(f.root, "b.ts"), "export const b=2;");
	const req = {
		...f.req,
		stages: [
			{
				id: "compare",
				request: {
					operation: "compare_public_api",
					target: "a.ts",
					compare_target: "b.ts",
				},
			},
		],
	};
	const p = (await f.call("run_batch", req)) as {
		id: string;
		requirements: string[];
		requestHash: string;
	};
	const a = f.tasks.approve(p.id, p.requirements, p.requestHash);
	await writeFile(join(f.root, "b.ts"), "export const changed=3;");
	const r = (await f.call("run_batch", {
		...req,
		phase: "run",
		planId: p.id,
		executionToken: a.executionToken,
	})) as { id: string };
	const c = await terminal(f, r.id);
	expect(c.status).toBe("failed");
	expect(c.jobs[0].error).toContain("Comparison artifact changed");
});
