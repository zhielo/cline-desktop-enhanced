import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
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
async function terminal(
	f: Pick<Awaited<ReturnType<typeof fixture>>, "root" | "service">,
	id: string,
) {
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

it("preserves nested CFG partial status while independent reads finish", async () => {
	const f = await fixture();
	await writeFile(
		join(f.root, "cfg.json"),
		JSON.stringify({
			schemaVersion: 1,
			entry: "a",
			blocks: [{ id: "a", successors: [] }],
		}),
	);
	const r = await f.run("run_batch", {
		...f.req,
		stages: [
			{
				id: "cfg",
				request: {
					operation: "advanced_analysis",
					advanced_action: "cfg_analyze",
					target: "cfg.json",
				},
			},
			{
				id: "dependent",
				depends_on: ["cfg"],
				request: { operation: "inspect", target: "owned.bin" },
			},
			{
				id: "independent",
				request: { operation: "inspect", target: "owned.bin" },
			},
		],
	});
	const c = await terminal(f, r.id);
	expect(c.status).toBe("partial");
	expect(c.jobs.map((j) => j.status)).toEqual([
		"partial",
		"cancelled",
		"completed",
	]);
	expect(c.jobs[0].result).toMatchObject({
		result: { status: "partial", evidence: { equivalence: "not-proven" } },
	});
	expect(c.jobs[1].startedAt).toBeUndefined();
});

const ownedGraph = {
	schemaVersion: 1,
	nodes: [],
	edges: [],
	coverage: ["Owned fixture, not target compatibility"],
	sourceHashes: [],
};
async function graphFixture(adapter?: Parameters<typeof fixture>[0]) {
	const f = await fixture(adapter);
	const manifest = {
		schemaVersion: 1,
		results: [
			{
				protocol: "cline-advanced-analysis/v1",
				status: "completed",
				engine: "owned-fixture",
				engineVersion: "1",
				evidence: {},
				limitations: ["Untrusted input report"],
			},
		],
	};
	await writeFile(join(f.root, "manifest.json"), JSON.stringify(manifest));
	const req = {
		operation_id: randomUUID(),
		title: "Owned chained graph",
		parallel: 1,
		stages: [
			{
				id: "build",
				request: {
					operation: "advanced_analysis",
					advanced_action: "graph_build",
					target: "manifest.json",
				},
			},
			{
				id: "query",
				depends_on: ["build"],
				request: {
					operation: "advanced_analysis",
					advanced_action: "graph_query",
					target: { stage_id: "build", output: "evidence-graph" },
				},
			},
		],
	};
	return { ...f, req };
}
it("chains an actual graph_build output into graph_query without trusting a report path", async () => {
	const f = await graphFixture(),
		preview = (await f.call("preview_batch", f.req)) as unknown as {
			request: { stages: Array<{ request: { target: unknown } }> };
		};
	expect(preview.request.stages[1].request.target).toEqual({
		stage_id: "build",
		output: "evidence-graph",
	});
	expect(f.tasks.list(f.root)).toHaveLength(0);
	const run = await f.run("run_batch", f.req),
		c = await terminal(f, run.id);
	expect(c.status).toBe("completed");
	expect(c.jobs[1].inputReport).toMatchObject({
		producerReceiptId: c.id,
		producerStageId: "build",
		producerResultSha256: c.jobs[0].resultHash,
		output: "evidence-graph",
	});
	expect(c.jobs[1].inputReport?.documentSha256).toMatch(/^[a-f0-9]{64}$/);
	expect(JSON.stringify(c.jobs[1].result)).toContain("owned-fixture");
	expect(
		(await readdir(join(f.root, "logs"))).filter((n) =>
			n.startsWith("report-"),
		),
	).toEqual([]);
});
it.each([
	"absent-dependency",
	"wrong-producer",
	"wrong-consumer",
	"unknown-output",
	"self-reference",
	"injected-path",
])("rejects invalid report reference %s before approval", async (kind) => {
	const f = await graphFixture();
	const req: any = structuredClone(f.req);
	if (kind === "absent-dependency") req.stages[1].depends_on = [];
	if (kind === "wrong-producer")
		req.stages[0].request = { operation: "inspect", target: "owned.bin" };
	if (kind === "wrong-consumer")
		req.stages[1].request.advanced_action = "cfg_analyze";
	if (kind === "unknown-output")
		req.stages[1].request.target.output = "executable";
	if (kind === "self-reference")
		req.stages[1].request.target.stage_id = "query";
	if (kind === "injected-path")
		req.stages[1].request.target.path = "../../outside";
	await expect(f.call("preview_batch", req)).rejects.toThrow();
	expect(f.tasks.list(f.root)).toHaveLength(0);
	expect(f.service.list(f.root)).toHaveLength(0);
});
it.each([
	"partial",
	"truncated",
	"malformed",
	"missing",
])("does not consume %s producer evidence", async (kind) => {
	let queries = 0;
	const f = await graphFixture(async (req) => {
		if (req.advanced_action === "graph_query") {
			queries++;
			return { status: "completed" };
		}
		if (kind === "missing")
			return { status: "completed", path: "../../never-follow-this.json" };
		return {
			result: {
				protocol: "cline-advanced-analysis/v1",
				status: kind === "partial" ? "partial" : "completed",
				evidence: {
					graph:
						kind === "malformed"
							? { ...ownedGraph, unexpected: "invalid" }
							: ownedGraph,
				},
			},
			...(kind === "truncated" ? { huge: "x".repeat(70000) } : {}),
		};
	});
	const run = await f.run("run_batch", f.req),
		c = await terminal(f, run.id);
	expect(c.status).not.toBe("completed");
	expect(queries).toBe(0);
	expect(c.jobs[1].status).not.toBe("completed");
});
it("freshly approved continuation consumes the exact reused producer without rerunning it", async () => {
	let builds = 0,
		queries = 0;
	const f = await graphFixture(async (req) => {
		if (req.operation === "scan_strings")
			throw new Error("Owned intermediate failure");
		if (req.advanced_action === "graph_build") {
			builds++;
			return {
				result: {
					protocol: "cline-advanced-analysis/v1",
					status: "completed",
					evidence: { graph: ownedGraph },
				},
			};
		}
		queries++;
		expect(JSON.parse(await readFile(String(req.target), "utf8"))).toEqual(
			ownedGraph,
		);
		return { status: "completed" };
	});
	const req = {
		...f.req,
		stages: [
			f.req.stages[0],
			{
				id: "fail",
				depends_on: ["build"],
				request: { operation: "scan_strings", target: "owned.bin" },
			},
			f.req.stages[1],
		],
	};
	const first = await f.run("run_batch", req),
		c = await terminal(f, first.id);
	expect(c.jobs.map((j) => j.status)).toEqual([
		"completed",
		"failed",
		"cancelled",
	]);
	const resumed = await f.run("resume_investigation", {
			receiptId: c.id,
			revision: c.revision,
		}),
		done = await terminal(f, resumed.id);
	expect(done.status).toBe("completed");
	expect(builds).toBe(1);
	expect(queries).toBe(1);
	expect(done.jobs[0].inputReport?.producerReceiptId).toBe(c.id);
});
it("cancellation removes private report snapshots and preserves bound provenance", async () => {
	let snapshot = "",
		entered!: () => void;
	const started = new Promise<void>((r) => {
		entered = r;
	});
	const f = await graphFixture(async (req, signal) => {
		if (req.advanced_action === "graph_build")
			return {
				result: {
					protocol: "cline-advanced-analysis/v1",
					status: "completed",
					evidence: { graph: ownedGraph },
				},
			};
		snapshot = String(req.target);
		await readFile(snapshot);
		entered();
		await new Promise<void>((_, reject) => {
			if (signal.aborted) reject(signal.reason);
			else
				signal.addEventListener("abort", () => reject(signal.reason), {
					once: true,
				});
		});
	});
	const run = await f.run("run_batch", f.req);
	await started;
	await f.call("cancel_batch", { receiptId: run.id });
	const c = await terminal(f, run.id);
	expect(c.status).not.toBe("completed");
	expect(c.jobs[1].inputReport?.producerStageId).toBe("build");
	await expect(readFile(snapshot)).rejects.toThrow();
});
it("fresh source-flow batch evidence stays partial and cannot unlock dependent work", async () => {
	const f = await fixture();
	const source = 'const url = "https://example.invalid/owned";\nfetch(url);\n';
	await writeFile(join(f.root, "owned.ts"), source);
	const request = {
		...f.req,
		stages: [
			{
				id: "flow",
				request: {
					operation: "trace_data_flow",
					target: "owned.ts",
					source_flow: {
						kind: "js-ts",
						start: {
							path: "owned.ts",
							line: 1,
							column: 7,
							kind: "configuration",
						},
						end: {
							path: "owned.ts",
							line: 2,
							column: 1,
							kind: "resolved-endpoint",
						},
					},
				},
			},
			{
				id: "dependent",
				depends_on: ["flow"],
				request: { operation: "inspect", target: "owned.bin" },
			},
		],
	};
	const started = await f.run("run_batch", request);
	const receipt = await terminal(f, started.id);
	expect(receipt.status).toBe("partial");
	expect(receipt.jobs.map((j) => j.status)).toEqual(["partial", "cancelled"]);
	expect(receipt.jobs[0].result).toMatchObject({
		status: "partial",
		mode: "fresh-js-ts-constant-endpoint-flow",
		observedExecution: false,
		endpointReachableInSelectedGraph: true,
	});
	expect(await readFile(join(f.root, "owned.ts"), "utf8")).toBe(source);
	await expect(
		f.call("preview_batch", {
			...request,
			stages: [
				{
					...request.stages[0],
					request: { ...request.stages[0].request, operation: "inspect" },
				},
			],
		}),
	).rejects.toThrow();
});
