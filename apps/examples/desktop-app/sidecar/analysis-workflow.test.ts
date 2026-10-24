import { it, expect, vi } from "vitest";
import { mkdtemp, writeFile, rm, mkdir, symlink } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
	AnalysisWorkflowStore,
	confinedArtifact,
} from "./analysis-workflow-store";
import {
	handleAnalysisWorkflow,
	featureTrace,
	buildEvidenceBundle,
} from "./analysis-workflow";
it("immutable artifact handles reject mutations and cross-session reads", async () => {
	const root = await mkdtemp(join(tmpdir(), "workflow-owned-"));
	await mkdir(join(root, "workspace"));
	const scope = { sessionId: "owned", workspace: join(root, "workspace") },
		store = new AnalysisWorkflowStore(join(root, "store.sqlite"));
	try {
		await writeFile(join(scope.workspace, "owned.exe"), "owned");
		const h = await store.open(scope, "owned.exe");
		expect((await store.verify(scope, h.id)).sha256).toBe(h.sha256);
		expect(() =>
			store.get({ ...scope, sessionId: "other" }, h.id, "artifact"),
		).toThrow("unavailable");
		await writeFile(join(scope.workspace, "owned.exe"), "changed");
		await expect(store.verify(scope, h.id)).rejects.toThrow("changed");
		await expect(store.open(scope, "../store.sqlite")).rejects.toThrow(
			"confined",
		);
	} finally {
		store.close();
		await rm(root, { recursive: true, force: true });
	}
});
it("confines native plan paths through workspace aliases while rejecting escapes", async () => {
	const root = await mkdtemp(join(tmpdir(), "workflow-alias-"));
	const owned = join(root, "owned");
	const alias = join(root, "owned-alias");
	const outside = join(root, "outside");
	await mkdir(owned);
	await mkdir(outside);
	await writeFile(join(owned, "owned.js"), "owned");
	await writeFile(join(outside, "outside.js"), "outside");
	await symlink(
		owned,
		alias,
		process.platform === "win32" ? "junction" : "dir",
	);
	await symlink(
		outside,
		join(owned, "escape"),
		process.platform === "win32" ? "junction" : "dir",
	);
	try {
		const nativeFile = realpathSync.native(join(owned, "owned.js"));
		expect((await confinedArtifact(alias, nativeFile)).path).toBe(nativeFile);
		await expect(
			confinedArtifact(alias, join(owned, "escape", "outside.js")),
		).rejects.toThrow("confined");
		await expect(
			confinedArtifact(alias, join(outside, "outside.js")),
		).rejects.toThrow("confined");
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
it("workflow does not bypass mode, trusted connection or one-use approvals", async () => {
	const invoke = vi.fn(),
		store = {
			verify: vi.fn(async () => ({ path: "/owned" })),
		} as unknown as AnalysisWorkflowStore;
	const ports = {
		invoke,
		staticReceipt: vi.fn(),
		taskBundle: vi.fn(),
		capture: vi.fn(),
	};
	const scope = { sessionId: "s", workspace: "/owned" };
	await expect(
		handleAnalysisWorkflow(
			"open_binary",
			{},
			scope,
			{ trusted: false, idle: true, mode: "static" },
			store,
			ports,
		),
	).rejects.toThrow("trusted");
	const input = {
		artifactId: "11111111-1111-4111-8111-111111111111",
		engine: "ghidra",
		selector: { symbol: "owned" },
		phase: "run",
	};
	await expect(
		handleAnalysisWorkflow(
			"analyze_function",
			input,
			scope,
			{ trusted: true, idle: true, mode: "static" },
			store,
			ports,
		),
	).rejects.toThrow("approved");
	expect(invoke).not.toHaveBeenCalled();
});
it("feature matching remains explicitly partial, never proof of a call chain", () => {
	expect(
		featureTrace(
			"owned",
			{ result: { facts: [{ kind: "call", value: "owned" }] } },
			[],
		),
	).toMatchObject({
		status: "partial",
		staticCandidates: [{ classification: "statically-inferred" }],
	});
	expect(featureTrace("absent", {}, []).status).toBe("unresolved");
});
it("export is selected, bounded and credential-filtered, not a settings backup", () => {
	const b = buildEvidenceBundle({ sessionId: "s", workspace: "/owned" }, [
		{
			authorization: "Bearer secret",
			executionToken: "private",
			note: "api_key=hidden",
		},
	]);
	expect(JSON.stringify(b)).not.toContain("Bearer secret");
	expect(JSON.stringify(b)).not.toContain("private");
	expect(b.bundleHash).toMatch(/^[a-f0-9]{64}$/);
	expect(() =>
		buildEvidenceBundle({ sessionId: "s", workspace: "/owned" }, [
			"x".repeat(5 * 1024 * 1024),
		]),
	).toThrow("4 MiB");
});
it("metadata recording may stop after mode changes, but never start while Off or busy", async () => {
	const capture = vi.fn(async () => ({
			purpose: "original",
			metadata: { cleanupVerified: true },
		})),
		put = vi.fn((scope, kind, body) => body);
	const ports = {
		capture,
		invoke: vi.fn(),
		staticReceipt: vi.fn(),
		taskBundle: vi.fn(),
	};
	const store = { put } as unknown as AnalysisWorkflowStore;
	const scope = { sessionId: "s", workspace: "/owned" };
	const req = {
		browserSessionId: "11111111-1111-4111-8111-111111111111",
		confirmRecord: true,
		purpose: "stop",
	};
	await expect(
		handleAnalysisWorkflow(
			"capture_browser_scenario",
			{ ...req, action: "start" },
			scope,
			{ trusted: true, idle: false, mode: "off" },
			store,
			ports,
		),
	).rejects.toThrow("idle Runtime");
	await handleAnalysisWorkflow(
		"capture_browser_scenario",
		{ ...req, action: "stop" },
		scope,
		{ trusted: true, idle: false, mode: "off" },
		store,
		ports,
	);
	expect(put).toHaveBeenCalledWith(
		scope,
		"scenario",
		expect.objectContaining({ purpose: "original" }),
	);
});
it("function analysis preparation and run reuse the existing approval protocol", async () => {
	const invoke = vi.fn(async () => ({ id: "plan" }));
	const store = {
		verify: vi.fn(async () => ({ path: "/owned/target.exe" })),
	} as unknown as AnalysisWorkflowStore;
	const ports = {
		invoke,
		staticReceipt: vi.fn(),
		taskBundle: vi.fn(),
		capture: vi.fn(),
	};
	const scope = { sessionId: "s", workspace: "/owned" };
	const req = {
		artifactId: "11111111-1111-4111-8111-111111111111",
		engine: "ghidra",
		selector: { address: "0x401000" },
	};
	await handleAnalysisWorkflow(
		"analyze_function",
		req,
		scope,
		{ trusted: true, idle: true, mode: "static" },
		store,
		ports,
	);
	expect(invoke).toHaveBeenCalledWith("prepare_analysis_task", {
		kind: "static",
		request: {
			engine: "ghidra",
			operation: "decompile",
			timeout_ms: 120000,
			target: "/owned/target.exe",
			function_selector: { address: "0x401000" },
		},
	});
	await handleAnalysisWorkflow(
		"analyze_function",
		{ ...req, phase: "run", planId: req.artifactId, executionToken: "one-use" },
		scope,
		{ trusted: true, idle: true, mode: "static" },
		store,
		ports,
	);
	expect(invoke).toHaveBeenLastCalledWith(
		"run_static_analysis",
		expect.objectContaining({ executionToken: "one-use" }),
	);
});
it("the real orchestrator accepts the wrapper's exact reviewed request once only", async () => {
	const { AnalysisTaskOrchestrator } = await import(
		"./analysis-task-orchestrator"
	);
	const { ReverseEngineeringInputSchema } = await import("@cline/core");
	const root = await mkdtemp(join(tmpdir(), "workflow-plan-"));
	const scope = { sessionId: "s", workspace: root };
	const store = new AnalysisWorkflowStore(join(root, "workflow.sqlite"));
	const orchestrator = new AnalysisTaskOrchestrator();
	try {
		await writeFile(join(root, "owned.exe"), "owned-static-fixture");
		const artifact = await store.open(scope, "owned.exe");
		const ports = {
			staticReceipt: vi.fn(),
			taskBundle: vi.fn(),
			capture: vi.fn(),
			invoke: async (command: string, args: Record<string, unknown>) => {
				const request = ReverseEngineeringInputSchema.parse(
					command === "prepare_analysis_task" ? args.request : args.input,
				);
				if (command === "prepare_analysis_task")
					return orchestrator.prepare({
						workspaceRoot: root,
						kind: "static",
						request,
						timeoutMs: 120000,
					});
				await orchestrator.consume({
					workspaceRoot: root,
					kind: "static",
					planId: String(args.planId),
					executionToken: String(args.executionToken),
					request,
				});
				return orchestrator.complete(
					String(args.planId),
					{ owned: true },
					"owned-fixture-no-engine-execution",
				);
			},
		};
		const options = { trusted: true, idle: true, mode: "static" };
		const req = {
			artifactId: artifact.id,
			engine: "ghidra",
			selector: { symbol: "owned" },
		};
		const plan = (await handleAnalysisWorkflow(
			"analyze_function",
			req,
			scope,
			options,
			store,
			ports,
		)) as { id: string; requestHash: string; requirements: string[] };
		const approved = orchestrator.approve(
			plan.id,
			plan.requirements,
			plan.requestHash,
		);
		const run = {
			...req,
			phase: "run",
			planId: plan.id,
			executionToken: approved.executionToken,
		};
		await handleAnalysisWorkflow(
			"analyze_function",
			run,
			scope,
			options,
			store,
			ports,
		);
		await expect(
			handleAnalysisWorkflow(
				"analyze_function",
				run,
				scope,
				options,
				store,
				ports,
			),
		).rejects.toThrow();
	} finally {
		store.close();
		await rm(root, { recursive: true, force: true });
	}
});
it("unknown workflow database versions are refused without overwriting their version", async () => {
	const { loadSqliteDb } = await import("@cline/shared/db");
	const root = await mkdtemp(join(tmpdir(), "workflow-version-"));
	const file = join(root, "owned.sqlite");
	const db = loadSqliteDb(file);
	db.exec("PRAGMA user_version=2");
	db.close?.();
	const store = new AnalysisWorkflowStore(file);
	try {
		expect(() =>
			store.list({ sessionId: "s", workspace: root }, "artifact"),
		).toThrow("Unsupported workflow database version");
		const check = loadSqliteDb(file);
		expect(check.prepare("PRAGMA user_version").get()?.user_version).toBe(2);
		check.close?.();
	} finally {
		store.close();
		await rm(root, { recursive: true, force: true });
	}
});
it("failed receipt persistence returns stopped capture evidence without replay", async () => {
	const capture = vi.fn(async () => ({ purpose: "owned", status: "partial" }));
	const store = {
		put: vi.fn(() => {
			throw new Error("disk full");
		}),
	} as unknown as AnalysisWorkflowStore;
	const result = await handleAnalysisWorkflow(
		"capture_browser_scenario",
		{
			action: "stop",
			browserSessionId: "11111111-1111-4111-8111-111111111111",
			purpose: "owned",
			confirmRecord: true,
		},
		{ sessionId: "s", workspace: "/owned" },
		{ trusted: true, idle: true, mode: "runtime" },
		store,
		{ capture, invoke: vi.fn(), staticReceipt: vi.fn(), taskBundle: vi.fn() },
	);
	expect(result).toMatchObject({
		capture: { purpose: "owned" },
		evidenceWarning: expect.stringContaining("do not replay"),
	});
	expect(capture).toHaveBeenCalledTimes(1);
});

it("redacts derived report fields as well as original selected records", () => {
	const bundle = buildEvidenceBundle(
		{ sessionId: "owned", workspace: "/owned" },
		[
			{
				providerSnapshot: {
					result: {
						evidence: {
							selectedFunctions: [{ name: "api_key=private-derived-secret" }],
						},
					},
				},
			},
		],
	);
	expect(JSON.stringify(bundle)).not.toContain("private-derived-secret");
});
it("Hybrid browser start denies missing static basis or recording consent without capturing", async () => {
	const capture = vi.fn(),
		ports = {
			capture,
			invoke: vi.fn(),
			staticReceipt: vi.fn(),
			taskBundle: vi.fn(),
		},
		scope = { sessionId: "s", workspace: "/owned" },
		store = {} as AnalysisWorkflowStore;
	const req = {
		browserSessionId: "11111111-1111-4111-8111-111111111111",
		action: "start",
		purpose: "owned question",
		confirmRecord: true,
	};
	for (const input of [req, { ...req, confirmRecord: false }])
		await expect(
			handleAnalysisWorkflow(
				"capture_browser_scenario",
				input,
				scope,
				{ trusted: true, idle: true, mode: "hybrid" },
				store,
				ports,
			),
		).rejects.toThrow();
	expect(capture).not.toHaveBeenCalled();
});
it("Hybrid preflight is unavailable to untrusted, Off or busy UI callers", async () => {
	const ports = {
			capture: vi.fn(),
			invoke: vi.fn(),
			staticReceipt: vi.fn(),
			taskBundle: vi.fn(),
		},
		scope = { sessionId: "s", workspace: "/owned" };
	for (const options of [
		{ trusted: false, idle: true, mode: "hybrid" },
		{ trusted: true, idle: true, mode: "off" },
		{ trusted: true, idle: false, mode: "hybrid" },
	])
		await expect(
			handleAnalysisWorkflow(
				"analysis_workflow_hybrid_prepare",
				{},
				scope,
				options,
				{} as AnalysisWorkflowStore,
				ports,
			),
		).rejects.toThrow("trusted enabled");
	expect(ports.capture).not.toHaveBeenCalled();
	expect(ports.invoke).not.toHaveBeenCalled();
});
it("batch new work requires enabled trusted scope; cleanup remains possible after Off", async () => {
	const root = await mkdtemp(join(tmpdir(), "batch-mode-")),
		store = new AnalysisWorkflowStore(join(root, "store.sqlite"));
	const batch = vi.fn(async () => ({ status: "owned" }));
	const ports = {
		invoke: vi.fn(),
		staticReceipt: vi.fn(),
		taskBundle: vi.fn(),
		capture: vi.fn(),
		batch,
	};
	const scope = { sessionId: "owned", workspace: root };
	try {
		for (const command of [
			"plan_batch",
			"preview_batch",
			"run_batch",
			"resume_investigation",
		]) {
			await expect(
				handleAnalysisWorkflow(
					command,
					{},
					scope,
					{ trusted: true, idle: true, mode: "off" },
					store,
					ports,
				),
			).rejects.toThrow("Analysis enabled");
		}
		for (const command of ["checkpoint_investigation", "cancel_batch"]) {
			expect(
				await handleAnalysisWorkflow(
					command,
					{},
					scope,
					{ trusted: true, idle: false, mode: "off", actor: "model" },
					store,
					ports,
				),
			).toEqual({ status: "owned" });
			await expect(
				handleAnalysisWorkflow(
					command,
					{},
					scope,
					{ trusted: false, idle: true, mode: "static" },
					store,
					ports,
				),
			).rejects.toThrow("trusted");
		}
	} finally {
		store.close();
		await rm(root, { recursive: true, force: true });
	}
});
it.each([
	"validate_candidate",
	"review_candidate_changes",
])("%s binds immutable owning artifact into separately approved request", async (command) => {
	const root = await mkdtemp(join(tmpdir(), "candidate-workflow-")),
		scope = { sessionId: "owned", workspace: root },
		store = new AnalysisWorkflowStore(join(root, "workflow.sqlite"));
	const invoke = vi.fn(async () => ({ id: "plan" })),
		ports = {
			invoke,
			staticReceipt: vi.fn(),
			taskBundle: vi.fn(),
			capture: vi.fn(),
		};
	try {
		await writeFile(join(root, "candidate.ts"), "export const owned=1;");
		const h = await store.open(scope, "candidate.ts");
		const input = {
			artifactId: h.id,
			...(command === "validate_candidate" ? { kind: "typescript" } : {}),
		};
		await handleAnalysisWorkflow(
			command,
			input,
			scope,
			{ trusted: true, idle: true, mode: "static" },
			store,
			ports,
		);
		expect(invoke).toHaveBeenCalledWith(
			"prepare_analysis_task",
			expect.objectContaining({
				kind: "static",
				request: expect.objectContaining({
					operation: command,
					target: h.path,
					...(command === "validate_candidate"
						? {
								candidate_validation: {
									expected_sha256: h.sha256,
									kind: "typescript",
								},
							}
						: { candidate_review: { manifest_sha256: h.sha256 } }),
				}),
			}),
		);
		await expect(
			handleAnalysisWorkflow(
				command,
				{ ...input, phase: "run" },
				scope,
				{ trusted: true, idle: true, mode: "static" },
				store,
				ports,
			),
		).rejects.toThrow("one-use");
		await expect(
			handleAnalysisWorkflow(
				command,
				input,
				{ ...scope, sessionId: "other" },
				{ trusted: true, idle: true, mode: "static" },
				store,
				ports,
			),
		).rejects.toThrow("unavailable");
		await expect(
			handleAnalysisWorkflow(
				command,
				input,
				scope,
				{ trusted: true, idle: true, mode: "off" },
				store,
				ports,
			),
		).rejects.toThrow("Analysis enabled");
		await expect(
			handleAnalysisWorkflow(
				command,
				input,
				scope,
				{ trusted: false, idle: true, mode: "static" },
				store,
				ports,
			),
		).rejects.toThrow("trusted");
		await writeFile(h.path, "changed");
		await expect(
			handleAnalysisWorkflow(
				command,
				input,
				scope,
				{ trusted: true, idle: true, mode: "static" },
				store,
				ports,
			),
		).rejects.toThrow("changed");
	} finally {
		store.close();
		await rm(root, { recursive: true, force: true });
	}
});
it("runtime planner binds owning immutable source but never invokes runtime from Static mode", async () => {
	const root = await mkdtemp(join(tmpdir(), "runtime-plan-workflow-")),
		scope = { sessionId: "owned", workspace: root },
		store = new AnalysisWorkflowStore(join(root, "workflow.sqlite"));
	const invoke = vi.fn(async () => ({ id: "plan" })),
		ports = {
			invoke,
			staticReceipt: vi.fn(),
			taskBundle: vi.fn(),
			capture: vi.fn(),
		};
	try {
		await writeFile(
			join(root, "owned.js"),
			"throw new Error('MUST_NOT_EXECUTE');",
		);
		const h = await store.open(scope, "owned.js");
		const input = {
			artifactId: h.id,
			observation: {
				backend: "node-inspector",
				pid: 123,
				processToken: "owned",
				endpoint: "ws://127.0.0.1:9229/00000000-0000-0000-0000-000000000000",
			},
		};
		await handleAnalysisWorkflow(
			"plan_runtime_observation",
			input,
			scope,
			{ trusted: true, idle: true, mode: "static" },
			store,
			ports,
		);
		expect(invoke).toHaveBeenCalledWith(
			"prepare_analysis_task",
			expect.objectContaining({
				kind: "static",
				request: expect.objectContaining({
					operation: "plan_runtime_observation",
					target: h.path,
					runtime_observation_plan: expect.objectContaining({
						expected_sha256: h.sha256,
					}),
				}),
			}),
		);
		await expect(
			handleAnalysisWorkflow(
				"plan_runtime_observation",
				{ ...input, phase: "run" },
				scope,
				{ trusted: true, idle: true, mode: "static" },
				store,
				ports,
			),
		).rejects.toThrow("one-use");
		await expect(
			handleAnalysisWorkflow(
				"plan_runtime_observation",
				input,
				{ ...scope, sessionId: "other" },
				{ trusted: true, idle: true, mode: "static" },
				store,
				ports,
			),
		).rejects.toThrow("unavailable");
		expect(ports.capture).not.toHaveBeenCalled();
	} finally {
		store.close();
		await rm(root, { recursive: true, force: true });
	}
});

it.each([
	"capture_process_tree",
	"capture_file_activity",
] as const)("%s cannot run in Static or cross artifact owners", async (command) => {
	const root = await mkdtemp(join(tmpdir(), "runtime-workflow-")),
		scope = { sessionId: "owned", workspace: root },
		store = new AnalysisWorkflowStore(join(root, "store.sqlite"));
	const runtimeCapture = vi.fn(async () => ({ status: "prepared" })),
		ports = {
			invoke: vi.fn(),
			staticReceipt: vi.fn(),
			taskBundle: vi.fn(),
			capture: vi.fn(),
			runtimeCapture,
		};
	try {
		await writeFile(join(root, "owned.js"), "owned");
		const artifact = await store.open(scope, "owned.js");
		const input = {
			artifactId: artifact.id,
			...(command === "capture_process_tree"
				? { pid: process.pid }
				: { durationMs: 200 }),
		};
		await expect(
			handleAnalysisWorkflow(
				command,
				input,
				scope,
				{ trusted: true, idle: true, mode: "static" },
				store,
				ports,
			),
		).rejects.toThrow("Runtime or Hybrid");
		expect(runtimeCapture).not.toHaveBeenCalled();
		await handleAnalysisWorkflow(
			command,
			input,
			scope,
			{ trusted: true, idle: true, mode: "runtime" },
			store,
			ports,
		);
		expect(runtimeCapture).toHaveBeenCalledWith(
			command,
			expect.objectContaining({
				phase: "prepare",
				request: expect.objectContaining({
					target: artifact.path,
					expected_sha256: artifact.sha256,
				}),
			}),
		);
		await expect(
			handleAnalysisWorkflow(
				command,
				input,
				{ ...scope, sessionId: "other" },
				{ trusted: true, idle: true, mode: "runtime" },
				store,
				ports,
			),
		).rejects.toThrow("unavailable");
		await expect(
			handleAnalysisWorkflow(
				command,
				{ ...input, confirmRecord: true },
				scope,
				{ trusted: true, idle: true, mode: "runtime" },
				store,
				ports,
			),
		).rejects.toThrow();
	} finally {
		store.close();
		await rm(root, { recursive: true, force: true });
	}
});
it("managed debugger front door binds immutable artifacts, denies Static and permits Off cleanup", async () => {
	const root = await mkdtemp(join(tmpdir(), "managed-workflow-")),
		store = new AnalysisWorkflowStore(join(root, "store.sqlite")),
		scope = { sessionId: "owned", workspace: root };
	const managedRuntime = vi.fn(async () => ({ status: "partial" }));
	const ports = {
		invoke: vi.fn(),
		staticReceipt: vi.fn(),
		taskBundle: vi.fn(),
		capture: vi.fn(),
		managedRuntime,
		managedSession: vi.fn(() => ({
			target: join(root, "owned.js"),
			expected_sha256: "a".repeat(64),
		})),
	};
	try {
		await writeFile(join(root, "owned.js"), "// owned");
		const artifact = await store.open(scope, "owned.js");
		const input = {
			artifactId: artifact.id,
			pid: 123,
			endpoint: "ws://127.0.0.1:9229/11111111-1111-4111-8111-111111111111",
		};
		await expect(
			handleAnalysisWorkflow(
				"attach_debug_session",
				input,
				scope,
				{ trusted: true, idle: true, mode: "static" },
				store,
				ports,
			),
		).rejects.toThrow("Runtime/Hybrid");
		await handleAnalysisWorkflow(
			"attach_debug_session",
			input,
			scope,
			{ trusted: true, idle: true, mode: "runtime" },
			store,
			ports,
		);
		expect(managedRuntime).toHaveBeenCalledWith(
			"attach_debug_session",
			expect.objectContaining({
				request: expect.objectContaining({
					target: realpathSync.native(join(root, "owned.js")),
					expected_sha256: artifact.sha256,
				}),
			}),
		);
		await handleAnalysisWorkflow(
			"set_scoped_breakpoints",
			{ runtimeSessionId: artifact.id, locations: [{ line: 1 }] },
			scope,
			{ trusted: true, idle: true, mode: "runtime" },
			store,
			ports,
		);
		expect(ports.managedSession).toHaveBeenCalledWith(artifact.id);
		await handleAnalysisWorkflow(
			"stop_runtime_session",
			{ runtimeSessionId: artifact.id },
			scope,
			{ trusted: true, idle: false, mode: "off" },
			store,
			ports,
		);
		expect(managedRuntime).toHaveBeenLastCalledWith("stop_runtime_session", {
			runtimeSessionId: artifact.id,
		});
		await expect(
			handleAnalysisWorkflow(
				"stop_runtime_session",
				{ runtimeSessionId: artifact.id },
				scope,
				{ trusted: false, idle: true, mode: "off" },
				store,
				ports,
			),
		).rejects.toThrow("Trusted");
	} finally {
		store.close();
		await rm(root, { recursive: true, force: true });
	}
});

it("saved correlation rejects missing, duplicate and untrusted task inputs without rerunning providers", async () => {
	const root = await mkdtemp(join(tmpdir(), "correlation-owned-"));
	try {
		const scope = { sessionId: "owned", workspace: root },
			input = {
				receiptId: "11111111-1111-4111-8111-111111111111",
				taskIds: ["22222222-2222-4222-8222-222222222222"],
			};
		const ports = {
			invoke: vi.fn(),
			capture: vi.fn(),
			staticReceipt: vi.fn(),
			taskBundle: vi.fn(() => ({})),
		};
		const store = {} as AnalysisWorkflowStore;
		await expect(
			handleAnalysisWorkflow(
				"correlate_static_runtime",
				input,
				scope,
				{ trusted: false, idle: true, mode: "off" },
				store,
				ports,
			),
		).rejects.toThrow("Trusted");
		expect(ports.taskBundle).not.toHaveBeenCalled();
		await expect(
			handleAnalysisWorkflow(
				"correlate_static_runtime",
				{ ...input, taskIds: [...input.taskIds, ...input.taskIds] },
				scope,
				{ trusted: true, idle: true, mode: "off" },
				store,
				ports,
			),
		).rejects.toThrow("distinct");
		await expect(
			handleAnalysisWorkflow(
				"correlate_static_runtime",
				input,
				scope,
				{ trusted: true, idle: true, mode: "off" },
				store,
				ports,
			),
		).rejects.toThrow("no observation will be rerun");
		expect(ports.invoke).not.toHaveBeenCalled();
		expect(ports.capture).not.toHaveBeenCalled();
		expect(ports.staticReceipt).not.toHaveBeenCalled();
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
it("correlates owning saved static/runtime evidence in Off without invoking tools", async () => {
	const { ANALYSIS_PROFILE, digest } = await import("@cline/core");
	const root = await mkdtemp(join(tmpdir(), "correlation-positive-"));
	try {
		const scope = { sessionId: "owned", workspace: realpathSync(root) },
			hash = "a".repeat(64);
		const result = {
			profile: ANALYSIS_PROFILE,
			parserVersion: "owned",
			status: "completed",
			artifacts: [{ path: "owned.js", sha256: hash, bytes: 1, role: "source" }],
			facts: [],
			edges: [],
			limitations: [],
			counters: { entries: 1, bytes: 1, nodes: 0 },
		};
		const receipt = {
			...scope,
			id: "11111111-1111-4111-8111-111111111111",
			status: "completed",
			result,
			resultHash: digest(result),
		};
		const observed = {
			provider: "v8-cpu-sampling-selected-script",
			sourceSha256: hash,
			nodes: [],
			samples: [],
		};
		const raw = {
			...scope,
			id: hash,
			taskId: "22222222-2222-4222-8222-222222222222",
			domain: "debugger",
			operation: "capture_execution_trace",
			tool: "managed-node-inspector/1",
			targetSha256: hash,
			resultHash: digest(observed),
			requestHash: hash,
			at: new Date().toISOString(),
			result: observed,
		};
		let snapshot = { ...raw, snapshotHash: digest(raw) };
		const ports = {
			invoke: vi.fn(),
			capture: vi.fn(),
			staticReceipt: vi.fn(() => receipt),
			taskBundle: vi.fn(() => ({ providerSnapshot: snapshot })),
		};
		const input = { receiptId: receipt.id, taskIds: [raw.taskId] },
			options = { trusted: true, idle: true, mode: "off" };
		const report = await handleAnalysisWorkflow(
			"correlate_static_runtime",
			input,
			scope,
			options,
			{} as AnalysisWorkflowStore,
			ports,
		);
		expect(report).toMatchObject({
			status: "partial",
			effect: "saved-evidence-read",
			verifiedBehavior: false,
			sampling: [{ sourceIdentity: "exact-byte-match", candidates: [] }],
		});
		const foreign = { ...raw, sessionId: "other" };
		snapshot = { ...foreign, snapshotHash: digest(foreign) };
		await expect(
			handleAnalysisWorkflow(
				"correlate_static_runtime",
				input,
				scope,
				options,
				{} as AnalysisWorkflowStore,
				ports,
			),
		).rejects.toThrow("scope");
		expect(ports.invoke).not.toHaveBeenCalled();
		expect(ports.capture).not.toHaveBeenCalled();
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});

it("device front door binds immutable artifact and denies Static while preserving Off cleanup", async () => {
	const root = await mkdtemp(join(tmpdir(), "device-workflow-")),
		scope = { sessionId: "owned", workspace: root },
		store = new AnalysisWorkflowStore(join(root, "workflow.sqlite"));
	const deviceSmoke = vi.fn(async () => ({ status: "prepared" })),
		ports = {
			invoke: vi.fn(),
			staticReceipt: vi.fn(),
			taskBundle: vi.fn(),
			capture: vi.fn(),
			deviceSmoke,
		};
	try {
		await writeFile(join(root, "owned.apk"), "owned fixture");
		const artifact = await store.open(scope, "owned.apk"),
			input = {
				action: "start",
				artifactId: artifact.id,
				deviceSerial: "owned-device",
				packageName: "com.example.app",
				purpose: "Owned observation",
			};
		await expect(
			handleAnalysisWorkflow(
				"run_device_smoke_test",
				input,
				scope,
				{ trusted: true, idle: true, mode: "static" },
				store,
				ports,
			),
		).rejects.toThrow("Static");
		expect(deviceSmoke).not.toHaveBeenCalled();
		await handleAnalysisWorkflow(
			"run_device_smoke_test",
			input,
			scope,
			{ trusted: true, idle: true, mode: "runtime" },
			store,
			ports,
		);
		expect(deviceSmoke).toHaveBeenCalledWith(
			expect.objectContaining({
				phase: "prepare",
				request: expect.objectContaining({
					target: artifact.path,
					expected_sha256: artifact.sha256,
					durationSeconds: 10,
				}),
			}),
		);
		await expect(
			handleAnalysisWorkflow(
				"run_device_smoke_test",
				input,
				{ ...scope, sessionId: "other" },
				{ trusted: true, idle: true, mode: "runtime" },
				store,
				ports,
			),
		).rejects.toThrow("unavailable");
		await handleAnalysisWorkflow(
			"run_device_smoke_test",
			{ action: "cancel", taskId: artifact.id },
			scope,
			{ trusted: true, idle: false, mode: "off" },
			store,
			ports,
		);
		expect(deviceSmoke).toHaveBeenLastCalledWith({
			request: { action: "cancel", taskId: artifact.id },
		});
	} finally {
		store.close();
		await rm(root, { recursive: true, force: true });
	}
});

it("release gate is a trusted Inspect workflow; saved reads and cleanup route after Off without network authority", async () => {
	const root = realpathSync(await mkdtemp(join(tmpdir(), "release-route-"))),
		store = new AnalysisWorkflowStore(join(root, "store.sqlite")),
		scope = { sessionId: "owned", workspace: root };
	const releaseGate = vi.fn(async () => ({ status: "cancelled" })),
		ports = {
			invoke: vi.fn(),
			capture: vi.fn(),
			staticReceipt: vi.fn(),
			taskBundle: vi.fn(),
			releaseGate,
		};
	const input = {
			action: "check",
			pullNumber: 133,
			expectedHead: "a".repeat(40),
		},
		options = { trusted: true, idle: true, mode: "static" };
	try {
		await handleAnalysisWorkflow(
			"check_release_gate",
			input,
			scope,
			options,
			store,
			ports,
		);
		expect(releaseGate).toHaveBeenLastCalledWith({
			phase: "prepare",
			request: input,
		});
		for (const extra of [
			{ url: "https://invalid.example" },
			{ policy: "override" },
			{ owner_session_id: "other" },
		])
			await expect(
				handleAnalysisWorkflow(
					"check_release_gate",
					{ ...input, ...extra },
					scope,
					options,
					store,
					ports,
				),
			).rejects.toThrow();
		await expect(
			handleAnalysisWorkflow(
				"check_release_gate",
				input,
				scope,
				{ ...options, trusted: false },
				store,
				ports,
			),
		).rejects.toThrow("Trusted");
		await expect(
			handleAnalysisWorkflow(
				"check_release_gate",
				input,
				scope,
				{ ...options, mode: "off" },
				store,
				ports,
			),
		).rejects.toThrow("enabled");
		await expect(
			handleAnalysisWorkflow(
				"check_release_gate",
				input,
				scope,
				{ ...options, idle: false },
				store,
				ports,
			),
		).rejects.toThrow("enabled");
		for (const action of ["read", "cancel"]) {
			const request = {
				action,
				taskId: "11111111-1111-4111-8111-111111111111",
			};
			await handleAnalysisWorkflow(
				"check_release_gate",
				request,
				scope,
				{ ...options, idle: false, mode: "off" },
				store,
				ports,
			);
			expect(releaseGate).toHaveBeenLastCalledWith({ request });
		}
		expect(ports.invoke).not.toHaveBeenCalled();
		expect(ports.capture).not.toHaveBeenCalled();
	} finally {
		store.close();
		await rm(root, { recursive: true, force: true });
	}
});

it("project-file review carries exact scope into Inspect approval, never validation or unbound execution", async () => {
	const root = await mkdtemp(join(tmpdir(), "project-review-workflow-")),
		scope = { sessionId: "owned", workspace: root },
		store = new AnalysisWorkflowStore(join(root, "workflow.sqlite"));
	const invoke = vi.fn(async () => ({ id: "plan" })),
		ports = {
			invoke,
			staticReceipt: vi.fn(),
			taskBundle: vi.fn(),
			capture: vi.fn(),
		};
	try {
		await writeFile(join(root, "manifest.json"), "{}");
		const artifact = await store.open(scope, "manifest.json"),
			input = { artifactId: artifact.id, scope: "project-files" },
			options = { trusted: true, idle: true, mode: "static" };
		await handleAnalysisWorkflow(
			"review_candidate_changes",
			input,
			scope,
			options,
			store,
			ports,
		);
		expect(invoke).toHaveBeenCalledWith(
			"prepare_analysis_task",
			expect.objectContaining({
				kind: "static",
				request: expect.objectContaining({
					candidate_review: {
						manifest_sha256: artifact.sha256,
						scope: "project-files",
					},
				}),
			}),
		);
		await handleAnalysisWorkflow(
			"review_candidate_changes",
			{ ...input, scope: "project-inventory" },
			scope,
			options,
			store,
			ports,
		);
		expect(invoke).toHaveBeenLastCalledWith(
			"prepare_analysis_task",
			expect.objectContaining({
				request: expect.objectContaining({
					candidate_review: {
						manifest_sha256: artifact.sha256,
						scope: "project-inventory",
					},
				}),
			}),
		);
		await expect(
			handleAnalysisWorkflow(
				"review_candidate_changes",
				{ ...input, phase: "run" },
				scope,
				options,
				store,
				ports,
			),
		).rejects.toThrow("one-use");
		await expect(
			handleAnalysisWorkflow(
				"validate_candidate",
				{ ...input, kind: "typescript" },
				scope,
				options,
				store,
				ports,
			),
		).rejects.toThrow("only accepted");
	} finally {
		store.close();
		await rm(root, { recursive: true, force: true });
	}
});

it("unknown ledger metadata requires a trusted host and never invokes an engine while Off", async () => {
	const unknowns = vi.fn((input) => ({ input, verifiedBehavior: false })),
		invoke = vi.fn();
	const ports = {
		unknowns,
		invoke,
		staticReceipt: vi.fn(),
		taskBundle: vi.fn(),
		capture: vi.fn(),
	};
	const scope = { sessionId: "owned", workspace: "/owned" };
	const store = {} as AnalysisWorkflowStore;
	const input = {
		action: "list",
		caseId: "11111111-1111-4111-8111-111111111111",
	};
	await expect(
		handleAnalysisWorkflow(
			"manage_investigation_unknowns",
			input,
			scope,
			{ trusted: false, idle: true, mode: "off" },
			store,
			ports,
		),
	).rejects.toThrow("Trusted");
	expect(unknowns).not.toHaveBeenCalled();
	await expect(
		handleAnalysisWorkflow(
			"manage_investigation_unknowns",
			{ ...input, executionToken: "forged" },
			scope,
			{ trusted: true, idle: true, mode: "off" },
			store,
			ports,
		),
	).rejects.toThrow();
	expect(unknowns).not.toHaveBeenCalled();
	expect(
		await handleAnalysisWorkflow(
			"manage_investigation_unknowns",
			input,
			scope,
			{ trusted: true, idle: false, mode: "off" },
			store,
			ports,
		),
	).toMatchObject({ verifiedBehavior: false });
	expect(unknowns).toHaveBeenCalledOnce();
	expect(invoke).not.toHaveBeenCalled();
});

it("native flow reads exact retained snapshots while Off and never invokes a provider", async () => {
	const { digest } = await import("@cline/core");
	const root = await mkdtemp(join(tmpdir(), "native-flow-host-"));
	try {
		const scope = { sessionId: "owned", workspace: realpathSync(root) },
			taskId = "22222222-2222-4222-8222-222222222222",
			hash = "a".repeat(64),
			result = {
				engine: "ghidra",
				engineVersion: "12.1.4",
				input: { sha256: hash },
				evidence: { selectedFunctions: [] },
			},
			raw = {
				...scope,
				id: hash,
				taskId,
				domain: "static",
				operation: "decompile",
				tool: "ghidra",
				targetSha256: hash,
				resultHash: digest(result),
				requestHash: hash,
				at: new Date().toISOString(),
				result,
			};
		const ports = {
				invoke: vi.fn(),
				capture: vi.fn(),
				staticReceipt: vi.fn(),
				taskBundle: vi.fn(() => ({
					providerSnapshot: { ...raw, snapshotHash: digest(raw) },
				})),
			},
			input = { action: "list", taskIds: [taskId] };
		await expect(
			handleAnalysisWorkflow(
				"trace_native_value_flow",
				input,
				scope,
				{ trusted: false, idle: true, mode: "off" },
				{} as AnalysisWorkflowStore,
				ports,
			),
		).rejects.toThrow("Trusted");
		expect(ports.taskBundle).not.toHaveBeenCalled();
		expect(
			await handleAnalysisWorkflow(
				"trace_native_value_flow",
				input,
				scope,
				{ trusted: true, idle: false, mode: "off" },
				{} as AnalysisWorkflowStore,
				ports,
			),
		).toMatchObject({
			effect: "saved-evidence-read",
			verifiedBehavior: false,
			functions: [],
		});
		expect(ports.invoke).not.toHaveBeenCalled();
		expect(ports.capture).not.toHaveBeenCalled();
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
it("metadata reader prepares an immutable exact hash request and cannot bypass enabled mode or approvals", async () => {
	const root = await mkdtemp(join(tmpdir(), "metadata-host-")),
		scope = { sessionId: "owned", workspace: root },
		store = new AnalysisWorkflowStore(join(root, "store.sqlite"));
	try {
		await writeFile(join(root, "owned.bin"), "owned");
		const artifact = await store.open(scope, "owned.bin"),
			input = { artifactId: artifact.id, reader: "go" },
			ports = {
				invoke: vi.fn(async () => ({ status: "prepared" })),
				capture: vi.fn(),
				staticReceipt: vi.fn(),
				taskBundle: vi.fn(),
			};
		await expect(
			handleAnalysisWorkflow(
				"inspect_artifact_metadata",
				input,
				scope,
				{ trusted: true, idle: true, mode: "off" },
				store,
				ports,
			),
		).rejects.toThrow("Analysis enabled");
		expect(ports.invoke).not.toHaveBeenCalled();
		await handleAnalysisWorkflow(
			"inspect_artifact_metadata",
			input,
			scope,
			{ trusted: true, idle: true, mode: "static" },
			store,
			ports,
		);
		expect(ports.invoke).toHaveBeenCalledWith("prepare_analysis_task", {
			kind: "static",
			request: {
				operation: "javascript_analysis",
				target: artifact.path,
				timeout_ms: 120000,
				javascript_options: {
					artifactReader: { reader: "go", expectedSha256: artifact.sha256 },
				},
			},
		});
		await expect(
			handleAnalysisWorkflow(
				"inspect_artifact_metadata",
				{ ...input, phase: "run" },
				scope,
				{ trusted: true, idle: true, mode: "static" },
				store,
				ports,
			),
		).rejects.toThrow("one-use");
		await writeFile(join(root, "owned.bin"), "changed");
		await expect(
			handleAnalysisWorkflow(
				"inspect_artifact_metadata",
				input,
				scope,
				{ trusted: true, idle: true, mode: "static" },
				store,
				ports,
			),
		).rejects.toThrow("changed");
	} finally {
		store.close();
		await rm(root, { recursive: true, force: true });
	}
});
it("bundle recovery and export are separate hash-bound Inspect/Modify requests with no self approval", async () => {
	const root = await mkdtemp(join(tmpdir(), "bundle-workflow-")),
		scope = { sessionId: "owned", workspace: root },
		store = new AnalysisWorkflowStore(join(root, "store.sqlite"));
	try {
		await writeFile(join(root, "bundle.js"), "owned");
		const artifact = await store.open(scope, "bundle.js"),
			ports = {
				invoke: vi.fn(async () => ({ status: "prepared" })),
				capture: vi.fn(),
				staticReceipt: vi.fn(),
				taskBundle: vi.fn(),
			},
			options = { trusted: true, idle: true, mode: "static" };
		await handleAnalysisWorkflow(
			"recover_bundle_sources",
			{ artifactId: artifact.id },
			scope,
			options,
			store,
			ports,
		);
		expect(ports.invoke).toHaveBeenLastCalledWith("prepare_analysis_task", {
			kind: "static",
			request: {
				operation: "javascript_analysis",
				target: artifact.path,
				timeout_ms: 120000,
				javascript_options: {
					bundleRecovery: { expectedSha256: artifact.sha256 },
				},
			},
		});
		await handleAnalysisWorkflow(
			"recover_bundle_sources",
			{ artifactId: artifact.id, engine: "wakaru" },
			scope,
			options,
			store,
			ports,
		);
		expect(ports.invoke).toHaveBeenLastCalledWith("prepare_analysis_task", {
			kind: "static",
			request: {
				operation: "javascript_analysis",
				target: artifact.path,
				timeout_ms: 120000,
				javascript_options: {
					bundleRecovery: { expectedSha256: artifact.sha256, engine: "wakaru" },
				},
			},
		});
		const req = {
			artifactId: artifact.id,
			receiptId: artifact.id,
			reportHash: "a".repeat(64),
			outputFile: join(root, "new.json"),
		};
		await handleAnalysisWorkflow(
			"publish_bundle_recovery",
			req,
			scope,
			options,
			store,
			ports,
		);
		expect(ports.invoke).toHaveBeenLastCalledWith("prepare_analysis_task", {
			kind: "static",
			request: {
				operation: "export_bundle_recovery",
				target: artifact.path,
				timeout_ms: 120000,
				output_file: req.outputFile,
				bundle_export: { receiptId: req.receiptId, reportHash: req.reportHash },
			},
		});
		await expect(
			handleAnalysisWorkflow(
				"publish_bundle_recovery",
				{ ...req, phase: "run" },
				scope,
				options,
				store,
				ports,
			),
		).rejects.toThrow("one-use");
		await expect(
			handleAnalysisWorkflow(
				"recover_bundle_sources",
				{ artifactId: artifact.id },
				scope,
				{ ...options, mode: "off" },
				store,
				ports,
			),
		).rejects.toThrow("Analysis enabled");
	} finally {
		store.close();
		await rm(root, { recursive: true, force: true });
	}
});
