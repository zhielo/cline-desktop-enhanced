import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { probeProcessStartTokenAsync } from "@cline/core";
import { afterEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
	mode: "runtime",
	workspace: "",
	record: vi.fn(),
}));
vi.mock("./first-party-analysis", () => ({
	firstPartyStore: () => ({
		session: () => ({ mode: state.mode, workspace: state.workspace }),
		get: () => undefined,
	}),
	bindFirstPartyTaskEvidence: vi.fn(),
	recordFirstPartyTaskEvidence: state.record,
	sessionTaskSnapshots: () => [],
}));

import {
	AnalysisTaskOrchestrator,
	type AnalysisTaskPlan,
} from "./analysis-task-orchestrator";
import type { ManagedInspectorSessions } from "./managed-inspector";
import { handleManagedRuntime } from "./managed-runtime";

const roots: string[] = [];
afterEach(async () => {
	state.mode = "runtime";
	state.record.mockReset();
	for (const root of roots.splice(0))
		await rm(root, { recursive: true, force: true });
});
async function fixture() {
	const root = realpathSync.native(
		await mkdtemp(join(tmpdir(), "managed-approval-")),
	);
	roots.push(root);
	// Store keys intentionally retain the ordinary resolver for backwards compatibility.
	state.workspace = realpathSync(root);
	const target = join(root, "owned.js");
	await writeFile(target, "// owned");
	const identity = await probeProcessStartTokenAsync(process.pid);
	if (identity.status !== "found")
		throw new Error("Fixture birth identity unavailable");
	const targetState = {
		target,
		expected_sha256: createHash("sha256").update("// owned").digest("hex"),
		pid: process.pid,
		processToken: identity.token,
		endpoint: "ws://127.0.0.1:9229/11111111-1111-4111-8111-111111111111",
		lifetimeMs: 60000,
	};
	const manager = {
		attach: vi.fn(async () => ({
			status: "partial",
			runtimeSessionId: "11111111-1111-4111-8111-111111111111",
		})),
		describe: vi.fn(() => targetState),
		breakpoints: vi.fn(async () => ({ status: "partial" })),
		sample: vi.fn(async () => ({ status: "partial" })),
		stop: vi.fn(async () => ({ status: "completed", transportClosed: true })),
	};
	const tasks = new AnalysisTaskOrchestrator({
		ledgerFilePath: join(root, "ledger.json"),
	});
	const request = {
		operation: "attach_debug_session",
		target,
		expected_sha256: targetState.expected_sha256,
		options: {
			pid: process.pid,
			endpoint: targetState.endpoint,
			lifetimeMs: 60000,
		},
	};
	const call = (
		input: unknown,
		sessionId = "owned",
		command = "attach_debug_session",
	) =>
		handleManagedRuntime(
			command,
			input,
			{ sessionId, workspace: root },
			tasks,
			manager as unknown as ManagedInspectorSessions,
		);
	return { root, target, tasks, request, call, manager };
}
it("demands independent Execute approval, denies replay and cross-session tokens", async () => {
	const f = await fixture(),
		plan = (await f.call({
			phase: "prepare",
			request: f.request,
		})) as AnalysisTaskPlan;
	expect(plan.permission).toBe("Execute");
	expect(plan.risk).toBe("high");
	expect(plan.requirements).toEqual(
		expect.arrayContaining([
			"execution-control",
			"independent-managed-runtime-execute-approval",
			"debugger-activation-cleanup-may-pause-or-resume",
		]),
	);
	await expect(
		f.call({ phase: "run", request: f.request, planId: plan.id }),
	).rejects.toThrow("one-use");
	const { executionToken } = f.tasks.approve(
			plan.id,
			plan.requirements,
			plan.requestHash,
		),
		input = {
			phase: "run",
			request: f.request,
			planId: plan.id,
			executionToken,
		};
	await expect(f.call(input, "other")).rejects.toThrow("owning session");
	expect(f.manager.attach).not.toHaveBeenCalled();
	expect(await f.call(input)).toMatchObject({ result: { status: "partial" } });
	expect(f.manager.attach).toHaveBeenCalledOnce();
	await expect(f.call(input)).rejects.toThrow("approval");
});
it("rejects Static, authority injection, changed endpoint and options", async () => {
	const f = await fixture();
	state.mode = "static";
	await expect(
		f.call({ phase: "prepare", request: f.request }),
	).rejects.toThrow("Runtime/Hybrid");
	state.mode = "runtime";
	await expect(
		f.call({
			phase: "prepare",
			request: { ...f.request, owner_session_id: "forged" },
		}),
	).rejects.toThrow();
	const plan = (await f.call({
			phase: "prepare",
			request: f.request,
		})) as AnalysisTaskPlan,
		{ executionToken } = f.tasks.approve(
			plan.id,
			plan.requirements,
			plan.requestHash,
		);
	await expect(
		f.call({
			phase: "run",
			planId: plan.id,
			executionToken,
			request: {
				...f.request,
				options: { ...f.request.options, lifetimeMs: 60001 },
			},
		}),
	).rejects.toThrow("approval");
	expect(f.manager.attach).not.toHaveBeenCalled();
	f.tasks.cancel(plan.id);
});
it("keeps owning cleanup available after Off and never requests fresh work approval", async () => {
	const f = await fixture();
	state.mode = "off";
	expect(
		await f.call(
			{ runtimeSessionId: "11111111-1111-4111-8111-111111111111" },
			"owned",
			"stop_runtime_session",
		),
	).toMatchObject({ transportClosed: true });
	expect(f.manager.stop).toHaveBeenCalledOnce();
	expect(f.tasks.list(f.root)).toHaveLength(0);
});
it("follow-up sampling derives target identity from owned session and requires a fresh exact plan", async () => {
	const f = await fixture(),
		request = {
			operation: "capture_execution_trace",
			target: f.target,
			expected_sha256: f.request.expected_sha256,
			options: {
				runtimeSessionId: "11111111-1111-4111-8111-111111111111",
				durationMs: 200,
			},
		};
	const plan = (await f.call(
		{ phase: "prepare", request },
		"owned",
		"capture_execution_trace",
	)) as AnalysisTaskPlan;
	expect(plan.permission).toBe("Execute");
	const { executionToken } = f.tasks.approve(
		plan.id,
		plan.requirements,
		plan.requestHash,
	);
	await f.call(
		{ phase: "run", planId: plan.id, executionToken, request },
		"owned",
		"capture_execution_trace",
	);
	expect(f.manager.sample).toHaveBeenCalledOnce();
	await expect(
		f.call(
			{
				phase: "prepare",
				request: { ...request, expected_sha256: "0".repeat(64) },
			},
			"owned",
			"capture_execution_trace",
		),
	).rejects.toThrow("target");
});
it("closes newly attached connection if mode changes before task completion", async () => {
	const f = await fixture(),
		plan = (await f.call({
			phase: "prepare",
			request: f.request,
		})) as AnalysisTaskPlan;
	const { executionToken } = f.tasks.approve(
		plan.id,
		plan.requirements,
		plan.requestHash,
	);
	f.manager.attach.mockImplementation(async () => {
		state.mode = "off";
		return {
			status: "partial",
			runtimeSessionId: "11111111-1111-4111-8111-111111111111",
		};
	});
	await expect(
		f.call({
			phase: "run",
			request: f.request,
			planId: plan.id,
			executionToken,
		}),
	).rejects.toThrow("mode changed");
	expect(f.manager.stop).toHaveBeenCalledOnce();
});
it("missing Hybrid basis cannot reach managed runtime control", async () => {
	const f = await fixture();
	state.mode = "hybrid";
	await expect(
		f.call({ phase: "prepare", request: f.request }),
	).rejects.toThrow();
	expect(f.manager.attach).not.toHaveBeenCalled();
});
