import { digest } from "@cline/core";
import { createHash } from "node:crypto";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
	mode: "runtime",
	workspace: "",
	receipt: undefined as unknown,
	bind: vi.fn(),
	record: vi.fn(),
}));
vi.mock("./first-party-analysis", () => ({
	firstPartyStore: () => ({
		session: () => ({ mode: state.mode, workspace: state.workspace }),
		get: () => state.receipt,
	}),
	bindFirstPartyTaskEvidence: state.bind,
	recordFirstPartyTaskEvidence: state.record,
	sessionTaskSnapshots: () => [],
}));

import {
	AnalysisTaskOrchestrator,
	type AnalysisTaskPlan,
} from "./analysis-task-orchestrator";
import { handleRuntimeCapture } from "./runtime-capture";

const roots: string[] = [];
afterEach(async () => {
	state.mode = "runtime";
	state.receipt = undefined;
	state.bind.mockClear();
	state.record.mockClear();
	for (const root of roots) await rm(root, { recursive: true, force: true });
	roots.length = 0;
});
async function fixture() {
	const root = await realpath(await mkdtemp(join(tmpdir(), "capture-task-")));
	roots.push(root);
	state.workspace = root;
	const target = join(root, "owned.js"),
		text = "// owned";
	await writeFile(target, text);
	const tasks = new AnalysisTaskOrchestrator({
		ledgerFilePath: join(root, "ledger.json"),
	});
	const scope = { sessionId: "owned", workspace: root };
	const request = {
		operation: "capture_file_activity",
		target,
		expected_sha256: createHash("sha256").update(text).digest("hex"),
		options: { durationMs: 200, maxEvents: 4 },
	};
	const call = (input: unknown, sessionId = "owned") =>
		handleRuntimeCapture(
			"capture_file_activity",
			input,
			{ ...scope, sessionId },
			tasks,
		);
	const prepare = () =>
		call({ phase: "prepare", request }) as Promise<AnalysisTaskPlan>;
	return { root, tasks, request, call, prepare };
}
it("requires exact one-use approval, denies cross-session reuse and records evidence", async () => {
	const f = await fixture(),
		plan = await f.prepare();
	expect(plan.kind).toBe("debugger");
	expect(plan.requirements).toContain("independent-runtime-metadata-approval");
	await expect(
		f.call({ phase: "run", request: f.request, planId: plan.id }),
	).rejects.toThrow("one-use");
	const approval = f.tasks.approve(
			plan.id,
			plan.requirements,
			plan.requestHash,
		),
		input = {
			phase: "run",
			request: f.request,
			planId: plan.id,
			executionToken: approval.executionToken,
		};
	await expect(f.call(input, "other")).rejects.toThrow("owning session");
	const result = await f.call(input);
	expect(result).toMatchObject({
		planId: plan.id,
		result: { status: "partial", provider: "node-fs-watch-exact-file" },
	});
	expect(state.record).toHaveBeenCalledOnce();
	await expect(f.call(input)).rejects.toThrow("approval");
});
it("does not widen Static or accept authority and altered request envelopes", async () => {
	const f = await fixture();
	state.mode = "static";
	await expect(f.prepare()).rejects.toThrow("Runtime/Hybrid");
	state.mode = "runtime";
	await expect(
		f.call({
			phase: "prepare",
			request: { ...f.request, owner_session_id: "other" },
		}),
	).rejects.toThrow();
	const plan = await f.prepare(),
		approval = f.tasks.approve(plan.id, plan.requirements, plan.requestHash);
	await expect(
		f.call({
			phase: "run",
			planId: plan.id,
			executionToken: approval.executionToken,
			request: { ...f.request, options: { durationMs: 201, maxEvents: 4 } },
		}),
	).rejects.toThrow("approval");
	f.tasks.cancel(plan.id);
});
it("mode changes cancel observation and release the capture slot", async () => {
	const f = await fixture();
	f.request.options.durationMs = 5000;
	const plan = await f.prepare(),
		approval = f.tasks.approve(plan.id, plan.requirements, plan.requestHash);
	const running = f.call({
		phase: "run",
		request: f.request,
		planId: plan.id,
		executionToken: approval.executionToken,
	});
	setTimeout(() => {
		state.mode = "off";
	}, 250);
	await expect(running).rejects.toThrow("mode changed");
	expect(state.record).not.toHaveBeenCalled();
	state.mode = "runtime";
	f.request.options.durationMs = 200;
	const next = await f.prepare(),
		nextApproval = f.tasks.approve(
			next.id,
			next.requirements,
			next.requestHash,
		);
	await expect(
		f.call({
			phase: "run",
			request: f.request,
			planId: next.id,
			executionToken: nextApproval.executionToken,
		}),
	).resolves.toMatchObject({ result: { status: "partial" } });
});
it("task cancellation closes a real watcher without persisting success", async () => {
	const f = await fixture();
	f.request.options.durationMs = 5000;
	const plan = await f.prepare(),
		approval = f.tasks.approve(plan.id, plan.requirements, plan.requestHash);
	const running = f.call({
		phase: "run",
		request: f.request,
		planId: plan.id,
		executionToken: approval.executionToken,
	});
	setTimeout(() => f.tasks.cancel(plan.id), 200);
	await expect(running).rejects.toThrow("cancelled");
	expect(state.record).not.toHaveBeenCalled();
	expect(f.tasks.list(f.root)[0]?.status).toBe("cancelled");
});

it("Hybrid binds an exact owning static basis and rejects stale evidence before observing", async () => {
	const f = await fixture();
	state.mode = "hybrid";
	await expect(f.prepare()).rejects.toThrow();
	const result = { artifacts: [{ sha256: f.request.expected_sha256 }] };
	const receipt = {
		sessionId: "owned",
		workspace: f.root,
		status: "completed",
		result,
		resultHash: digest(result),
	};
	state.receipt = receipt;
	const request = {
		...f.request,
		hybrid: {
			baselineKind: "receipt",
			baselineId: "11111111-1111-4111-8111-111111111111",
			question: "Did this exact file emit a notification?",
			evidenceHash: receipt.resultHash,
			relation: "exact-artifact-hash",
		},
	};
	const plan = (await f.call({
			phase: "prepare",
			request,
		})) as AnalysisTaskPlan,
		approval = f.tasks.approve(plan.id, plan.requirements, plan.requestHash);
	state.receipt = { ...receipt, resultHash: "a".repeat(64) };
	await expect(
		f.call({
			phase: "run",
			request,
			planId: plan.id,
			executionToken: approval.executionToken,
		}),
	).rejects.toThrow("intact result hash");
	expect(state.record).not.toHaveBeenCalled();
	f.tasks.cancel(plan.id);
});
