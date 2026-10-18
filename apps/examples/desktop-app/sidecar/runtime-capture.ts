import { realpathSync } from "node:fs";
import {
	probeProcessStartTokenAsync,
	runtimeAnalysisEnabled,
} from "@cline/core";
import { z } from "zod";
import type { AnalysisTaskOrchestrator } from "./analysis-task-orchestrator";
import {
	bindFirstPartyTaskEvidence,
	firstPartyStore,
	recordFirstPartyTaskEvidence,
	sessionTaskSnapshots,
} from "./first-party-analysis";
import { recheckHybridObservation } from "./hybrid-analysis";
import {
	assertCaptureFile,
	captureFileActivity,
	captureProcessTree,
} from "./runtime-capture-backend";

const Id = z.string().uuid();
const requestSchema = z
	.object({
		operation: z.enum(["capture_process_tree", "capture_file_activity"]),
		target: z.string().min(1).max(4096),
		expected_sha256: z.string().regex(/^[a-f0-9]{64}$/),
		options: z.union([
			z
				.object({
					pid: z.number().int().positive().max(4294967295),
					maxProcesses: z.number().int().min(1).max(128),
				})
				.strict(),
			z
				.object({
					durationMs: z.number().int().min(200).max(5000),
					maxEvents: z.number().int().min(1).max(128),
				})
				.strict(),
		]),
		hybrid: z.unknown().optional(),
	})
	.strict();
const slots = new Set<string>();
/** Host-only approval envelope. No input authority/owner/PID birth token is accepted from the model. */
export async function handleRuntimeCapture(
	command: string,
	raw: unknown,
	scope: { sessionId: string; workspace: string },
	tasks: AnalysisTaskOrchestrator,
) {
	const envelope = z
		.object({
			phase: z.enum(["prepare", "run"]),
			planId: Id.optional(),
			executionToken: z.string().min(1).max(512).optional(),
			request: requestSchema,
		})
		.strict()
		.parse(raw);
	const base = envelope.request;
	if (
		command !== base.operation ||
		(command === "capture_process_tree") !== "pid" in base.options
	)
		throw new Error("Capture command and strict options mismatch");
	const bound = firstPartyStore().session(scope.sessionId);
	if (
		!bound ||
		bound.workspace !== realpathSync(scope.workspace) ||
		!runtimeAnalysisEnabled(bound.mode)
	)
		throw new Error(
			"Runtime capture requires an owning Runtime/Hybrid session",
		);
	const hybridPorts = {
		receipt: (id: string) => firstPartyStore().get(scope.sessionId, id),
		task: (id: string) =>
			sessionTaskSnapshots(scope.sessionId, scope.workspace).find(
				(s) => s.taskId === id,
			),
	};
	const hybrid =
		bound.mode === "hybrid"
			? await recheckHybridObservation(
					base.hybrid,
					scope,
					hybridPorts,
					base.target,
				)
			: undefined;
	// Hybrid was already resolved/rechecked against owning task/receipt by the workflow.
	if (bound.mode !== "hybrid" && base.hybrid)
		throw new Error("Hybrid evidence cannot be used outside Hybrid mode");
	const assertCurrent = () => {
		const current = firstPartyStore().session(scope.sessionId);
		if (
			!current ||
			current.workspace !== bound.workspace ||
			current.mode !== bound.mode
		)
			throw new Error("Runtime capture scope or mode changed");
	};
	const owner_session_id = scope.sessionId;
	const request: Record<string, unknown> = {
		...base,
		owner_session_id,
		...(hybrid ? { hybrid } : {}),
	};
	if (envelope.phase === "prepare") {
		await assertCaptureFile(
			base.target,
			base.expected_sha256,
			new AbortController().signal,
		);
		if ("pid" in base.options) {
			const identity = await probeProcessStartTokenAsync(base.options.pid);
			if (identity.status !== "found")
				throw new Error("Exact process birth identity unavailable");
			request.processToken = identity.token;
		}
		assertCurrent();
		const plan = await tasks.prepare({
			workspaceRoot: scope.workspace,
			kind: "debugger",
			request,
			timeoutMs: 30000,
			maxOutputBytes: 262144,
		});
		bindFirstPartyTaskEvidence(scope.sessionId, scope.workspace, plan);
		return plan;
	}
	if (!envelope.planId || !envelope.executionToken)
		throw new Error("A separately approved one-use runtime plan is required");
	const saved = tasks
		.list(scope.workspace)
		.find((p) => p.id === envelope.planId);
	if (
		!saved ||
		saved.request.owner_session_id !== owner_session_id ||
		saved.operation !== command
	)
		throw new Error("Runtime capture plan unavailable in this owning session");
	if ("pid" in base.options) request.processToken = saved.request.processToken;
	if (slots.has(owner_session_id) || slots.size >= 2)
		throw new Error("Runtime capture concurrency budget exhausted");
	slots.add(owner_session_id);
	let started = false;
	let timer: ReturnType<typeof setInterval> | undefined;
	const capture = new AbortController();
	let taskSignal: AbortSignal | undefined;
	const cancel = () =>
		capture.abort(taskSignal?.reason ?? new Error("Capture cancelled"));
	try {
		const plan = await tasks.consume({
			planId: envelope.planId,
			executionToken: envelope.executionToken,
			workspaceRoot: scope.workspace,
			kind: "debugger",
			request,
		});
		started = true;
		taskSignal = tasks.signal(plan.id);
		taskSignal.addEventListener("abort", cancel, { once: true });
		if (taskSignal.aborted) cancel();
		timer = setInterval(() => {
			try {
				assertCurrent();
			} catch (error) {
				capture.abort(error);
			}
		}, 100);
		const signal = capture.signal;
		assertCurrent();
		if (hybrid)
			await recheckHybridObservation(hybrid, scope, hybridPorts, base.target);
		await assertCaptureFile(base.target, base.expected_sha256, signal);
		const result =
			"pid" in base.options
				? await captureProcessTree(
						base.options.pid,
						String(request.processToken),
						base.options.maxProcesses,
						signal,
					)
				: await captureFileActivity(
						base.target,
						base.expected_sha256,
						base.options.durationMs,
						base.options.maxEvents,
						signal,
					);
		signal.throwIfAborted();
		assertCurrent();
		const completed = tasks.complete(plan.id, result, "bounded-runtime-metadata/1");
		try {
			recordFirstPartyTaskEvidence(
				scope.sessionId,
				scope.workspace,
				completed,
				result,
			);
		} catch {
			return {
				planId: plan.id,
				result,
				evidenceWarning:
					"Capture completed but session snapshot persistence failed; do not replay observation to repair metadata.",
			};
		}
		return { planId: plan.id, result };
	} catch (error) {
		if (started) tasks.fail(envelope.planId, error);
		throw error;
	} finally {
		if (timer) clearInterval(timer);
		taskSignal?.removeEventListener("abort", cancel);
		slots.delete(owner_session_id);
	}
}
