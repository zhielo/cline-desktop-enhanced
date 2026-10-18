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
	type InspectorOwner,
	type ManagedInspectorTarget,
	managedInspectorSessions,
} from "./managed-inspector";
import { assertCaptureFile } from "./runtime-capture-backend";

const Id = z.string().uuid();
const attachOptions = z
	.object({
		pid: z.number().int().positive().max(4294967295),
		endpoint: z.string().max(200),
		lifetimeMs: z.number().int().min(1000).max(120000),
	})
	.strict();
const breakOptions = z
	.object({
		runtimeSessionId: Id,
		locations: z
			.array(
				z
					.object({
						line: z.number().int().min(0).max(100000),
						column: z.number().int().min(0).max(4096),
					})
					.strict(),
			)
			.min(1)
			.max(8),
	})
	.strict();
const sampleOptions = z
	.object({
		runtimeSessionId: Id,
		durationMs: z.number().int().min(200).max(2000),
	})
	.strict();
const requestSchema = z
	.object({
		operation: z.enum([
			"attach_debug_session",
			"set_scoped_breakpoints",
			"capture_execution_trace",
		]),
		target: z.string().min(1).max(4096),
		expected_sha256: z.string().regex(/^[a-f0-9]{64}$/),
		options: z.union([attachOptions, breakOptions, sampleOptions]),
		hybrid: z.unknown().optional(),
	})
	.strict();

export { managedInspectorSessions } from "./managed-inspector";
/** Host-private one-use Execute review. Public model inputs never carry authority or PID birth identity. */
export async function handleManagedRuntime(
	command: string,
	raw: unknown,
	scope: InspectorOwner,
	tasks: AnalysisTaskOrchestrator,
	manager = managedInspectorSessions,
	assertHostCurrent: () => void = () => {},
) {
	if (command === "stop_runtime_session") {
		const { runtimeSessionId } = z
			.object({ runtimeSessionId: Id })
			.strict()
			.parse(raw);
		// Cleanup is owning-scope-only, and deliberately remains available after Analysis Off.
		return manager.stop(scope, runtimeSessionId);
	}
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
	if (command !== base.operation)
		throw new Error("Managed runtime command mismatch");
	const options = (
		command === "attach_debug_session"
			? attachOptions
			: command === "set_scoped_breakpoints"
				? breakOptions
				: sampleOptions
	).parse(base.options);
	const bound = firstPartyStore().session(scope.sessionId);
	if (
		!bound ||
		realpathSync.native(bound.workspace) !==
			realpathSync.native(scope.workspace) ||
		!runtimeAnalysisEnabled(bound.mode)
	)
		throw new Error(
			"Managed runtime requires an owning Runtime/Hybrid session",
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
	if (bound.mode !== "hybrid" && base.hybrid)
		throw new Error("Hybrid evidence cannot be used outside Hybrid mode");
	const assertCurrent = () => {
		assertHostCurrent();
		const current = firstPartyStore().session(scope.sessionId);
		if (
			!current ||
			current.workspace !== bound.workspace ||
			current.mode !== bound.mode
		)
			throw new Error("Managed runtime scope or mode changed");
	};
	const request: Record<string, unknown> = {
		...base,
		options,
		owner_session_id: scope.sessionId,
		...(hybrid ? { hybrid } : {}),
	};
	let target: ManagedInspectorTarget | undefined;
	if ("runtimeSessionId" in options) {
		target = manager.describe(scope, options.runtimeSessionId);
		if (
			target.target !== base.target ||
			target.expected_sha256 !== base.expected_sha256 ||
			JSON.stringify(target.hybrid) !== JSON.stringify(hybrid)
		)
			throw new Error("Managed runtime target or Hybrid basis changed");
		request.processToken = target.processToken;
	}
	if (envelope.phase === "prepare") {
		await assertCaptureFile(
			base.target,
			base.expected_sha256,
			new AbortController().signal,
		);
		if ("pid" in options) {
			const identity = await probeProcessStartTokenAsync(options.pid);
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
		throw new Error(
			"A separately approved one-use managed runtime plan is required",
		);
	const saved = tasks
		.list(scope.workspace)
		.find((p) => p.id === envelope.planId);
	if (
		!saved ||
		saved.request.owner_session_id !== scope.sessionId ||
		saved.operation !== command
	)
		throw new Error("Managed runtime plan unavailable in this owning session");
	if ("pid" in options) request.processToken = saved.request.processToken;
	let started = false;
	let attachedId: string | undefined;
	try {
		const plan = await tasks.consume({
			planId: envelope.planId,
			executionToken: envelope.executionToken,
			workspaceRoot: scope.workspace,
			kind: "debugger",
			request,
		});
		started = true;
		assertCurrent();
		if (hybrid)
			await recheckHybridObservation(hybrid, scope, hybridPorts, base.target);
		const signal = tasks.signal(plan.id);
		const result =
			"pid" in options
				? await manager.attach(
						scope,
						{
							target: base.target,
							expected_sha256: base.expected_sha256,
							processToken: String(request.processToken),
							...options,
							...(hybrid ? { hybrid } : {}),
						},
						assertCurrent,
						signal,
					)
				: "locations" in options
					? await manager.breakpoints(
							scope,
							options.runtimeSessionId,
							options.locations,
							signal,
						)
					: await manager.sample(
							scope,
							options.runtimeSessionId,
							options.durationMs,
							signal,
						);
		if (command === "attach_debug_session")
			attachedId = (result as { runtimeSessionId?: string }).runtimeSessionId;
		signal.throwIfAborted();
		assertCurrent();
		const completed = tasks.complete(plan.id, result, "managed-node-inspector/1");
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
					"Operation completed but evidence persistence failed; do not replay debug control to repair metadata.",
			};
		}
		return { planId: plan.id, result };
	} catch (error) {
		if (attachedId)
			await manager.stop(scope, attachedId, "approval-task-failed");
		if (started) tasks.fail(envelope.planId, error);
		throw error;
	}
}
