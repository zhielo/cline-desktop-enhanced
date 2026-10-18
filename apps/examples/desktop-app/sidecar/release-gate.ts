import { realpathSync } from "node:fs";
import { z } from "zod";
import type {
	AnalysisTaskOrchestrator,
	AnalysisTaskPlan,
} from "./analysis-task-orchestrator";
import { InvestigationSchemas } from "@cline/core";
const ReleaseGateRequestSchema = InvestigationSchemas.check_release_gate;
import { RELEASE_GATE_POLICY as policy } from "./release-gate-policy";
import { collectReleaseGate } from "./release-gate-collector";
const envelopeSchema = z
	.object({
		phase: z.enum(["prepare", "run"]).optional(),
		planId: z.string().uuid().optional(),
		executionToken: z.string().min(1).max(512).optional(),
		request: z.unknown(),
	})
	.strict();
export type ReleaseGateHostPorts = {
	tasks: AnalysisTaskOrchestrator;
	session: (id: string) => { workspace: string; mode: string } | undefined;
	assertProfile: () => void;
	bind: (sessionId: string, workspace: string, plan: AnalysisTaskPlan) => void;
	record: (
		sessionId: string,
		workspace: string,
		plan: AnalysisTaskPlan,
		result: unknown,
	) => unknown;
	snapshots: (
		sessionId: string,
		workspace: string,
	) => Array<{
		taskId: string;
		operation: string;
		result: unknown;
		snapshotHash: string;
	}>;
	collect?: typeof collectReleaseGate;
};
const active = new Set<string>();
/** Trusted local host only. Public model schema cannot populate this envelope. */
export async function handleReleaseGate(
	raw: unknown,
	scope: { sessionId: string; workspace: string },
	ports: ReleaseGateHostPorts,
) {
	const envelope = envelopeSchema.parse(raw),
		input = ReleaseGateRequestSchema.parse(envelope.request),
		root = realpathSync(scope.workspace);
	const task = (id: string) => {
		const plan = ports.tasks.list(root).find((p) => p.id === id);
		if (
			!plan ||
			plan.kind !== "static" ||
			plan.operation !== "check_release_gate" ||
			plan.request.owner_session_id !== scope.sessionId
		)
			throw new Error(
				"Release task unavailable in this owning session/workspace",
			);
		return plan;
	};
	if (input.action !== "check") {
		if (envelope.phase || envelope.planId || envelope.executionToken)
			throw new Error("Saved read/cleanup cannot include an approval envelope");
		if (input.action === "read") {
			const snapshot = ports
				.snapshots(scope.sessionId, root)
				.find(
					(s) =>
						s.taskId === input.taskId && s.operation === "check_release_gate",
				);
			if (!snapshot)
				throw new Error(
					"Saved release receipt unavailable in this owning session/workspace",
				);
			return {
				taskId: input.taskId,
				receipt: snapshot.result,
				snapshotHash: snapshot.snapshotHash,
				saved: true,
				limitations: [
					"Saved historical result only; no network request, CI retry or assertion that the current head is unchanged.",
				],
			};
		}
		const plan = task(input.taskId);
		if (["awaiting-approval", "approved", "running"].includes(plan.status))
			ports.tasks.cancel(plan.id);
		return {
			taskId: plan.id,
			status: task(plan.id).status,
			limitations: [
				"Cancellation aborts bounded read-only evidence collection; it does not cancel GitHub workflows.",
			],
		};
	}
	if (!envelope.phase)
		throw new Error("Independent Inspect approval phase required");
	const initial = ports.session(scope.sessionId);
	if (!initial || initial.workspace !== root || initial.mode === "off")
		throw new Error(
			"Release verification requires an owning enabled Analysis session",
		);
	const assertCurrent = () => {
		ports.assertProfile();
		const current = ports.session(scope.sessionId);
		if (
			!current ||
			current.workspace !== root ||
			current.mode !== initial.mode ||
			current.mode === "off"
		)
			throw new Error("Release verification scope, mode or profile changed");
	};
	assertCurrent();
	const request = {
		operation: "check_release_gate",
		owner_session_id: scope.sessionId,
		analysis_mode: initial.mode,
		pullNumber: input.pullNumber,
		expectedHead: input.expectedHead,
		policy: policy.version,
	};
	if (envelope.phase === "prepare") {
		if (envelope.planId || envelope.executionToken)
			throw new Error("Prepare cannot carry a prior approval");
		const plan = await ports.tasks.prepare({
			workspaceRoot: root,
			kind: "static",
			request,
			timeoutMs: 95_000,
			maxOutputBytes: 128 * 1024,
		});
		try {
			assertCurrent();
			ports.bind(scope.sessionId, root, plan);
			return plan;
		} catch (error) {
			ports.tasks.cancel(plan.id);
			throw error;
		}
	}
	if (!envelope.planId || !envelope.executionToken)
		throw new Error("Fresh independent Inspect approval required");
	task(envelope.planId);
	if (active.has(scope.sessionId) || active.size >= 2)
		throw new Error("Release verification concurrency budget occupied");
	active.add(scope.sessionId);
	let running: AnalysisTaskPlan | undefined,
		watcher: ReturnType<typeof setInterval> | undefined;
	try {
		running = await ports.tasks.consume({
			planId: envelope.planId,
			executionToken: envelope.executionToken,
			workspaceRoot: root,
			kind: "static",
			request,
		});
		const plan = running;
		const signal = ports.tasks.signal(plan.id);
		assertCurrent();
		watcher = setInterval(() => {
			try {
				assertCurrent();
			} catch {
				try {
					ports.tasks.cancel(plan.id);
				} catch {
					/* already terminal */
				}
			}
		}, 100);
		let result: unknown;
		try {
			result = await (ports.collect ?? collectReleaseGate)(
				input.pullNumber,
				input.expectedHead,
				{ signal, assertCurrent },
			);
		} catch (error) {
			signal.throwIfAborted();
			assertCurrent();
			result = {
				status: "blocked",
				policy: policy.version,
				pullNumber: input.pullNumber,
				expectedHead: input.expectedHead,
				checkedAt: new Date().toISOString(),
				reason: (error instanceof Error
					? error.message
					: "Release evidence unavailable"
				)
					.replace(/https?:\/\/[^\s]+/g, "[transport URL omitted]")
					.slice(0, 500),
				limitations: [
					"No passing release attestation. Missing, unavailable or inconsistent evidence never becomes green; no automatic retry or credential fallback.",
				],
			};
		}
		signal.throwIfAborted();
		assertCurrent();
		const completed = ports.tasks.complete(
			plan.id,
			result,
			"public-github-exact-head-release-gate/v1",
		);
		let receipt: unknown;
		try {
			receipt = ports.record(scope.sessionId, root, completed, result);
		} catch {
			/* Do not replay completed network work if durable snapshot retention fails. */
		}
		return { taskId: plan.id, result, snapshotAvailable: !!receipt };
	} catch (error) {
		if (running) ports.tasks.fail(running.id, error);
		throw error;
	} finally {
		if (watcher) clearInterval(watcher);
		active.delete(scope.sessionId);
	}
}
