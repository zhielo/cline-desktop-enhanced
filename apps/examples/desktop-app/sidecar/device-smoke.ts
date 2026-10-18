import { realpathSync } from "node:fs";
import { runtimeAnalysisEnabled } from "@cline/core";
import { z } from "zod";
import type { AnalysisTaskOrchestrator } from "./analysis-task-orchestrator";
import type { ApkIncidentService } from "./apk-incident-service";
import { ownedFile } from "./incident-artifacts";
import {
	bindFirstPartyTaskEvidence,
	firstPartyStore,
	recordFirstPartyTaskEvidence,
	sessionTaskSnapshots,
} from "./first-party-analysis";
import { recheckHybridObservation } from "./hybrid-analysis";
const Id = z.string().uuid();
const envelopeSchema = z
	.object({
		phase: z.enum(["prepare", "run"]).optional(),
		planId: Id.optional(),
		executionToken: z.string().min(1).max(512).optional(),
		request: z.discriminatedUnion("action", [
			z
				.object({
					action: z.literal("start"),
					target: z.string().min(1).max(4096),
					expected_sha256: z.string().regex(/^[a-f0-9]{64}$/),
					deviceSerial: z.string().trim().min(1).max(200),
					packageName: z
						.string()
						.regex(/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/),
					durationSeconds: z.number().int().min(2).max(120),
					purpose: z.string().trim().min(1).max(2000),
					hybrid: z.unknown().optional(),
				})
				.strict(),
			z.object({ action: z.enum(["status", "cancel"]), taskId: Id }).strict(),
		]),
	})
	.strict();
const slots = new Map<string, string>();
/** Host-only adapter over the existing incident engine. No model-provided authority or shell. */
export async function handleDeviceSmoke(
	raw: unknown,
	scope: { sessionId: string; workspace: string },
	tasks: AnalysisTaskOrchestrator,
	incidents: ApkIncidentService,
	assertProfile: () => void,
) {
	const envelope = envelopeSchema.parse(raw),
		input = envelope.request;
	const root = realpathSync(scope.workspace);
	if (input.action !== "start") {
		if (envelope.phase || envelope.planId || envelope.executionToken)
			throw new Error("Status/cleanup cannot contain an execution envelope");
		const plan = tasks.list(root).find((p) => p.id === input.taskId);
		if (
			!plan ||
			plan.kind !== "device" ||
			plan.operation !== "launch_apk" ||
			plan.request.owner_session_id !== scope.sessionId ||
			!plan.request.analysis_mode
		)
			throw new Error("Device smoke task unavailable in this owning session");
		const incident = incidents.byPlan(root, plan.id);
		if (
			input.action === "cancel" &&
			["awaiting-approval", "approved", "running"].includes(plan.status)
		)
			tasks.cancel(plan.id);
		const latest = tasks.list(root).find((p) => p.id === plan.id)!;
		return {
			taskId: latest.id,
			taskStatus: latest.status,
			incidentId: incident?.id,
			observationStatus: incident?.status ?? "not-started",
			stage: incident?.stage,
			failures: incident?.failures ?? [],
			coverage: incident?.coverage ?? [],
			result: incident?.result,
			error: incident?.error ?? latest.error,
			snapshotAvailable: sessionTaskSnapshots(scope.sessionId, root).some(
				(s) => s.taskId === plan.id,
			),
			cleanupConfirmed:
				(!incident && latest.status !== "running") ||
				(!!incident && ["completed", "incomplete"].includes(incident.status)),
			limitations: [
				"Status never starts or retries device work. Cancellation stops collection, not the Android app; in-flight cleanup can still be pending.",
				"No observed crash is not a passing smoke/regression assertion; only the installed base APK is attested.",
			],
		};
	}
	if (!envelope.phase) throw new Error("Host approval phase required");
	const bound = firstPartyStore().session(scope.sessionId);
	if (!bound || bound.workspace !== root || !runtimeAnalysisEnabled(bound.mode))
		throw new Error("Device smoke requires an owning Runtime/Hybrid session");
	const assertCurrent = () => {
		assertProfile();
		const current = firstPartyStore().session(scope.sessionId);
		if (!current || current.workspace !== root || current.mode !== bound.mode)
			throw new Error("Device smoke scope or mode changed");
	};
	assertCurrent();
	const hybridPorts = {
		receipt: (id: string) => firstPartyStore().get(scope.sessionId, id),
		task: (id: string) =>
			sessionTaskSnapshots(scope.sessionId, root).find((s) => s.taskId === id),
	};
	const hybrid =
		bound.mode === "hybrid"
			? await recheckHybridObservation(
					input.hybrid,
					scope,
					hybridPorts,
					input.target,
				)
			: undefined;
	if (bound.mode !== "hybrid" && input.hybrid)
		throw new Error("Hybrid evidence cannot be used outside Hybrid mode");
	const artifact = await ownedFile(root, input.target);
	if (artifact.sha256 !== input.expected_sha256)
		throw new Error("Smoke artifact changed after opening/review");
	const request = {
		operation: "launch_apk",
		target: artifact.path,
		target_sha256: artifact.sha256,
		package: input.packageName,
		device_serial: input.deviceSerial,
		duration_seconds: input.durationSeconds,
		reproduction: input.purpose,
		expected:
			"Observe exact installed base APK after launch; no absence-of-crash or regression pass claim",
		owner_session_id: scope.sessionId,
		analysis_mode: bound.mode,
		...(hybrid ? { hybrid } : {}),
	};
	if (envelope.phase === "prepare") {
		const plan = await incidents.prepare(root, request);
		try {
			assertCurrent();
		} catch (error) {
			tasks.cancel(plan.id);
			throw error;
		}
		if (plan.request.target_sha256 !== artifact.sha256) {
			tasks.cancel(plan.id);
			throw new Error("Smoke artifact changed during preparation");
		}
		try {
			bindFirstPartyTaskEvidence(scope.sessionId, root, plan);
		} catch (error) {
			tasks.cancel(plan.id);
			throw error;
		}
		return plan;
	}
	if (!envelope.planId || !envelope.executionToken)
		throw new Error(
			"Fresh independently approved one-use device plan required",
		);
	const plan = tasks.list(root).find((p) => p.id === envelope.planId);
	// start() consumes the original exact envelope. Compare ALL public intent before delegating.
	if (
		!plan ||
		plan.kind !== "device" ||
		Object.keys(request).some(
			(k) =>
				JSON.stringify(plan.request[k]) !==
				JSON.stringify(request[k as keyof typeof request]),
		) ||
		Object.keys(plan.request).some(
			(k) =>
				!(k in request) && !(k === "use_root" && plan.request[k] === false),
		)
	)
		throw new Error("Device smoke plan differs from this exact owning request");
	if (
		slots.has(scope.sessionId) ||
		slots.size >= 2 ||
		[...slots.values()].includes(input.deviceSerial)
	)
		throw new Error(
			"Device smoke concurrency budget exhausted; no overlapping observation on one device",
		);
	slots.set(scope.sessionId, input.deviceSerial);
	try {
		assertCurrent();
		const result = await incidents.start(
			root,
			envelope.planId,
			envelope.executionToken,
			{
				assertCurrent,
				completed: (completed, result) => {
					recordFirstPartyTaskEvidence(
						scope.sessionId,
						root,
						completed,
						result,
					);
				},
				finished: () => slots.delete(scope.sessionId),
			},
		);
		return {
			...result,
			taskId: plan.id,
			limitations: [
				"Asynchronous observation accepted, not a passed test. Read status with this taskId.",
				"App is not force-stopped; launch may change application data and network state. Cancel stops observation only.",
				"No install, root, arbitrary shell, UI automation, split attestation or physical-device validation claim.",
			],
		};
	} catch (error) {
		slots.delete(scope.sessionId);
		throw error;
	}
}
