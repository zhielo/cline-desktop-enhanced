import {
	existsSync,
	mkdirSync,
	readFileSync,
	renameSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { dirname } from "node:path";
import { sharedSessionTaskStatePath } from "./paths";

export type DurableTaskStatus =
	| "planned"
	| "running"
	| "verifying"
	| "repairing"
	| "completed"
	| "waiting_for_user"
	| "blocked"
	| "failed"
	| "cancelled"
	| "skipped";

export type DurableTaskStepStatus =
	| "pending"
	| "in_progress"
	| "blocked"
	| "waiting_for_user"
	| "completed"
	| "failed"
	| "skipped"
	| "cancelled";

export type DurableTaskStepKind = "work" | "repair" | "verification";

export type DurableTaskValidation = {
	command: string;
	status: "pending" | "running" | "passed" | "failed" | "skipped";
	startedAtMs?: number;
	completedAtMs?: number;
	exitCode?: number;
	error?: string;
};

export type DurableTaskStep = {
	id: string;
	label: string;
	status: DurableTaskStepStatus;
	kind: DurableTaskStepKind;
	parentStepId?: string;
	acceptanceCriteria?: string[];
	validationCommands?: string[];
	ownerAgentId?: string;
	worktree?: string;
	artifacts?: string[];
	startedAtMs?: number;
	completedAtMs?: number;
	repairAttempt?: number;
	maxRepairAttempts?: number;
	skipReason?: string;
	checkpointRunCount?: number;
	validation?: DurableTaskValidation[];
};

export type DurableTaskTransition = {
	from?: DurableTaskStatus;
	to: DurableTaskStatus;
	atMs: number;
	reason: string;
};

export type DurableTaskRepair = {
	state?: "repair_required" | "repairing" | "verifying" | "blocked";
	attempt?: number;
	maxAttempts?: number;
};

export type DurableTaskState = {
	planId: string;
	status: DurableTaskStatus;
	steps: DurableTaskStep[];
	activeStepId?: string;
	repair?: DurableTaskRepair;
	updatedAtMs: number;
	transitions: DurableTaskTransition[];
	rollback?: {
		checkpointRunCount: number;
		atMs: number;
		reason: string;
	};
};

const TERMINAL_STEP_STATUSES = new Set<DurableTaskStepStatus>([
	"completed",
	"skipped",
	"cancelled",
]);
const MAX_TASK_TRANSITIONS = 500;

const TASK_STATUSES = new Set<DurableTaskStatus>([
	"planned",
	"running",
	"verifying",
	"repairing",
	"completed",
	"waiting_for_user",
	"blocked",
	"failed",
	"cancelled",
	"skipped",
]);

const STEP_STATUSES = new Set<DurableTaskStepStatus>([
	"pending",
	"in_progress",
	"blocked",
	"waiting_for_user",
	"completed",
	"failed",
	"skipped",
	"cancelled",
]);

const STEP_KINDS = new Set<DurableTaskStepKind>([
	"work",
	"repair",
	"verification",
]);
const REPAIR_STATES = new Set<NonNullable<DurableTaskRepair["state"]>>([
	"repair_required",
	"repairing",
	"verifying",
	"blocked",
]);

const ALLOWED_TRANSITIONS: Record<
	DurableTaskStatus,
	ReadonlySet<DurableTaskStatus>
> = {
	planned: new Set([
		"planned",
		"running",
		"verifying",
		"repairing",
		"completed",
		"waiting_for_user",
		"blocked",
		"failed",
		"cancelled",
	]),
	running: new Set([
		"running",
		"verifying",
		"repairing",
		"completed",
		"waiting_for_user",
		"blocked",
		"failed",
		"cancelled",
	]),
	verifying: new Set([
		"verifying",
		"repairing",
		"completed",
		"waiting_for_user",
		"blocked",
		"failed",
		"cancelled",
	]),
	repairing: new Set([
		"repairing",
		"running",
		"verifying",
		"waiting_for_user",
		"blocked",
		"failed",
		"cancelled",
	]),
	waiting_for_user: new Set([
		"waiting_for_user",
		"running",
		"repairing",
		"verifying",
		"blocked",
		"cancelled",
	]),
	blocked: new Set(["blocked", "running", "repairing", "cancelled"]),
	failed: new Set([
		"failed",
		"running",
		"verifying",
		"repairing",
		"blocked",
		"cancelled",
	]),
	// A completed projection may still have declared validation commands that
	// the host has not executed yet. Only that host-driven verification path
	// reopens completion; ordinary plan updates remain terminal because they do
	// not add a pending validation record.
	completed: new Set(["completed", "verifying"]),
	cancelled: new Set(["cancelled"]),
	skipped: new Set(["skipped"]),
};

function deriveTaskStatus(
	steps: DurableTaskStep[],
	repair?: DurableTaskRepair,
): DurableTaskStatus {
	if (steps.some((step) => step.status === "waiting_for_user")) {
		return "waiting_for_user";
	}
	if (
		repair?.state === "blocked" ||
		steps.some((step) => step.status === "blocked")
	) {
		return "blocked";
	}
	if (repair?.state === "repairing") return "repairing";
	if (repair?.state === "verifying") return "verifying";
	if (
		steps.some((step) =>
			step.validation?.some((validation) => validation.status === "failed"),
		)
	) {
		return "failed";
	}
	if (
		steps.some((step) =>
			step.validation?.some(
				(validation) =>
					validation.status === "pending" || validation.status === "running",
			),
		)
	) {
		return "verifying";
	}
	const active = steps.find((step) => step.status === "in_progress");
	if (active?.kind === "repair") return "repairing";
	if (active?.kind === "verification") return "verifying";
	if (active) return "running";
	if (steps.some((step) => step.status === "failed")) return "failed";
	if (
		steps.length > 0 &&
		steps.every((step) => TERMINAL_STEP_STATUSES.has(step.status))
	) {
		if (steps.some((step) => step.status === "cancelled")) return "cancelled";
		if (steps.every((step) => step.status === "skipped")) return "skipped";
		return "completed";
	}
	return "planned";
}

function validateSteps(steps: DurableTaskStep[]): string | undefined {
	if (steps.length === 0) return "A task plan must contain at least one step";
	const ids = new Set<string>();
	let activeCount = 0;
	let failedIndex = -1;
	for (const [index, step] of steps.entries()) {
		if (ids.has(step.id)) return `Duplicate task step id: ${step.id}`;
		ids.add(step.id);
		if (step.status === "skipped" && !step.skipReason?.trim()) {
			return `Skipped task step requires a reason: ${step.id}`;
		}
		if (
			step.checkpointRunCount !== undefined &&
			(!Number.isInteger(step.checkpointRunCount) ||
				step.checkpointRunCount < 1)
		) {
			return `Invalid checkpoint run count for task step: ${step.id}`;
		}
		if (
			step.validation &&
			(step.validation.length === 0 ||
				step.validation.some(
					(item) =>
						!item.command.trim() ||
						!["pending", "running", "passed", "failed", "skipped"].includes(
							item.status,
						),
				))
		) {
			return `Invalid validation state for task step: ${step.id}`;
		}
		if (step.status === "in_progress") activeCount += 1;
		if (
			failedIndex < 0 &&
			(step.status === "failed" || step.status === "blocked")
		) {
			failedIndex = index;
		}
	}
	if (activeCount > 1) return "Only one task step may be in progress";
	if (failedIndex >= 0) {
		const repairCompleted = steps
			.slice(failedIndex + 1)
			.some(
				(step) =>
					(step.kind === "repair" || step.kind === "verification") &&
					step.status === "completed",
			);
		const advancedWork = steps
			.slice(failedIndex + 1)
			.some((step) => step.kind === "work" && step.status === "in_progress");
		if (advancedWork && !repairCompleted) {
			return "Work cannot advance past a failed step before repair or verification completes";
		}
	}
	return undefined;
}

export function advanceDurableTaskState(input: {
	planId: string;
	steps: DurableTaskStep[];
	repair?: DurableTaskRepair;
	previous?: DurableTaskState;
	atMs?: number;
	reason?: string;
}): DurableTaskState {
	const validationError = validateSteps(input.steps);
	if (validationError) throw new Error(validationError);
	const atMs = input.atMs ?? Date.now();
	const status = deriveTaskStatus(input.steps, input.repair);
	const previous = input.previous;
	const reason = input.reason ?? "plan.updated";
	if (
		previous &&
		previous.planId === input.planId &&
		(!ALLOWED_TRANSITIONS[previous.status].has(status) ||
			(previous.status === "completed" &&
				status === "verifying" &&
				!reason.startsWith("validation.started:")))
	) {
		throw new Error(`Invalid task transition: ${previous.status} -> ${status}`);
	}
	const transition: DurableTaskTransition = {
		...(previous ? { from: previous.status } : {}),
		to: status,
		atMs,
		reason,
	};
	return {
		planId: input.planId,
		status,
		steps: input.steps.map((step) => ({
			...step,
			acceptanceCriteria: step.acceptanceCriteria
				? [...step.acceptanceCriteria]
				: undefined,
			validationCommands: step.validationCommands
				? [...step.validationCommands]
				: undefined,
			artifacts: step.artifacts ? [...step.artifacts] : undefined,
			validation: step.validation
				? step.validation.map((validation) => ({ ...validation }))
				: undefined,
		})),
		...(input.steps.find((step) => step.status === "in_progress")
			? {
					activeStepId: input.steps.find(
						(step) => step.status === "in_progress",
					)?.id,
				}
			: {}),
		...(input.repair ? { repair: { ...input.repair } } : {}),
		...(previous?.rollback ? { rollback: { ...previous.rollback } } : {}),
		updatedAtMs: atMs,
		transitions:
			previous?.planId === input.planId
				? [
						...previous.transitions.slice(-(MAX_TASK_TRANSITIONS - 1)),
						transition,
					]
				: [transition],
	};
}

export function beginDurableTaskValidation(input: {
	state: DurableTaskState;
	stepId: string;
	atMs?: number;
}): DurableTaskState {
	const step = input.state.steps.find((item) => item.id === input.stepId);
	if (!step) throw new Error(`Unknown task step: ${input.stepId}`);
	if (!step.validationCommands?.length) {
		throw new Error(`Task step has no validation commands: ${input.stepId}`);
	}
	const atMs = input.atMs ?? Date.now();
	return advanceDurableTaskState({
		planId: input.state.planId,
		previous: input.state,
		atMs,
		reason: `validation.started:${input.stepId}`,
		repair: { ...input.state.repair, state: "verifying" },
		steps: input.state.steps.map((item) =>
			item.id === input.stepId
				? {
						...item,
						status: "in_progress",
						completedAtMs: undefined,
						validation: item.validationCommands?.map((command) => ({
							command,
							status: "pending" as const,
						})),
					}
				: item,
		),
	});
}

export function recordDurableTaskValidation(input: {
	state: DurableTaskState;
	stepId: string;
	command: string;
	status: DurableTaskValidation["status"];
	atMs?: number;
	exitCode?: number;
	error?: string;
}): DurableTaskState {
	const atMs = input.atMs ?? Date.now();
	const step = input.state.steps.find((item) => item.id === input.stepId);
	if (!step?.validation) {
		throw new Error(`Task validation has not started: ${input.stepId}`);
	}
	const validations = step.validation.map((item) =>
		item.command === input.command
			? {
					...item,
					status: input.status,
					...(input.status === "running" && item.startedAtMs === undefined
						? { startedAtMs: atMs }
						: {}),
					...(input.status === "passed" ||
					input.status === "failed" ||
					input.status === "skipped"
						? { completedAtMs: atMs }
						: {}),
					...(input.exitCode !== undefined ? { exitCode: input.exitCode } : {}),
					...(input.error ? { error: input.error } : {}),
				}
			: item,
	);
	const failed = validations.some((item) => item.status === "failed");
	const finished = validations.every((item) =>
		["passed", "failed", "skipped"].includes(item.status),
	);
	const nextSteps = input.state.steps.map((item) =>
		item.id === input.stepId
			? {
					...item,
					status: failed
						? ("failed" as const)
						: finished
							? ("completed" as const)
							: ("in_progress" as const),
					validation: validations,
					...(finished ? { completedAtMs: atMs } : {}),
				}
			: item,
	);
	return advanceDurableTaskState({
		planId: input.state.planId,
		previous: input.state,
		atMs,
		reason: `validation.${input.status}:${input.stepId}`,
		repair: failed
			? { ...input.state.repair, state: "repair_required" }
			: finished
				? undefined
				: { ...input.state.repair, state: "verifying" },
		steps: nextSteps,
	});
}

export function rollbackDurableTaskState(input: {
	state: DurableTaskState;
	checkpointRunCount: number;
	atMs?: number;
	reason?: string;
}): DurableTaskState {
	if (
		!Number.isInteger(input.checkpointRunCount) ||
		input.checkpointRunCount < 1
	) {
		throw new Error("checkpointRunCount must be a positive integer");
	}
	const atMs = input.atMs ?? Date.now();
	const reason =
		input.reason ?? `checkpoint.rollback:${input.checkpointRunCount}`;
	const steps = input.state.steps.map((step) =>
		step.checkpointRunCount !== undefined &&
		step.checkpointRunCount >= input.checkpointRunCount
			? {
					...step,
					status: "pending" as const,
					startedAtMs: undefined,
					completedAtMs: undefined,
					repairAttempt: undefined,
					skipReason: undefined,
					artifacts: undefined,
					validation: undefined,
				}
			: step,
	);
	const status = deriveTaskStatus(steps);
	return {
		...input.state,
		status,
		steps,
		activeStepId: undefined,
		repair: undefined,
		rollback: {
			checkpointRunCount: input.checkpointRunCount,
			atMs,
			reason,
		},
		updatedAtMs: atMs,
		transitions: [
			...input.state.transitions.slice(-(MAX_TASK_TRANSITIONS - 1)),
			{ from: input.state.status, to: status, atMs, reason },
		],
	};
}

function isDurableTaskState(value: unknown): value is DurableTaskState {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const state = value as Partial<DurableTaskState>;
	if (
		typeof state.planId !== "string" ||
		!state.planId ||
		typeof state.status !== "string" ||
		!TASK_STATUSES.has(state.status as DurableTaskStatus) ||
		!Array.isArray(state.steps) ||
		!Array.isArray(state.transitions) ||
		typeof state.updatedAtMs !== "number" ||
		!Number.isInteger(state.updatedAtMs) ||
		state.updatedAtMs < 0
	) {
		return false;
	}
	const stepsAreValid = state.steps.every(
		(step) =>
			step &&
			typeof step.id === "string" &&
			typeof step.label === "string" &&
			typeof step.status === "string" &&
			STEP_STATUSES.has(step.status as DurableTaskStepStatus) &&
			typeof step.kind === "string" &&
			STEP_KINDS.has(step.kind as DurableTaskStepKind) &&
			(step.skipReason === undefined || typeof step.skipReason === "string") &&
			(step.checkpointRunCount === undefined ||
				(typeof step.checkpointRunCount === "number" &&
					Number.isInteger(step.checkpointRunCount) &&
					step.checkpointRunCount >= 1)) &&
			(step.validation === undefined ||
				(Array.isArray(step.validation) &&
					step.validation.every(
						(item) =>
							item &&
							typeof item.command === "string" &&
							typeof item.status === "string",
					))),
	);
	if (!stepsAreValid) return false;
	const steps = state.steps as DurableTaskStep[];
	if (validateSteps(steps)) return false;
	const activeStepId = steps.find((step) => step.status === "in_progress")?.id;
	if (state.activeStepId !== activeStepId) return false;
	const repair = state.repair as DurableTaskRepair | undefined;
	if (
		repair &&
		(typeof repair !== "object" ||
			(repair.state !== undefined && !REPAIR_STATES.has(repair.state)) ||
			(repair.attempt !== undefined &&
				(!Number.isInteger(repair.attempt) || repair.attempt < 0)) ||
			(repair.maxAttempts !== undefined &&
				(!Number.isInteger(repair.maxAttempts) || repair.maxAttempts < 1)))
	) {
		return false;
	}
	if (state.status !== deriveTaskStatus(steps, repair)) return false;
	if (
		state.rollback !== undefined &&
		(typeof state.rollback !== "object" ||
			!Number.isInteger(state.rollback.checkpointRunCount) ||
			state.rollback.checkpointRunCount < 1 ||
			!Number.isInteger(state.rollback.atMs) ||
			state.rollback.atMs < 0 ||
			typeof state.rollback.reason !== "string" ||
			!state.rollback.reason)
	) {
		return false;
	}
	const transitionsAreValid =
		state.transitions.length > 0 &&
		state.transitions.length <= MAX_TASK_TRANSITIONS &&
		state.transitions.every((transition) => {
			if (!transition || typeof transition !== "object") return false;
			const item = transition as Partial<DurableTaskTransition>;
			return (
				(item.from === undefined ||
					(typeof item.from === "string" &&
						TASK_STATUSES.has(item.from as DurableTaskStatus))) &&
				typeof item.to === "string" &&
				TASK_STATUSES.has(item.to as DurableTaskStatus) &&
				typeof item.atMs === "number" &&
				Number.isInteger(item.atMs) &&
				item.atMs >= 0 &&
				typeof item.reason === "string" &&
				item.reason.length > 0
			);
		});
	return (
		transitionsAreValid &&
		(state.transitions.at(-1) as DurableTaskTransition | undefined)?.to ===
			state.status
	);
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
	return value && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}

function projectedTaskEvent(
	value: unknown,
): Record<string, unknown> | undefined {
	const record = asRecord(value);
	if (!record) return undefined;
	const direct = asRecord(record.taskEvent);
	if (direct?.type === "plan.updated") return direct;
	const meta = asRecord(record.meta);
	const fromMeta = asRecord(meta?.taskEvent);
	if (fromMeta?.type === "plan.updated") return fromMeta;
	const metadata = asRecord(record.metadata);
	const fromMetadata = asRecord(metadata?.taskEvent);
	if (fromMetadata?.type === "plan.updated") return fromMetadata;
	if (typeof record.content === "string") {
		try {
			const parsed = asRecord(JSON.parse(record.content));
			return projectedTaskEvent(parsed);
		} catch {
			return undefined;
		}
	}
	return undefined;
}

function migrateProjectedTaskState(
	messages: unknown[],
): DurableTaskState | undefined {
	for (let index = messages.length - 1; index >= 0; index -= 1) {
		const event = projectedTaskEvent(messages[index]);
		if (!event) continue;
		const planId =
			typeof event.planId === "string" && event.planId.trim()
				? event.planId.trim()
				: undefined;
		if (!planId || !Array.isArray(event.steps)) continue;
		const steps = event.steps.flatMap((rawStep) => {
			const step = asRecord(rawStep);
			if (
				!step ||
				typeof step.id !== "string" ||
				typeof step.label !== "string" ||
				typeof step.status !== "string" ||
				!STEP_STATUSES.has(step.status as DurableTaskStepStatus)
			) {
				return [];
			}
			const kind =
				typeof step.kind === "string" &&
				STEP_KINDS.has(step.kind as DurableTaskStepKind)
					? (step.kind as DurableTaskStepKind)
					: "work";
			return [
				{
					...step,
					id: step.id,
					label: step.label,
					status: step.status as DurableTaskStepStatus,
					kind,
				} as DurableTaskStep,
			];
		});
		try {
			return advanceDurableTaskState({
				planId,
				steps,
				atMs:
					typeof event.updatedAtMs === "number" &&
					Number.isInteger(event.updatedAtMs) &&
					event.updatedAtMs >= 0
						? event.updatedAtMs
						: Date.now(),
				reason: "migration.projected-report",
			});
		} catch {}
	}
	return undefined;
}

export function readDurableTaskState(
	sessionId: string,
): DurableTaskState | undefined {
	const path = sharedSessionTaskStatePath(sessionId);
	if (!existsSync(path)) return undefined;
	try {
		const parsed = JSON.parse(readFileSync(path, "utf8")) as {
			version?: unknown;
			state?: unknown;
		};
		return parsed.version === 1 && isDurableTaskState(parsed.state)
			? parsed.state
			: undefined;
	} catch {
		return undefined;
	}
}

export function readOrMigrateDurableTaskState(
	sessionId: string,
	messages: unknown[] = [],
): DurableTaskState | undefined {
	const current = readDurableTaskState(sessionId);
	if (current) return current;
	const migrated = migrateProjectedTaskState(messages);
	if (!migrated) return undefined;
	persistDurableTaskState(sessionId, migrated);
	return migrated;
}

export function persistDurableTaskState(
	sessionId: string,
	state: DurableTaskState,
): void {
	const path = sharedSessionTaskStatePath(sessionId);
	const temporaryPath = `${path}.tmp-${process.pid}-${Date.now()}`;
	mkdirSync(dirname(path), { recursive: true });
	try {
		writeFileSync(
			temporaryPath,
			`${JSON.stringify({ version: 1, state }, null, 2)}\n`,
			{ encoding: "utf8", mode: 0o600 },
		);
		try {
			renameSync(temporaryPath, path);
		} catch {
			// Windows can refuse an otherwise valid replacement rename. Keep the
			// fully-written temporary file until the old artifact is removed.
			rmSync(path, { force: true });
			renameSync(temporaryPath, path);
		}
	} catch (error) {
		rmSync(temporaryPath, { force: true });
		throw error;
	}
}
