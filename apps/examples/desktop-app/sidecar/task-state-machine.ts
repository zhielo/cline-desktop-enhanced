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
	completed: new Set(["completed"]),
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
	if (
		previous &&
		previous.planId === input.planId &&
		!ALLOWED_TRANSITIONS[previous.status].has(status)
	) {
		throw new Error(`Invalid task transition: ${previous.status} -> ${status}`);
	}
	const transition: DurableTaskTransition = {
		...(previous ? { from: previous.status } : {}),
		to: status,
		atMs,
		reason: input.reason ?? "plan.updated",
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
		})),
		...(input.steps.find((step) => step.status === "in_progress")
			? {
					activeStepId: input.steps.find(
						(step) => step.status === "in_progress",
					)?.id,
				}
			: {}),
		...(input.repair ? { repair: { ...input.repair } } : {}),
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
			STEP_KINDS.has(step.kind as DurableTaskStepKind),
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
