import type { ChatMessage, ChatSessionStatus } from "@/lib/chat-schema";

export type TaskReportStepStatus =
	| "pending"
	| "in_progress"
	| "blocked"
	| "waiting_for_user"
	| "completed"
	| "failed"
	| "skipped"
	| "cancelled";

export type TaskReportStepKind = "work" | "repair" | "verification";

export type TaskReportStep = {
	id: string;
	label: string;
	status: TaskReportStepStatus;
	kind: TaskReportStepKind;
	parentStepId?: string;
};

export type TaskRepairState =
	| "repair_required"
	| "repairing"
	| "verifying"
	| "blocked";

export type TaskRepairReport = {
	state: TaskRepairState;
	failedStepId: string;
	failedStepLabel: string;
	attempt: number;
	maxAttempts: number;
};

export type TaskEvidenceStatus = "running" | "completed" | "failed";

export type TaskEvidence = {
	id: string;
	label: string;
	detail?: string;
	status: TaskEvidenceStatus;
	toolName: string;
	stepId?: string;
	durationMs?: number;
	createdAt: number;
};

export type SessionTaskReport = {
	mode: "plan" | "activity";
	explanation?: string;
	steps: TaskReportStep[];
	evidence: TaskEvidence[];
	repair?: TaskRepairReport;
	activeStepId?: string;
	completedCount: number;
	progressPercent: number | null;
	sourceMessageId: string;
	sourceTool: string;
	updatedAt: number;
};

const PLAN_TOOL_NAMES = new Set([
	"update_plan",
	"update_task_plan",
	"update_todo_list",
	"todo_write",
	"write_todos",
]);
const REPAIR_STEP_PATTERN =
	/\b(repair|fix|diagnos|debug|recover|retry|rerun|re-run)\b/i;
const VERIFICATION_STEP_PATTERN =
	/\b(test|verify|verification|validate|check|lint|typecheck)\b/i;

const TOOL_LABELS: Record<string, string> = {
	apply_patch: "Applying code changes",
	bash: "Running a command",
	create_file: "Creating a file",
	edit: "Editing a file",
	get_file_contents: "Reading repository files",
	read_file: "Reading a file",
	replace_in_file: "Editing a file",
	run_command: "Running a command",
	search_code: "Searching the codebase",
	str_replace: "Editing a file",
	write_file: "Writing a file",
};

function asRecord(value: unknown): Record<string, unknown> | null {
	return value && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: null;
}

function parsePayload(content: string): Record<string, unknown> | null {
	try {
		return asRecord(JSON.parse(content));
	} catch {
		return null;
	}
}

function toolName(
	message: ChatMessage,
	payload?: Record<string, unknown> | null,
) {
	return String(
		message.meta?.toolName ?? payload?.toolName ?? "",
	).toLowerCase();
}

function normalizeStatus(value: unknown): TaskReportStepStatus | null {
	if (typeof value !== "string") return null;
	const normalized = value.trim().replaceAll("-", "_").toLowerCase();
	switch (normalized) {
		case "pending":
		case "todo":
		case "not_started":
			return "pending";
		case "inprogress":
		case "in_progress":
		case "active":
		case "running":
			return "in_progress";
		case "blocked":
			return "blocked";
		case "waiting":
		case "waiting_for_user":
		case "needs_input":
			return "waiting_for_user";
		case "completed":
		case "complete":
		case "done":
			return "completed";
		case "failed":
		case "error":
			return "failed";
		case "skipped":
			return "skipped";
		case "cancelled":
		case "canceled":
			return "cancelled";
		default:
			return null;
	}
}

function stepLabel(step: Record<string, unknown>): string | null {
	for (const key of ["step", "label", "title", "content", "text"]) {
		const value = step[key];
		if (typeof value === "string" && value.trim()) return value.trim();
	}
	return null;
}

function explicitStepKind(value: unknown): TaskReportStepKind | null {
	if (typeof value !== "string") return null;
	switch (value.trim().replaceAll("-", "_").toLowerCase()) {
		case "repair":
		case "recovery":
		case "fix":
			return "repair";
		case "verification":
		case "verify":
		case "validation":
		case "test":
			return "verification";
		case "work":
		case "implementation":
			return "work";
		default:
			return null;
	}
}

function stepKind(
	step: Record<string, unknown>,
	label: string,
): TaskReportStepKind {
	const explicit =
		explicitStepKind(step.kind) ??
		explicitStepKind(step.category) ??
		explicitStepKind(step.phase);
	if (explicit) return explicit;
	if (REPAIR_STEP_PATTERN.test(label)) return "repair";
	if (VERIFICATION_STEP_PATTERN.test(label)) return "verification";
	return "work";
}

function normalizeSteps(value: unknown, messageId: string): TaskReportStep[] {
	if (!Array.isArray(value)) return [];
	let hasActiveStep = false;
	const steps = value.flatMap((rawStep, index) => {
		const step = asRecord(rawStep);
		if (!step) return [];
		const label = stepLabel(step);
		const rawStatus = normalizeStatus(step.status);
		if (!label || !rawStatus) return [];
		const status =
			rawStatus === "in_progress" && hasActiveStep ? "pending" : rawStatus;
		if (status === "in_progress") hasActiveStep = true;
		const rawId = step.id;
		const rawParentId = step.parent_step_id ?? step.parentStepId;
		return [
			{
				id:
					typeof rawId === "string" && rawId.trim()
						? rawId.trim()
						: `${messageId}:${index}`,
				label,
				status,
				kind: stepKind(step, label),
				parentStepId:
					typeof rawParentId === "string" && rawParentId.trim()
						? rawParentId.trim()
						: undefined,
			},
		];
	});

	const failureIndex = steps.findIndex(
		(step) => step.status === "failed" || step.status === "blocked",
	);
	if (failureIndex < 0) return steps;
	const repairFinished = steps
		.slice(failureIndex + 1)
		.some(
			(step) =>
				(step.kind === "repair" || step.kind === "verification") &&
				step.status === "completed",
		);
	return steps.map((step, index) => {
		if (
			index > failureIndex &&
			step.status === "in_progress" &&
			step.kind === "work" &&
			!repairFinished
		) {
			return { ...step, status: "pending" };
		}
		return step;
	});
}

function positiveInteger(value: unknown, fallback: number): number {
	return typeof value === "number" && Number.isInteger(value) && value > 0
		? value
		: fallback;
}

function normalizeRepairState(value: unknown): TaskRepairState | null {
	if (typeof value !== "string") return null;
	const normalized = value.trim().replaceAll("-", "_").toLowerCase();
	switch (normalized) {
		case "repair_required":
		case "repairing":
		case "verifying":
		case "blocked":
			return normalized;
		default:
			return null;
	}
}

function buildRepairReport(
	steps: TaskReportStep[],
	input: Record<string, unknown>,
): TaskRepairReport | undefined {
	const failure = steps.find(
		(step) => step.status === "failed" || step.status === "blocked",
	);
	if (!failure) return undefined;

	const explicitRepair = asRecord(input.repair);
	const laterSteps = steps.slice(steps.indexOf(failure) + 1);
	const repairSteps = laterSteps.filter((step) => step.kind === "repair");
	const verificationSteps = laterSteps.filter(
		(step) => step.kind === "verification",
	);
	const activeRepair = repairSteps.some(
		(step) => step.status === "in_progress",
	);
	const completedRepair = repairSteps.some(
		(step) => step.status === "completed",
	);
	const activeVerification = verificationSteps.some(
		(step) => step.status === "in_progress",
	);
	const explicitState = normalizeRepairState(explicitRepair?.state);
	const state: TaskRepairState =
		explicitState ??
		(failure.status === "blocked"
			? "blocked"
			: activeVerification || completedRepair
				? "verifying"
				: activeRepair
					? "repairing"
					: "repair_required");
	return {
		state,
		failedStepId: failure.id,
		failedStepLabel: failure.label,
		attempt: positiveInteger(
			explicitRepair?.attempt ?? input.repair_attempt,
			activeRepair ? 1 : 0,
		),
		maxAttempts: positiveInteger(
			explicitRepair?.max_attempts ??
				explicitRepair?.maxAttempts ??
				input.max_repair_attempts,
			3,
		),
	};
}

function titleCaseTool(tool: string): string {
	return tool
		.replaceAll(/[_-]+/g, " ")
		.replace(/\b\w/g, (character) => character.toUpperCase());
}

function evidenceDetail(
	input: Record<string, unknown> | null,
): string | undefined {
	for (const key of [
		"command",
		"query",
		"path",
		"file_path",
		"filePath",
		"url",
		"target",
	]) {
		const value = input?.[key];
		if (typeof value === "string" && value.trim()) {
			const compact = value.trim().replaceAll(/\s+/g, " ");
			return compact.length > 96 ? `${compact.slice(0, 93)}…` : compact;
		}
	}
	return undefined;
}

function evidenceFromMessages(
	messages: ChatMessage[],
	runStartIndex: number,
): TaskEvidence[] {
	const evidence = new Map<string, TaskEvidence>();
	for (let index = runStartIndex; index < messages.length; index++) {
		const message = messages[index];
		if (message.role !== "tool") continue;
		const payload = parsePayload(message.content);
		const name = toolName(message, payload);
		if (!name || PLAN_TOOL_NAMES.has(name)) continue;
		const input = asRecord(payload?.input);
		const key = message.meta?.toolCallId ?? message.id;
		const taskEvent = message.meta?.taskEvent;
		const isError =
			payload?.isError === true || taskEvent?.type === "tool.failed";
		const running =
			taskEvent?.type === "tool.started" ||
			message.meta?.hookEventName === "tool_call_start" ||
			(payload !== null && payload.result == null && !isError);
		const stepId =
			message.meta?.taskStepId ??
			(taskEvent && "stepId" in taskEvent ? taskEvent.stepId : undefined);
		evidence.set(key, {
			id: key,
			label: TOOL_LABELS[name] ?? titleCaseTool(name),
			detail: evidenceDetail(input),
			status: isError ? "failed" : running ? "running" : "completed",
			toolName: name,
			stepId,
			durationMs:
				taskEvent && "durationMs" in taskEvent
					? taskEvent.durationMs
					: undefined,
			createdAt: message.createdAt,
		});
	}
	return [...evidence.values()]
		.sort((left, right) => right.createdAt - left.createdAt)
		.slice(0, 5);
}

function currentRunStart(messages: ChatMessage[]): number {
	for (let index = messages.length - 1; index >= 0; index--) {
		if (messages[index]?.role === "user") return index + 1;
	}
	return 0;
}

function buildActivityFallback(
	messages: ChatMessage[],
	status: ChatSessionStatus | undefined,
	runStartIndex: number,
): SessionTaskReport | null {
	const evidence = evidenceFromMessages(messages, runStartIndex);
	if (evidence.length === 0) return null;
	const latest = evidence[0];
	const active =
		evidence.find((item) => item.status === "running") ??
		(status === "running" || status === "starting" ? latest : undefined);
	return {
		mode: "activity",
		explanation: active
			? "Following live tool activity for this turn."
			: "Execution evidence from the latest turn.",
		steps: [],
		evidence,
		completedCount: evidence.filter((item) => item.status === "completed")
			.length,
		progressPercent: null,
		sourceMessageId: latest.id,
		sourceTool: latest.toolName,
		updatedAt: latest.createdAt,
	};
}

/**
 * Projects the current user turn's newest structured planner event into stable
 * UI state. The transcript remains the durable event log. Tool evidence is
 * scoped to the same turn and plan state is never inferred from assistant prose.
 */
export function buildSessionTaskReport(
	messages: ChatMessage[],
	status?: ChatSessionStatus,
): SessionTaskReport | null {
	const runStartIndex = currentRunStart(messages);
	for (let index = messages.length - 1; index >= runStartIndex; index--) {
		const message = messages[index];
		if (message.role !== "tool") continue;
		const payload = parsePayload(message.content);
		const name = toolName(message, payload);
		const planEvent =
			message.meta?.taskEvent?.type === "plan.updated"
				? message.meta.taskEvent
				: undefined;
		if (
			!planEvent &&
			(!PLAN_TOOL_NAMES.has(name) || payload?.isError === true)
		) {
			continue;
		}
		const input = asRecord(payload?.input) ?? payload ?? {};
		const steps = normalizeSteps(
			planEvent?.steps ??
				input.plan ??
				input.steps ??
				input.todos ??
				input.items,
			message.id,
		);
		if (steps.length === 0) continue;
		const explanation =
			planEvent?.explanation ??
			(typeof input.explanation === "string" && input.explanation.trim()
				? input.explanation.trim()
				: undefined);
		const completedCount = steps.filter(
			(step) => step.status === "completed",
		).length;
		const activeStep = steps.find((step) => step.status === "in_progress");
		const repairInput = planEvent?.repair
			? {
					repair: {
						state: planEvent.repair.state,
						attempt: planEvent.repair.attempt,
						maxAttempts: planEvent.repair.maxAttempts,
					},
				}
			: input;
		return {
			mode: "plan",
			explanation,
			steps,
			evidence: evidenceFromMessages(messages, runStartIndex),
			repair: buildRepairReport(steps, repairInput),
			activeStepId: planEvent?.activeStepId ?? activeStep?.id,
			completedCount,
			progressPercent: Math.round((completedCount / steps.length) * 100),
			sourceMessageId: message.id,
			sourceTool: name || "task_protocol",
			updatedAt: message.createdAt,
		};
	}
	return buildActivityFallback(messages, status, runStartIndex);
}
