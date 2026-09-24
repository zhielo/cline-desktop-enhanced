import type { ChatMessage } from "@/lib/chat-schema";

export type TaskReportStepStatus =
	| "pending"
	| "in_progress"
	| "blocked"
	| "waiting_for_user"
	| "completed"
	| "failed"
	| "skipped"
	| "cancelled";

export type TaskReportStep = {
	id: string;
	label: string;
	status: TaskReportStepStatus;
};

export type SessionTaskReport = {
	explanation?: string;
	steps: TaskReportStep[];
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

function normalizeSteps(value: unknown, messageId: string): TaskReportStep[] {
	if (!Array.isArray(value)) return [];
	let hasActiveStep = false;
	return value.flatMap((rawStep, index) => {
		const step = asRecord(rawStep);
		if (!step) return [];
		const label = stepLabel(step);
		const rawStatus = normalizeStatus(step.status);
		if (!label || !rawStatus) return [];
		// Codex plans permit one active step. Project malformed provider output
		// safely instead of presenting several simultaneous current steps.
		const status =
			rawStatus === "in_progress" && hasActiveStep ? "pending" : rawStatus;
		if (status === "in_progress") hasActiveStep = true;
		const rawId = step.id;
		return [
			{
				id:
					typeof rawId === "string" && rawId.trim()
						? rawId.trim()
						: `${messageId}:${index}`,
				label,
				status,
			},
		];
	});
}

/**
 * Projects the newest structured planner call into stable session UI state.
 * The transcript remains the durable event log, so hydration and reconnects
 * rebuild the same report without a second persistence surface.
 */
export function buildSessionTaskReport(
	messages: ChatMessage[],
): SessionTaskReport | null {
	for (let index = messages.length - 1; index >= 0; index--) {
		const message = messages[index];
		if (message.role !== "tool") continue;
		const payload = parsePayload(message.content);
		const toolName = String(
			message.meta?.toolName ?? payload?.toolName ?? "",
		).toLowerCase();
		if (!PLAN_TOOL_NAMES.has(toolName) || payload?.isError === true) continue;
		const input = asRecord(payload?.input) ?? payload;
		const steps = normalizeSteps(
			input?.plan ?? input?.steps ?? input?.todos ?? input?.items,
			message.id,
		);
		if (steps.length === 0) continue;
		const explanation =
			typeof input?.explanation === "string" && input.explanation.trim()
				? input.explanation.trim()
				: undefined;
		return {
			explanation,
			steps,
			sourceMessageId: message.id,
			sourceTool: toolName,
			updatedAt: message.createdAt,
		};
	}
	return null;
}
