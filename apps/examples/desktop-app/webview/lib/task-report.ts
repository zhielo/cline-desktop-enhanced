import type {
	TaskExecutionEvidence,
	TaskExecutionReport,
	TaskExecutionStep,
	TaskExecutionStepStatus,
} from "@cline/shared";
import type { ChatMessage, ChatSessionStatus } from "@/lib/chat-schema";
import type { SessionFileDiff } from "@/lib/session-diff";

const TERMINAL_STATUSES = new Set<ChatSessionStatus>([
	"completed",
	"cancelled",
	"failed",
	"error",
]);
const VERIFICATION_PATTERN =
	/(?:test|lint|typecheck|check|verify|build|audit)/i;

export type TaskReportSummary = {
	toolCalls: number;
	tokensIn: number;
	tokensOut: number;
	cacheReadTokens?: number;
	totalCostUsd?: number;
	additions?: number;
	deletions?: number;
};

function cleanText(value: string): string {
	return value.replace(/\s+/g, " ").trim();
}

function shortText(value: unknown, maximum = 140): string | undefined {
	if (value == null) return undefined;
	const text = cleanText(
		typeof value === "string" ? value : JSON.stringify(value),
	);
	if (!text) return undefined;
	return text.length > maximum ? `${text.slice(0, maximum - 1)}…` : text;
}

function parseToolMessage(message: ChatMessage): {
	toolName: string;
	input?: unknown;
	result?: unknown;
	isError: boolean;
	running: boolean;
} | null {
	if (message.role !== "tool") return null;
	let payload: Record<string, unknown> = {};
	try {
		const parsed = JSON.parse(message.content) as unknown;
		if (parsed && typeof parsed === "object")
			payload = parsed as Record<string, unknown>;
	} catch {
		// Imported transcripts can contain plain-text tool output.
	}
	const toolName =
		(typeof payload.toolName === "string" && payload.toolName) ||
		message.meta?.toolName ||
		"Tool";
	const isError =
		payload.isError === true ||
		typeof payload.error === "string" ||
		message.meta?.hookEventName === "agent_error";
	const running = message.meta?.hookEventName === "tool_call_start";
	return {
		toolName,
		input: payload.input,
		result: payload.result ?? payload.output ?? message.meta?.toolOutput,
		isError,
		running,
	};
}

function evidenceFromMessages(
	messages: ChatMessage[],
): TaskExecutionEvidence[] {
	return messages.flatMap((message) => {
		const tool = parseToolMessage(message);
		if (!tool) return [];
		const detail = shortText(tool.input) ?? shortText(tool.result);
		return [
			{
				evidenceId: message.meta?.toolCallId ?? message.id,
				type: VERIFICATION_PATTERN.test(tool.toolName) ? "test" : "tool",
				label: tool.toolName,
				status: tool.running ? "running" : tool.isError ? "failure" : "success",
				timestamp: new Date(message.createdAt).toISOString(),
				summary: detail,
			},
		] satisfies TaskExecutionEvidence[];
	});
}

function parseChecklist(
	messages: ChatMessage[],
): Array<{ title: string; status: TaskExecutionStepStatus }> {
	for (let index = messages.length - 1; index >= 0; index -= 1) {
		const message = messages[index];
		if (message?.role !== "assistant") continue;
		const steps = message.content.split(/\r?\n/).flatMap((line) => {
			const match = line.match(
				/^\s*(?:[-*]|\d+[.)])\s+\[([ xX~-])\]\s+(.+?)\s*$/,
			);
			if (!match) return [];
			const marker = match[1]?.toLowerCase();
			return [
				{
					title: cleanText(match[2] ?? "Step"),
					status:
						marker === "x"
							? "passed"
							: marker === "-" || marker === "~"
								? "running"
								: "pending",
				},
			];
		});
		if (steps.length > 0) return steps;
	}
	return [];
}

function statusForReport(
	status: ChatSessionStatus,
): TaskExecutionReport["status"] {
	if (status === "starting") return "starting";
	if (status === "running") return "running";
	if (status === "completed") return "completed";
	if (status === "cancelled") return "cancelled";
	if (status === "failed" || status === "error") return "failed";
	if (status === "stopping") return "stopping";
	return "idle";
}

function fallbackSteps(
	messages: ChatMessage[],
	status: ChatSessionStatus,
	evidence: TaskExecutionEvidence[],
): TaskExecutionStep[] {
	const terminal = TERMINAL_STATUSES.has(status);
	const failed = status === "failed" || status === "error";
	const hasWork = evidence.length > 0;
	const verification = evidence.filter((item) => item.type === "test");
	const verificationFailed = verification.some(
		(item) => item.status === "failure",
	);
	const finalMessage = [...messages]
		.reverse()
		.find((message) => message.role === "assistant" && message.content.trim());
	const now = new Date().toISOString();
	const makeStep = (
		position: number,
		title: string,
		stepStatus: TaskExecutionStepStatus,
		stepEvidence: TaskExecutionEvidence[] = [],
	): TaskExecutionStep => ({
		stepId: `derived-${position}`,
		position,
		title,
		status: stepStatus,
		acceptanceCriteria: [],
		dependencies: position > 1 ? [`derived-${position - 1}`] : [],
		attemptCount: stepEvidence.length > 0 ? 1 : 0,
		evidence: stepEvidence,
		...(stepStatus === "running" ? { startedAt: now } : {}),
		...(stepStatus === "passed" || stepStatus === "failed"
			? { completedAt: now }
			: {}),
	});
	return [
		makeStep(
			1,
			"Understand the task",
			messages.length > 0 ? "passed" : "pending",
		),
		makeStep(
			2,
			"Execute changes and tools",
			failed ? "failed" : terminal ? "passed" : hasWork ? "running" : "pending",
			evidence,
		),
		makeStep(
			3,
			"Validate the result",
			verificationFailed
				? "failed"
				: verification.length > 0 && terminal
					? "passed"
					: verification.length > 0
						? "running"
						: terminal
							? "skipped"
							: "pending",
			verification,
		),
		makeStep(
			4,
			"Prepare the final report",
			status === "completed" && finalMessage
				? "passed"
				: failed
					? "failed"
					: terminal
						? "skipped"
						: "pending",
		),
	];
}

function stepsFromChecklist(
	checklist: Array<{ title: string; status: TaskExecutionStepStatus }>,
	evidence: TaskExecutionEvidence[],
	status: ChatSessionStatus,
): TaskExecutionStep[] {
	const runningIndex = checklist.findIndex((step) => step.status === "running");
	const firstPendingIndex = checklist.findIndex(
		(step) => step.status === "pending",
	);
	const currentIndex = runningIndex >= 0 ? runningIndex : firstPendingIndex;
	return checklist.map((step, index) => {
		let stepStatus = step.status;
		if (
			stepStatus === "pending" &&
			index === currentIndex &&
			status === "running"
		)
			stepStatus = "running";
		if ((status === "failed" || status === "error") && index === currentIndex)
			stepStatus = "failed";
		return {
			stepId: `checklist-${index + 1}`,
			position: index + 1,
			title: step.title,
			status: stepStatus,
			acceptanceCriteria: [],
			dependencies: index > 0 ? [`checklist-${index}`] : [],
			attemptCount: stepStatus === "pending" ? 0 : 1,
			evidence: index === currentIndex ? evidence.slice(-5) : [],
		};
	});
}

export function buildTaskExecutionReport(options: {
	sessionId?: string | null;
	status: ChatSessionStatus;
	messages: ChatMessage[];
	fileDiffs: SessionFileDiff[];
	queuedInstructions?: string[];
}): TaskExecutionReport {
	const { sessionId, status, messages, fileDiffs } = options;
	const objective =
		messages
			.find((message) => message.role === "user" && message.content.trim())
			?.content.trim() || "Start a conversation to define this task.";
	const evidence = evidenceFromMessages(messages);
	const checklist = parseChecklist(messages);
	const steps =
		checklist.length > 0
			? stepsFromChecklist(checklist, evidence, status)
			: fallbackSteps(messages, status, evidence);
	const timestamps = messages
		.map((message) => message.createdAt)
		.filter(Number.isFinite);
	const completedAt =
		TERMINAL_STATUSES.has(status) && timestamps.length > 0
			? new Date(Math.max(...timestamps)).toISOString()
			: undefined;
	const finalMessage = [...messages]
		.reverse()
		.find((message) => message.role === "assistant" && message.content.trim());
	return {
		...(sessionId ? { sessionId } : {}),
		objective: cleanText(objective),
		status: statusForReport(status),
		steps,
		evidence,
		changedFiles: fileDiffs.map((file) => ({
			path: file.path,
			additions: file.additions,
			deletions: file.deletions,
		})),
		queuedInstructions: options.queuedInstructions ?? [],
		...(timestamps.length > 0
			? { startedAt: new Date(Math.min(...timestamps)).toISOString() }
			: {}),
		updatedAt: new Date().toISOString(),
		...(completedAt ? { completedAt } : {}),
		...(finalMessage ? { summary: cleanText(finalMessage.content) } : {}),
	};
}

export function reportProgress(report: TaskExecutionReport): {
	completed: number;
	total: number;
	percent: number;
} {
	const total = report.steps.length;
	const completed = report.steps.filter(
		(step) => step.status === "passed" || step.status === "skipped",
	).length;
	return {
		completed,
		total,
		percent: total === 0 ? 0 : Math.round((completed / total) * 100),
	};
}
