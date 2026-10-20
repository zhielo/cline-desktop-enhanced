import { z } from "zod";

/** A host execution receipt, not model prose, approval or semantic correctness. */
export const TaskObservationSchema = z
	.object({
		version: z.literal("task-observation/v1"),
		id: z.string().min(1).max(400),
		sessionId: z.string().min(1).max(200),
		toolCallId: z.string().min(1).max(300),
		toolName: z.string().min(1).max(160),
		stepId: z.string().min(1).max(300).optional(),
		planId: z.string().min(1).max(300).optional(),
		source: z.enum(["host-tool", "host-validation"]),
		execution: z.enum([
			"running",
			"finished",
			"failed",
			"cancelled",
			"timed_out",
			"blocked",
		]),
		outcome: z.enum([
			"unverified",
			"partial",
			"failed",
			"inconclusive",
			"blocked",
			"bounded-checks-passed",
		]),
		recordedAtMs: z.number().int().nonnegative(),
		durationMs: z.number().finite().nonnegative().optional(),
		validationScope: z.string().max(8192).optional(),
		checkCount: z.number().int().min(0).max(1000).optional(),
	})
	.strict();
export type TaskObservation = z.infer<typeof TaskObservationSchema>;

export function reportRecord(value: unknown): Record<string, unknown> | null {
	return value && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: null;
}

/** Tool output can downgrade a receipt, never confer verification authority. */
export function reportedOutcome(value: unknown): TaskObservation["outcome"] {
	if (typeof value === "string") {
		if (value.length > 65_536) return "unverified";
		try {
			value = JSON.parse(value);
		} catch {
			return "unverified";
		}
	}
	let record = reportRecord(value);
	let outcome: TaskObservation["outcome"] = "unverified";
	for (let depth = 0; record && depth < 4; depth++) {
		const status =
			typeof record.status === "string" ? record.status.toLowerCase() : "";
		if (
			record.timedOut === true ||
			record.cancelled === true ||
			record.ok === false ||
			record.isError === true ||
			["failed", "error", "cancelled", "timed_out", "timeout"].includes(status)
		)
			return "failed";
		if (status === "blocked") outcome = "blocked";
		else if (outcome !== "blocked" && status === "partial") outcome = "partial";
		else if (outcome === "unverified" && status === "inconclusive")
			outcome = "inconclusive";
		record = reportRecord(record.result) ?? reportRecord(record.output);
	}
	return outcome;
}

export function hostToolObservation(input: {
	sessionId: string;
	toolCallId: string;
	toolName: string;
	stepId?: string;
	planId?: string;
	running?: boolean;
	failed?: boolean;
	output?: unknown;
	durationMs?: number;
	now?: number;
}): TaskObservation | undefined {
	const outcome = input.failed ? "failed" : reportedOutcome(input.output);
	return TaskObservationSchema.safeParse({
		version: "task-observation/v1",
		id: `${input.toolCallId}:${input.running ? "started" : "finished"}`,
		sessionId: input.sessionId,
		toolCallId: input.toolCallId,
		toolName: input.toolName,
		...(input.stepId ? { stepId: input.stepId } : {}),
		...(input.planId ? { planId: input.planId } : {}),
		source: "host-tool",
		execution: input.running
			? "running"
			: input.failed || outcome === "failed"
				? "failed"
				: outcome === "blocked"
					? "blocked"
					: "finished",
		outcome: input.running ? "unverified" : outcome,
		recordedAtMs: input.now ?? Date.now(),
		...(typeof input.durationMs === "number" &&
		Number.isFinite(input.durationMs) &&
		input.durationMs >= 0
			? { durationMs: input.durationMs }
			: {}),
	}).data;
}

/** Best-effort redaction; never an assertion that arbitrary text is secret-free. */
export function redactReportText(text: string): string {
	const truncated = text.length > 200_000;
	return (
		text
			.slice(0, 200_000)
			.replace(
				/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g,
				"[REDACTED PRIVATE KEY]",
			)
			.replace(
				/\b(?:Bearer\s+|sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,})[^\s"'<>]*/gi,
				"[REDACTED TOKEN]",
			)
			.replace(
				/((?:api[_-]?key|password|passwd|secret|access[_-]?token|authorization)\s*["']?\s*[:=]\s*)["']?[^\s,;"'<>]+["']?/gi,
				"$1[REDACTED]",
			)
			.replace(/\bhttps?:\/\/[^\s<>"']+/gi, (value) => {
				try {
					const url = new URL(value);
					url.username = "";
					url.password = "";
					url.search = "";
					url.hash = "";
					return url.toString();
				} catch {
					return "[REDACTED URL]";
				}
			})
			.replace(/\b[A-Za-z]:[\\/](?:[^\s<>"'|]+)?/g, "[LOCAL PATH]")
			.replace(
				/(?:\/(?:Users|home|tmp|data|var|opt|mnt|private)\/)[^\s<>"'|]*/g,
				"[LOCAL PATH]",
			) + (truncated ? "\n[Report text truncated to 200,000 characters.]" : "")
	);
}

export function validationScope(value: {
	label: string;
	validationCommands?: string[];
	acceptanceCriteria?: string[];
}) {
	const scope = JSON.stringify([
		value.label,
		value.validationCommands ?? [],
		value.acceptanceCriteria ?? [],
	]);
	return scope.length <= 8192 ? scope : undefined;
}
