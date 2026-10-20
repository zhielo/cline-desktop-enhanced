import { open } from "node:fs/promises";
import { TaskObservationSchema } from "../shared/task-observation";
import { sessionLogPath } from "./paths";

type RecordValue = Record<string, unknown>;
const record = (v: unknown): RecordValue | null =>
	v && typeof v === "object" && !Array.isArray(v) ? (v as RecordValue) : null;
/** Best-effort bounded decoration only. Never creates transcript turns or executes work. */
export async function restoreTaskReportEvents(
	sessionId: string,
	messages: RecordValue[],
) {
	if (!/^[A-Za-z0-9_-]{1,160}$/.test(sessionId)) return messages;
	let file: Awaited<ReturnType<typeof open>> | undefined;
	try {
		file = await open(sessionLogPath(sessionId), "r");
		const stat = await file.stat();
		if (!stat.isFile()) return messages;
		const start = Math.max(0, stat.size - 2 * 1024 * 1024),
			buffer = Buffer.alloc(Math.min(stat.size, 2 * 1024 * 1024));
		const { bytesRead } = await file.read(buffer, 0, buffer.length, start);
		let lines = buffer.subarray(0, bytesRead).toString("utf8").split("\n");
		if (start > 0) lines = lines.slice(1);
		return decorateTaskReportEvents(sessionId, messages, lines.slice(-4000));
	} catch {
		return messages;
	} finally {
		await file?.close().catch(() => {});
	}
}
export function decorateTaskReportEvents(
	sessionId: string,
	messages: RecordValue[],
	lines: string[],
): RecordValue[] {
	const events = new Map<string, RecordValue>();
	const validations = new Map<string, Map<string, unknown>>();
	for (const line of lines.slice(-4000)) {
		if (line.length > 262_144) continue;
		try {
			const envelope = record(JSON.parse(line));
			if (
				!["chat_tool_call_start", "chat_tool_call_end"].includes(
					String(envelope?.stream),
				)
			)
				continue;
			const chunk =
				typeof envelope?.chunk === "string"
					? record(JSON.parse(envelope.chunk))
					: null;
			const event = record(chunk?.taskEvent);
			if (
				!event ||
				typeof chunk?.toolCallId !== "string" ||
				typeof chunk?.toolName !== "string"
			)
				continue;
			const proof = TaskObservationSchema.safeParse(event.observation);
			// The local log is a host receipt store, not an imported report authority.
			if (
				proof.success &&
				proof.data.sessionId === sessionId &&
				proof.data.toolCallId === chunk.toolCallId &&
				proof.data.toolName === chunk.toolName &&
				proof.data.source === "host-validation" &&
				proof.data.planId
			) {
				const map = validations.get(proof.data.planId) ?? new Map();
				map.set(proof.data.toolCallId, proof.data);
				validations.set(proof.data.planId, map);
			}
			const prior = events.get(chunk.toolCallId);
			if (prior?.type === "tool.completed" || prior?.type === "tool.failed")
				continue;
			events.set(chunk.toolCallId, { ...event, toolName: chunk.toolName });
		} catch {
			/* A partial/malformed tail is unavailable evidence, not a failure or pass. */
		}
	}
	const lastPlans = new Map<string, RecordValue>();
	const result = messages.map((message) => {
		if (message.sessionId !== sessionId || message.role !== "tool")
			return message;
		const meta = record(message.meta);
		const id = meta?.toolCallId;
		if (typeof id !== "string") return message;
		const event = events.get(id);
		if (!event || event.toolName !== meta?.toolName) return message;
		const observation = TaskObservationSchema.safeParse(event.observation);
		if (
			event.type !== "plan.updated" &&
			(!observation.success || observation.data.sessionId !== sessionId)
		)
			return message;
		const decorated = {
			...message,
			meta: {
				...meta,
				taskEvent: event,
				taskStepId: typeof event.stepId === "string" ? event.stepId : undefined,
			},
		};
		if (event.type === "plan.updated" && typeof event.planId === "string")
			lastPlans.set(event.planId, decorated);
		return decorated;
	});
	for (const [id, message] of lastPlans) {
		const meta = record(message.meta)!;
		const event = record(meta.taskEvent)!;
		const checks = validations.get(id);
		if (checks)
			meta.taskEvent = {
				...event,
				hostValidations: [...checks.values()].slice(-100),
			};
	}
	return result;
}
