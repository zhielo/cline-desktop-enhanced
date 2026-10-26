"use client";
import { useId, type ReactNode } from "react";
import type { ChatRenderItem } from "./group-messages";
import { buildToolPresentation } from "./tool-summaries";
import { useActivityDisclosure } from "../activity-presentation";
import { nativeExecutionFailure } from "@/lib/native-tool-progress";
import {
	TaskObservationSchema,
	reportedOutcome,
} from "../../../../../shared/task-observation";
import type { ChatMessage, ChatSessionStatus } from "@/lib/chat-schema";

/** Keep errors, unresolved tools and generated deliverables visible; fold routine work only. */
export function splitActivity(items: ChatRenderItem[]) {
	const routine: ChatRenderItem[] = [],
		attention: ChatRenderItem[] = [];
	let tools = 0;
	for (const item of items) {
		if (item.type !== "tools") {
			routine.push(item);
			continue;
		}
		const quiet: ChatMessage[] = [],
			important: ChatMessage[] = [];
		for (const message of item.messages) {
			tools++;
			const p = buildToolPresentation(message);
			const event = message.meta?.taskEvent;
			const receipt = TaskObservationSchema.safeParse(event?.observation);
			const bound =
				receipt.success &&
				receipt.data.sessionId === message.sessionId &&
				receipt.data.toolCallId === message.meta?.toolCallId &&
				receipt.data.toolName ===
					String(message.meta?.toolName ?? p.payload?.toolName ?? "")
					? receipt.data
					: undefined;
			const rawOutcome =
				p.payload?.result && typeof p.payload.result === "object"
					? (p.payload.result as Record<string, unknown>).outcome
					: null;
			let outcome: unknown = bound?.outcome;
			if (!bound) outcome = reportedOutcome(p.payload?.result);
			if (
				(p.summary.toolName === "reverse_engineer" &&
					nativeExecutionFailure(p.payload?.result)) ||
				p.inProgress ||
				(bound &&
					["failed", "timed_out", "blocked", "cancelled"].includes(
						bound.execution,
					)) ||
				["failed", "blocked", "partial", "inconclusive"].includes(
					String(rawOutcome),
				) ||
				p.payload?.isError ||
				event?.type === "tool.failed" ||
				outcome === "cancelled" ||
				outcome === "failed" ||
				outcome === "blocked" ||
				outcome === "partial" ||
				outcome === "inconclusive" ||
				p.summary.outputMedia.length ||
				p.summary.toolName === "submit_and_exit"
			)
				important.push(message);
			else quiet.push(message);
		}
		if (quiet.length) routine.push({ type: "tools", messages: quiet });
		if (important.length)
			attention.push({ type: "tools", messages: important });
	}
	// The latest completed action remains visible while awaiting the next operation.
	if (!attention.length && routine.length) {
		const tail = routine.at(-1)!;
		if (tail.type === "tools" && tail.messages.length > 1) {
			attention.push({ type: "tools", messages: tail.messages.slice(-1) });
			routine[routine.length - 1] = {
				type: "tools",
				messages: tail.messages.slice(0, -1),
			};
		} else attention.push(routine.pop()!);
	}
	return { routine, attention, tools };
}
export function LiveActivityGroup({
	id,
	sessionId,
	items,
	status,
	fullActivity,
	renderItem,
}: {
	id: string;
	sessionId: string | null;
	items: ChatRenderItem[];
	status: ChatSessionStatus;
	fullActivity: boolean;
	renderItem: (item: ChatRenderItem) => ReactNode;
}) {
	const panelId = useId();
	const [expanded, setExpanded] = useActivityDisclosure(
		sessionId,
		`live:${id}`,
	);
	const { routine, attention, tools } = splitActivity(items);
	const active =
		status === "running" || status === "starting" || status === "stopping";
	if (fullActivity || !active || !routine.length)
		return (
			<div className="flex min-w-0 flex-col gap-1">{items.map(renderItem)}</div>
		);
	return (
		<section
			className="min-w-0 rounded-lg border border-border/70 bg-card/30"
			aria-label="Grouped live activity"
		>
			<button
				type="button"
				aria-expanded={expanded}
				aria-controls={panelId}
				className="flex min-h-11 w-full flex-wrap items-center justify-between gap-2 rounded-lg px-3 py-2 text-left text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
				onClick={() => setExpanded(!expanded)}
			>
				<span className="font-medium">
					Task activity · {tools} tool {tools === 1 ? "action" : "actions"}
				</span>
				<span className="text-muted-foreground">
					{expanded ? "Collapse routine activity" : "Show routine activity"}
				</span>
			</button>
			<div id={panelId} className="min-w-0 space-y-1 px-3 pb-2">
				{(expanded ? items : attention).map(renderItem)}
			</div>
		</section>
	);
}
