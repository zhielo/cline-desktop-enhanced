import { Children, isValidElement, type ReactNode } from "react";
import type { ChatMessage } from "@/lib/chat-schema";
import { buildSessionTaskReport } from "@/lib/task-report";
import { cn } from "@/lib/utils";
import { TaskReportPanel } from "./task-report-panel";

function collectToolMessages(node: ReactNode, messages: Map<string, ChatMessage>) {
	Children.forEach(node, (child) => {
		if (!isValidElement(child)) return;
		const props = child.props as Record<string, unknown>;
		const candidates = [
			...(Array.isArray(props.messages) ? props.messages : []),
			props.message,
		];
		for (const candidate of candidates) {
			if (!candidate || typeof candidate !== "object") continue;
			const message = candidate as Partial<ChatMessage>;
			if (message.role === "tool" && typeof message.id === "string") {
				messages.set(message.id, candidate as ChatMessage);
			}
		}
		if ("children" in props) collectToolMessages(props.children as ReactNode, messages);
	});
}

export function SessionContent({
	children,
	className,
}: {
	children: ReactNode;
	className?: string;
}) {
	const toolMessages = new Map<string, ChatMessage>();
	collectToolMessages(children, toolMessages);
	const taskReport = buildSessionTaskReport([...toolMessages.values()]);

	return (
		<div
			className={cn(
				"mx-auto w-full min-w-0 max-w-(--breakpoint-lg)",
				className,
			)}
		>
			{taskReport ? (
				<div className="mb-4">
					<TaskReportPanel report={taskReport} />
				</div>
			) : null}
			{children}
		</div>
	);
}
