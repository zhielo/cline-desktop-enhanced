import type { ReactNode } from "react";
import type { ChatSessionStatus } from "@/lib/chat-schema";
import type { SessionTaskReport } from "@/lib/task-report";
import { cn } from "@/lib/utils";
import { TaskReportPanel } from "./task-report-panel";

export function SessionContent({
	children,
	className,
	status,
	taskReport,
}: {
	children: ReactNode;
	className?: string;
	status?: ChatSessionStatus;
	taskReport?: SessionTaskReport | null;
}) {
	return (
		<div
			className={cn(
				"mx-auto w-full min-w-0 max-w-(--breakpoint-lg)",
				className,
			)}
		>
			{taskReport ? (
				<div className="mb-4">
					<TaskReportPanel
						key={taskReport.sourceMessageId}
						report={taskReport}
						status={status}
					/>
				</div>
			) : null}
			{children}
		</div>
	);
}
