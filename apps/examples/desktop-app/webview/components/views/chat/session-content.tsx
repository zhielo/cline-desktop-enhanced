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
	onReviewChanges,
	onOpenReport,
	onOpenActivity,
}: {
	children: ReactNode;
	className?: string;
	status?: ChatSessionStatus;
	taskReport?: SessionTaskReport | null;
	onReviewChanges?: () => void;
	onOpenReport?: () => void;
	onOpenActivity?: () => void;
}) {
	return (
		<div className={cn("mx-auto w-full min-w-0 max-w-[880px]", className)}>
			{taskReport ? (
				<div className="mb-4">
					<TaskReportPanel
						key={taskReport.turnId ?? taskReport.sourceMessageId}
						report={taskReport}
						onReviewChanges={onReviewChanges}
						onOpenReport={onOpenReport}
						onOpenActivity={onOpenActivity}
						status={status}
					/>
				</div>
			) : null}
			{children}
		</div>
	);
}
