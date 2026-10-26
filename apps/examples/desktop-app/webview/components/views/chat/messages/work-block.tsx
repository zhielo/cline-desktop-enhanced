"use client";

import {
	WorkActivity,
	WorkActivityContent,
	WorkActivityTrigger,
} from "@cline/ui/components/agent-chat";
import { useActivityDisclosure } from "../activity-presentation";
import { memo, type ReactNode } from "react";

/**
 * Collapsed summary row for a finished run's working rows. Expanding re-shows
 * the run's normal chat rows (tool calls, thinking traces, narration) under
 * the shared disclosure rail. Collapse state lives in the ui primitive, so
 * keying this block by the work item's stable id preserves it across renders.
 */
export const WorkBlock = memo(function WorkBlock({
	id = "work",
	sessionId,
	durationMilliseconds,
	toolCallCount,
	children,
}: {
	id?: string;
	sessionId?: string | null;
	durationMilliseconds?: number;
	toolCallCount: number;
	children: ReactNode;
}) {
	const [open, setOpen] = useActivityDisclosure(sessionId, `work:${id}`);
	return (
		<WorkActivity open={open} onOpenChange={setOpen}>
			<WorkActivityTrigger
				durationMilliseconds={durationMilliseconds}
				toolCallCount={toolCallCount}
			/>
			<WorkActivityContent>{children}</WorkActivityContent>
		</WorkActivity>
	);
});
