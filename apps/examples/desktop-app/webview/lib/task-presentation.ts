import type { TaskReportView } from "./task-report-view";

/** One semantic contract for summary, report and completion presentation. */
export function taskOutcomeTone(outcome: TaskReportView["outcome"]) {
	if (outcome === "Declared checks passed") return "verified" as const;
	if (outcome.startsWith("Failed")) return "failed" as const;
	if (
		outcome === "Blocked" ||
		outcome.startsWith("Partial") ||
		outcome.startsWith("Cancelled")
	)
		return "attention" as const;
	return "unverified" as const;
}
export function toolExecutionState(input: {
	running: boolean;
	missingReceipt: boolean;
	failed: boolean;
}) {
	if (input.failed) return { status: "error" as const, label: "Failed" };
	if (input.running) return { status: "running" as const, label: "Running" };
	if (input.missingReceipt)
		return { status: "finished" as const, label: "No terminal receipt" };
	return { status: "finished" as const, label: "Tool finished" };
}
