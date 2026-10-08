import { checkAnalysisEnvironment } from "@cline/core";

let active: ReturnType<typeof checkAnalysisEnvironment> | undefined;
/** Coalesce concurrent UI requests. Never reuse a completed/stale environment result. */
export function getAnalysisEnvironment() {
	if (!active) {
		active = checkAnalysisEnvironment().finally(() => {
			active = undefined;
		});
	}
	return active;
}
