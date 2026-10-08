import { stat } from "node:fs/promises";
import { checkAnalysisEnvironment } from "@cline/core";
let active: ReturnType<typeof checkAnalysisEnvironment> | undefined;
let completed:
	| {
			key: string;
			expires: number;
			value: Awaited<ReturnType<typeof checkAnalysisEnvironment>>;
	  }
	| undefined;
async function identity() {
	const executable = process.env.CLINE_RE_PYTHON?.trim() ?? "PATH";
	const info =
		executable === "PATH"
			? undefined
			: await stat(executable).catch(() => undefined);
	return JSON.stringify([
		executable,
		info?.mtimeMs,
		info?.size,
		process.env.CLINE_ANALYSIS_RUNTIME_ID,
		"analysis-readiness/v1",
	]);
}
/** Coalesce simultaneous probes. Cached owned fixtures are not fresh IDA/device acceptance. */
export function getAnalysisEnvironment(force = true) {
	if (!active) {
		active = (async () => {
			const key = await identity();
			if (!force && completed?.key === key && completed.expires > Date.now())
				return completed.value;
			const result = await checkAnalysisEnvironment();
			// Failed/missing engines are never hidden behind a successful old receipt.
			if (result.readiness?.status === "completed")
				completed = { key, expires: Date.now() + 5 * 60_000, value: result };
			else completed = undefined;
			return result;
		})().finally(() => {
			active = undefined;
		});
	}
	return active;
}
