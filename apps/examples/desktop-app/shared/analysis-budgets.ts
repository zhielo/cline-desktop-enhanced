/** Shared approval and execution deadlines. Explicit shorter deadlines are retained. */
export const DEFAULT_ANALYSIS_TIMEOUT_MS = 120_000;
export const MAX_ANALYSIS_TIMEOUT_MS = 30 * 60_000;
export const IDA_OVERALL_TIMEOUT_MS = 75 * 60_000;
export const IDA_AUTO_ANALYSIS_TIMEOUT_MS = 60 * 60_000;
export function resolveAnalysisTimeoutMs(
	request: Record<string, unknown>,
	explicit?: number,
): number {
	const ida = request.engine === "ida";
	const maximum = ida ? IDA_OVERALL_TIMEOUT_MS : MAX_ANALYSIS_TIMEOUT_MS;
	const requested =
		explicit ??
		request.timeout_ms ??
		(ida ? IDA_OVERALL_TIMEOUT_MS : DEFAULT_ANALYSIS_TIMEOUT_MS);
	if (
		typeof requested !== "number" ||
		!Number.isFinite(requested) ||
		requested <= 0
	)
		throw new Error("Analysis timeout must be a positive finite number");
	return Math.min(Math.max(requested, 1_000), maximum);
}
