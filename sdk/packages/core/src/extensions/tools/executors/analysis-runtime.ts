export type AnalysisRuntimeIdentity = {
	source: "bundled" | "configured" | "path";
	runtimeId?: string;
	manifestHash?: string;
	integrity?: "verified" | "failed";
	reason?: string;
};
let identity: AnalysisRuntimeIdentity | undefined;
export function configureAnalysisRuntime(value: AnalysisRuntimeIdentity) {
	identity = { ...value };
}
export function getAnalysisRuntimeIdentity(): AnalysisRuntimeIdentity {
	if (identity) return { ...identity };
	if (process.env.CLINE_ANALYSIS_RUNTIME_ID)
		return {
			source: "bundled",
			runtimeId: process.env.CLINE_ANALYSIS_RUNTIME_ID,
		};
	return {
		source: process.env.CLINE_RE_PYTHON?.trim() ? "configured" : "path",
	};
}
