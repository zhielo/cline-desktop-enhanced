import { runAdvancedAnalysis } from "./advanced-analysis";

/** Explicit, bounded execution of owned fixtures only. No installs or target analysis. */
export async function checkAnalysisEnvironment(signal?: AbortSignal) {
	const [toolchain, readiness] = await Promise.all([
		runAdvancedAnalysis({ action: "toolchain", timeoutMs: 20_000 }, signal),
		runAdvancedAnalysis(
			{ action: "analysis_readiness", timeoutMs: 60_000 },
			signal,
		),
	]);
	return {
		checkedAt: new Date().toISOString(),
		configured: Boolean(process.env.CLINE_RE_PYTHON?.trim()),
		interpreter: toolchain.evidence.interpreter ?? {
			executable: toolchain.diagnostics?.interpreter ?? null,
			version: null,
		},
		toolchain,
		readiness,
		externalCapabilities: [
			{
				id: "IDA / IDAPython",
				status: "configuration-required",
				reason:
					"Separate installed-engine acceptance test required; Python package imports do not validate IDA.",
			},
			{
				id: "Hex-Rays",
				status: "configuration-required",
				reason: "Processor-specific licensed decompiler must be tested in IDA.",
			},
			{
				id: "Android device / isolated worker",
				status: "configuration-required",
				reason:
					"Static fixtures are not physical-device or sandbox provisioning evidence.",
			},
		],
		setup:
			"Use scripts/setup-analysis-environment.ps1 from a trusted checkout. It requires -Apply to install pinned packages. Restart the desktop and backend after setting CLINE_RE_PYTHON.",
	};
}
