// Only controller-owned helper output is passed here, never target stdout/stderr.
const stages = new Set([
	"staging",
	"profile",
	"acl",
	"job",
	"pipes",
	"startup-attributes",
	"launch",
	"token-check",
	"job-assign",
	"birth",
	"capture",
	"resume",
	"wait",
	"termination",
	"drain",
	"receipt",
	"cleanup",
]);
const fallback =
	"OS isolation failed closed before a successful receipt; no fallback";
export function isolationHostFailureMessage(text: string): string {
	if (Buffer.byteLength(text) > 4096) return fallback;
	try {
		const v: unknown = JSON.parse(text);
		if (!v || typeof v !== "object" || Array.isArray(v)) return fallback;
		const d = v as Record<string, unknown>;
		if (
			Object.keys(d).sort().join(",") !==
				"cleanupFailures,error,hresult,schemaVersion,stage,win32Error" ||
			d.schemaVersion !== 1 ||
			d.error !== "isolation-launch-failed" ||
			typeof d.stage !== "string" ||
			!stages.has(d.stage) ||
			!Number.isInteger(d.hresult) ||
			Number(d.hresult) < -2147483648 ||
			Number(d.hresult) > 2147483647 ||
			(d.win32Error !== null &&
				(!Number.isInteger(d.win32Error) ||
					Number(d.win32Error) < 0 ||
					Number(d.win32Error) > 2147483647)) ||
			!Array.isArray(d.cleanupFailures) ||
			d.cleanupFailures.length > 2 ||
			d.cleanupFailures.some(
				(x) => x !== "profile-cleanup" && x !== "staging-cleanup",
			)
		)
			return fallback;
		return `OS isolation failed closed: stage=${d.stage}; win32=${d.win32Error ?? "none"}; hresult=0x${(Number(d.hresult) >>> 0).toString(16)}; cleanup=${d.cleanupFailures.join(",") || "none"}; no fallback`;
	} catch {
		return fallback;
	}
}
