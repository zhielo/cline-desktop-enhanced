import { readFile } from "node:fs/promises";

export function annotationFromSummary(summary) {
	if (summary?.status !== "failed") return undefined;
	const startup = typeof summary.hubStartupDiagnostic === "string"
		? summary.hubStartupDiagnostic.slice(-1600) : "";
	const reason = (String(summary.reason ?? "Inspect installed UI evidence").slice(0, 800) +
		(startup ? `; owned Hub startup tail: ${startup}` : ""))
		.replace(/(?:Bearer\s+|approval_token=)\S+/gi, "[REDACTED]")
		.replace(/("(?:authToken|token|apiKey|password|secret)"\s*:\s*")[^"]*"/gi, '$1[REDACTED]"')
		.replace(/\b[0-9a-f]{32,}\b/gi, "[REDACTED]")
		.slice(0, 2000);
	const stages = Array.isArray(summary.stages)
		? summary.stages.filter(s => typeof s === "string" && /^[a-z0-9-]{1,100}$/.test(s)).slice(-3).join(", ")
		: "";
	return `Installed acceptance failed after [${stages || "launch"}]: ${reason}`
		.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A");
}

if (process.argv[1]?.endsWith("report-installed-acceptance.mjs") && process.argv[2]) {
	try {
		const bytes = await readFile(process.argv[2]);
		if (bytes.length > 64 * 1024) throw new Error("Summary exceeds budget");
		const annotation = annotationFromSummary(JSON.parse(bytes.toString("utf8")));
		if (annotation) console.log(`::error title=Installed acceptance::${annotation}`);
	} catch {
		console.log("Installed acceptance summary unavailable; inspect retained bounded artifacts.");
	}
}