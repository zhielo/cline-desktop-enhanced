import type { Row } from "../shared/incident-readiness";

export { ownedFixtureRows } from "../shared/incident-readiness";
export function incidentReadiness(
	discovery: Record<string, unknown>,
	adb: Record<string, unknown> | undefined,
	health: unknown,
) {
	const rows: Row[] = [];
	const capabilities = discovery.capabilities as
		| Record<string, unknown>
		| undefined;
	const available = Object.fromEntries(
		["ghidra", "ida", "jadx"].map((tool) => [
			tool,
			(capabilities?.[tool] as Record<string, unknown> | undefined)?.[
				tool === "jadx" ? "cli" : "headless"
			],
		]),
	);
	for (const tool of ["ghidra", "ida", "jadx"]) {
		rows.push({
			tool,
			state: available?.[tool] ? "installed" : "blocked",
			evidence: available?.[tool]
				? "Discovered executable; no owned-fixture execution/license validation in this observation"
				: "Executable not discovered",
		});
	}
	rows.push({
		tool: "adb",
		state:
			adb &&
			adb.versionExitCode === 0 &&
			adb.devicesExitCode === 0 &&
			adb.incomplete === false &&
			typeof adb.version === "string" &&
			adb.version.includes("Android Debug Bridge")
				? "execution-verified"
				: "blocked",
		evidence: adb
			? "ADB version/devices commands executed; each incident separately verifies the selected serial and APK"
			: "ADB probe unavailable",
	});
	for (const tool of [
		"physical-device",
		"KernelSU/root",
		"Frida",
		"APK signing",
		"runtime sandbox",
	])
		rows.push({
			tool,
			state: "unverified",
			evidence:
				"Task-specific approval and preflight required; inventory/configuration is not runtime proof",
		});
	return {
		rows,
		discovery,
		adb,
		ownedFixtureHealth: health ?? null,
		notice:
			"Owned fixture health is reported verbatim. Presence never promotes a proprietary engine to execution-verified; task-ready is established only by the exact job preflight.",
	};
}
