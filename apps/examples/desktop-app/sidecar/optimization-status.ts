import { readFileSync, mkdirSync, writeFileSync, renameSync } from "node:fs";
import { dirname, join } from "node:path";
import {
	analysisResourceGovernor,
	getPowerShellWorkerBaselineDecision,
	cleanupStaleDetachedCommandLogs,
} from "@cline/core";
import { resolveClineDataDir } from "@cline/shared/storage";
import { privateUpdateReadiness } from "./trusted-update";
const path = () =>
	join(resolveClineDataDir(), "settings", "resource-profile.json");
export function loadResourceProfile() {
	try {
		const value = JSON.parse(readFileSync(path(), "utf8"));
		if (["economy", "balanced", "deep"].includes(value.profile)) {
			analysisResourceGovernor.setProfile(value.profile);
			process.env.CLINE_RESOURCE_PROFILE = value.profile;
		}
	} catch {
		/* Conservative default. */
	}
}
export function setResourceProfile(profile: unknown) {
	if (profile !== "economy" && profile !== "balanced" && profile !== "deep")
		throw new Error("Invalid resource profile");
	const file = path();
	mkdirSync(dirname(file), { recursive: true });
	const temp = `${file}.${process.pid}.tmp`;
	writeFileSync(temp, JSON.stringify({ profile }), { mode: 0o600 });
	renameSync(temp, file);
	analysisResourceGovernor.setProfile(profile);
	process.env.CLINE_RESOURCE_PROFILE = profile;
	return { ...optimizationStatus(), restartRequired: true };
}
export function optimizationStatus() {
	return {
		resources: analysisResourceGovernor.snapshot(),
		performance: {
			status: "baseline-required",
			reason:
				"Installed startup samples are recorded in acceptance evidence; no controlled before/after baseline is claimed.",
			commandLatency: getPowerShellWorkerBaselineDecision(),
		},
		updates: privateUpdateReadiness(),
		limitations: [
			"Resource admission is per owning process; it is not machine-wide CPU/RAM enforcement.",
			"Native engine pool and process safety limits remain unchanged.",
		],
	};
}
export async function cleanupCompletedCommandLogs() {
	const removed = await cleanupStaleDetachedCommandLogs();
	return {
		removed,
		message:
			"Only expired detached command logs were considered. Active process identities, project files, session history and runtime packs were not deleted.",
	};
}
