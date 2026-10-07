import * as path from "node:path";
import { runSupervised } from "./supervised-process";

const REGISTRY_PROBE_TIMEOUT_MS = 5_000;

/** Optional environment discovery must not hang the caller or leave raw probes running. */
export async function readWindowsRegistryValue(
	key: string,
	name: string,
	platform: NodeJS.Platform = process.platform,
): Promise<string | undefined> {
	if (platform !== "win32") return undefined;
	try {
		const command = path.win32.join(
			process.env.SystemRoot ?? process.env.WINDIR ?? "C:\\Windows",
			"System32",
			"reg.exe",
		);
		const result = await runSupervised(
			command,
			["query", key, "/v", name],
			REGISTRY_PROBE_TIMEOUT_MS,
		);
		if (
			result.exitCode !== 0 ||
			result.timedOut ||
			result.cancelled ||
			result.outputDrainTimedOut ||
			result.truncated
		)
			return undefined;
		const line = result.stdout
			.split(/\r?\n/)
			.find((candidate) => /\bREG_(?:EXPAND_)?SZ\b/i.test(candidate));
		const value = line?.split(/\bREG_(?:EXPAND_)?SZ\b/i)[1]?.trim();
		return value
			? value.replace(
					/%([^%]+)%/g,
					(match, variable: string) =>
						process.env[variable] ??
						process.env[variable.toUpperCase()] ??
						match,
				)
			: undefined;
	} catch {
		// Missing registry access/tools are optional; retain the inherited environment.
		return undefined;
	}
}
