import { win32 } from "node:path";
/** Trusted helper bootstrap only. Never pass this environment to target code. */
export function isolationHostEnvironment(
	source: Record<string, string | undefined>,
	temporaryDirectory: string,
) {
	const names = [
		"APPDATA",
		"LOCALAPPDATA",
		"SystemRoot",
		"USERPROFILE",
	] as const;
	const required = Object.fromEntries(
		names.map((name) => {
			const value = source[name];
			if (
				!value ||
				value.length > 4096 ||
				value.includes("\0") ||
				!win32.isAbsolute(value)
			)
				throw new Error(
					`Windows isolation bootstrap variable unavailable: ${name}`,
				);
			return [name, value];
		}),
	);
	if (
		!temporaryDirectory ||
		temporaryDirectory.includes("\0") ||
		!win32.isAbsolute(temporaryDirectory)
	)
		throw new Error("Absolute Windows temporary directory required");
	// Sorted case-insensitively even for launchers that don't sort object entries.
	return {
		APPDATA: required.APPDATA,
		LOCALAPPDATA: required.LOCALAPPDATA,
		SystemRoot: required.SystemRoot,
		TEMP: temporaryDirectory,
		TMP: temporaryDirectory,
		USERPROFILE: required.USERPROFILE,
	};
}
