import * as fs from "node:fs/promises";
import * as path from "node:path";

/**
 * Ghidra validates every project-location component with NamingUtilities.
 * Unlike the other engines it cannot store a project below ~/.cline.
 * Do not move other engines' caches or silently relocate explicit user paths.
 */
export function ghidraAnalysisCacheRoot(
	homeDirectory: string,
	configuredCacheDirectory: string | undefined,
): string {
	return path.resolve(
		configuredCacheDirectory ??
			path.join(homeDirectory, "cline-analysis-cache", "reverse-engineering"),
	);
}

export function validateGhidraProjectPath(directory: string): void {
	// Ghidra normalizes backslashes to slashes even on POSIX.
	if (
		directory
			.replace(/\\/g, "/")
			.split("/")
			.some((part) => part.startsWith("."))
	)
		throw new Error(
			"Ghidra project directories cannot contain dot-prefixed path components " +
				"(including .cline or .cache). Choose a non-dot output_directory or " +
				"set CLINE_RE_CACHE_DIR to a non-dot absolute path and restart the backend. " +
				"No existing cache was moved or deleted.",
		);
}

/** Validate both the launcher argument and its physical parent before writes. */
export async function validateGhidraProjectDirectory(
	directory: string,
): Promise<void> {
	validateGhidraProjectPath(directory);
	let existing = path.resolve(directory);
	const suffix: string[] = [];
	for (;;) {
		try {
			const physical = await fs.realpath(existing);
			validateGhidraProjectPath(path.join(physical, ...suffix));
			return;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
			const parent = path.dirname(existing);
			if (parent === existing) throw error;
			suffix.unshift(path.basename(existing));
			existing = parent;
		}
	}
}
