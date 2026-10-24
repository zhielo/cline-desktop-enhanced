import { posix, win32 } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { AnalysisResult } from "./contracts";
import type { TaskEvidenceSnapshot } from "./unified-evidence";

const Hash = z.string().regex(/^[a-f0-9]{64}$/);
const Script = z
	.object({
		scriptId: z.string().min(1).max(80),
		url: z.string().max(1000),
		status: z.enum(["loaded", "unknown"]),
		sha256: Hash.optional(),
		staticMatch: z.boolean().optional(),
	})
	.strict();

// Lexical identity only. This function never opens files or resolves symlinks.
// Network URLs, sourceURL labels, and query-bearing URLs are not path identity.
function sourcePath(value: string, workspace: string): string | undefined {
	let path = value;
	if (path.startsWith("file:")) {
		try {
			const url = new URL(path);
			if (url.hostname || url.search || url.hash) return;
			path = /^\/[a-z]:\//i.test(url.pathname)
				? decodeURIComponent(url.pathname.slice(1))
				: fileURLToPath(url);
		} catch {
			return;
		}
	} else if (/^[a-z][a-z0-9+.-]*:/i.test(path) && !/^[a-z]:[\\/]/i.test(path)) {
		return;
	}
	if (!path || /[\0\r\n]/.test(path)) return;
	if (/^[a-z]:[\\/]/i.test(workspace)) {
		if (/^[a-z]:[^\\/]/i.test(path)) return;
		return win32.resolve(workspace, path).toLowerCase();
	}
	// Do not interpret a foreign Windows path as a relative POSIX path.
	if (/^[a-z]:|^\\\\/i.test(path)) return;
	return posix.resolve(workspace, path);
}

/** Reconciles retained Inspector reports, never attaches or fetches source. */
export function reconcileInspectorSources(
	result: AnalysisResult,
	snapshots: TaskEvidenceSnapshot[],
	workspace: string,
) {
	return snapshots
		.filter(
			(s) => s.domain === "debugger" && s.tool === "node-inspector-passive",
		)
		.map((s) => {
			const raw =
				s.result && typeof s.result === "object"
					? (s.result as Record<string, unknown>)
					: {};
			const input =
				raw.input && typeof raw.input === "object"
					? (raw.input as Record<string, unknown>)
					: {};
			const admitted =
				raw.protocol === "cline-js-inspector/2" &&
				["completed", "partial"].includes(String(raw.status)) &&
				Hash.safeParse(input.sha256).success &&
				input.sha256 === s.targetSha256;
			const scripts = Array.isArray(raw.scripts) ? raw.scripts : [];
			const artifacts = result.artifacts.filter((a) => a.role === "source");
			const matches = admitted
				? scripts.slice(0, 128).map((value) => {
						const parsed = Script.safeParse(value);
						if (!parsed.success)
							return { classification: "invalid-script-record" as const };
						const script = parsed.data;
						const path = sourcePath(script.url, workspace);
						const location = path
							? artifacts.filter((a) => sourcePath(a.path, workspace) === path)
							: [];
						const bytes = script.sha256
							? artifacts.filter((a) => a.sha256 === script.sha256)
							: [];
						// A contradiction at an exact location must not disappear because
						// another file elsewhere happens to have the observed bytes.
						const classification =
							location.length > 1
								? "ambiguous-location"
								: location.length === 1 &&
									  script.sha256 &&
									  location[0].sha256 !== script.sha256
									? "source-byte-mismatch"
									: location.length === 1 && script.sha256
										? "exact-location-and-byte-match"
										: location.length === 1
											? "location-only-unverified"
											: bytes.length > 1
												? "ambiguous-byte-match"
												: bytes.length === 1
													? "exact-byte-match-location-unresolved"
													: "unresolved";
						return {
							scriptId: script.scriptId,
							classification,
							observedSha256: script.sha256,
							candidates: (location.length ? location : bytes)
								.slice(0, 16)
								.map((a) => ({
									path: a.path,
									sha256: a.sha256,
								})),
							candidatesTruncated: Math.max(location.length, bytes.length) > 16,
						};
					})
				: [];
			return {
				taskId: s.taskId,
				snapshotHash: s.snapshotHash,
				providerAdmitted: admitted,
				scripts: matches,
				scriptsTruncated: scripts.length > 128,
				verifiedExecution: false,
				limitations: [
					"Saved report reconciliation only; no filesystem reads, source-map fetching, attachment, or execution.",
					"Inspector is a protocol report, not an authenticated execution witness. Parsed/loaded scripts do not prove execution.",
					"Paths are lexical hints, not filesystem identity. A byte match is not reachability, behavior, or provenance proof.",
					"Missing reports and bounded-window omissions do not prove absence. Source maps and sourceURL labels are not trusted mappings.",
				],
			};
		});
}
