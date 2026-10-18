import * as path from "node:path";
import { VersionComparisonSchema } from "../investigation-workflows-schema";
import { candidateHash } from "./candidate-files";
import { reviewProjectFiles } from "./project-review";
import {
	collectWorkflowSources,
	comparePublicDeclarations,
} from "./source-investigation";

/** Fixed read-only composition, not a build, approval or semantic-equivalence oracle. */
export async function compareProjectVersions(
	input: {
		target?: string;
		compare_target?: string;
		version_comparison?: unknown;
		timeout_ms?: number;
	},
	signal?: AbortSignal,
) {
	const q = VersionComparisonSchema.parse(input.version_comparison);
	if (
		!input.target ||
		!input.compare_target ||
		!path.isAbsolute(input.target) ||
		!path.isAbsolute(input.compare_target)
	)
		throw Error(
			"Project comparison requires two explicit absolute directory targets",
		);
	const before = path.resolve(input.target),
		after = path.resolve(input.compare_target);
	if (before === after || path.dirname(before) !== path.dirname(after))
		throw Error(
			"Project comparison requires distinct sibling directories under one authorized parent",
		);
	const combined = AbortSignal.any([
		...(signal ? [signal] : []),
		AbortSignal.timeout(Math.min(input.timeout_ms ?? 120000, 600000)),
	]);
	combined.throwIfAborted();
	const request = {
		protocol: "cline-project-inventory-request/v1",
		baseline_directory: path.basename(before),
		candidate_directory: path.basename(after),
	};
	const inventory = () => reviewProjectFiles(before, request, combined, true);
	const initial = await inventory();
	const base = {
		protocol: "cline-project-version-comparison/v1",
		operation: "compare_versions",
		effect: "read",
		published: false,
		observedExecution: false,
		baselineInventorySha256: initial.baselineInventorySha256,
		candidateInventorySha256: initial.candidateInventorySha256,
		baselineFiles: initial.baselineFiles,
		candidateFiles: initial.candidateFiles,
		changedFiles: initial.changedFiles,
	};
	if (!initial.proposedManifest)
		return {
			...base,
			status: "blocked",
			reason:
				"More than 256 file changes; narrow the project roots. No incomplete combined report or approval generated.",
			publicApi: { status: "not-started" },
		};
	const changes = initial.proposedManifest.approved_changes.map((c) => ({
		...c,
		kind:
			c.before_sha256 === null
				? "added"
				: c.after_sha256 === null
					? "removed"
					: "changed",
		category: category(c.path),
	}));
	const categoryCounts: Record<string, number> = {};
	for (const c of changes)
		categoryCounts[c.category] = (categoryCounts[c.category] ?? 0) + 1;
	const collect = async (target: string) => {
		try {
			return await collectWorkflowSources(target, combined);
		} catch (error) {
			combined.throwIfAborted();
			if (
				error instanceof Error &&
				error.message.startsWith("No supported JS/TS sources")
			)
				return {
					sources: [],
					limitations: ["No supported JS/TS files in this covered inventory"],
				};
			throw error;
		}
	};
	const left = await collect(before),
		right = await collect(after);
	combined.throwIfAborted();
	const api = comparePublicDeclarations(
		left.sources,
		right.sources,
		Math.min(q.max_results, 50),
		false,
	);
	const apiJson = JSON.stringify(api);
	const publicApi =
		Buffer.byteLength(apiJson) <= 131072
			? { status: "partial", ...api }
			: {
					status: "partial",
					detailsOmitted: true,
					counts: api.counts,
					reason: "Explicit API evidence exceeded 128 KiB detail budget",
					evidenceSha256: candidateHash(apiJson),
				};
	const final = await inventory();
	if (
		initial.baselineInventorySha256 !== final.baselineInventorySha256 ||
		initial.candidateInventorySha256 !== final.candidateInventorySha256
	)
		throw Error(
			"Project changed during combined comparison; discard evidence and retry with stable inputs",
		);
	combined.throwIfAborted();
	const changeDetails = boundedRows(changes, q.max_results, 49152);
	const sourceRows = [
		...left.sources.map(({ path, sha256, bytes }) => ({
			side: "baseline",
			path,
			sha256,
			bytes,
		})),
		...right.sources.map(({ path, sha256, bytes }) => ({
			side: "candidate",
			path,
			sha256,
			bytes,
		})),
	];
	const sourceDetails = boundedRows(sourceRows, 256, 49152);
	const report = {
		...base,
		status: "partial",
		identicalBytes:
			initial.baselineInventorySha256 === initial.candidateInventorySha256,
		categoryCounts,
		changes: changeDetails.rows,
		changesTruncated: changeDetails.truncated,
		changeSetSha256: candidateHash(JSON.stringify(changes)),
		publicApi,
		sourceArtifacts: sourceDetails.rows,
		sourceArtifactsTruncated: sourceDetails.truncated,
		sourceArtifactsSha256: candidateHash(JSON.stringify(sourceRows)),
		sourceLimitations: [...left.limitations, ...right.limitations]
			.slice(0, 16)
			.map((s) => s.slice(0, 384)),
		sourceLimitationsTruncated:
			left.limitations.length + right.limitations.length > 16 ||
			[...left.limitations, ...right.limitations].some((s) => s.length > 384),
		coverage: {
			inventoryPasses: 4,
			maxEntriesPerRoot: 4096,
			maxDepth: 16,
			maxFileBytes: 16777216,
			maxCombinedBytesPerPass: 67108864,
			maxChanges: 256,
			maxReturnedChanges: q.max_results,
			maxPublicApiRows: Math.min(q.max_results, 50),
			maxOutputBytes: 262144,
			maxChangeDetailsBytes: 49152,
			maxSourceArtifactDetailsBytes: 49152,
		},
		limitations: [
			"Combined complete bounded regular-file byte/hash inventory and explicit JS/TS API syntax differences only; category labels derive from paths, not trusted format or behavioral identification. No semantic resource, manifest, DEX/native instruction or ABI comparison, rename inference or breaking-change verdict.",
			"Inventories include dotfiles and use no ignore list. JS/TS API scanning separately excludes node_modules/.git/dist/build/.cline and caps 128 files, 1 MiB/file, 8 MiB combined source per root and depth 8. Unchanged files can still have unresolved or unsupported APIs; syntax signatures exclude inferred types and resolved reexports.",
			"Four bounded inventory passes bracket source parsing; ordinary mutation is rejected, not an atomic snapshot or hostile-filesystem sandbox. Empty-directory/metadata/ACL/alternate-stream differences are not covered. SHA256 matches establish byte evidence, not producer identity or execution equivalence.",
			"Read only: no approval, project writes, extraction, downloads, builds, signing, device installation or target execution. Static mode grants no runtime permissions. Not an authorization allowlist or passing candidate-review receipt.",
		],
	};
	if (Buffer.byteLength(JSON.stringify(report)) > 262144)
		throw Error(
			"Combined comparison output budget exceeded; narrow project scope",
		);
	return report;
}
function boundedRows<T>(rows: T[], maximum: number, budget: number) {
	const selected: T[] = [];
	let used = 2;
	for (const row of rows) {
		const cost = Buffer.byteLength(JSON.stringify(row)) + 1;
		if (selected.length >= maximum || used + cost > budget) break;
		selected.push(row);
		used += cost;
	}
	return { rows: selected, truncated: selected.length < rows.length };
}
function category(file: string) {
	if (
		/(^|\/)(AndroidManifest\.xml|package\.json|[^/]+\.(?:csproj|sln))$/i.test(
			file,
		)
	)
		return "manifest";
	if (/(^|\/)(res|resources|assets)\//i.test(file)) return "resources-assets";
	if (/\.(?:dex|smali)$/i.test(file)) return "android-code";
	if (/\.(?:so|dll|exe|dylib|wasm|a|o)$/i.test(file)) return "native-binary";
	if (/\.(?:[cm]?[jt]s|[jt]sx|java|kt|cs|py|c|h|cpp|hpp|rs)$/i.test(file))
		return "source";
	return "other";
}
