import { DependencyEvidenceOptionsSchema } from "../investigation-workflows-schema";
import { z } from "zod";
import { candidateHash, readCandidateFile } from "./candidate-files";

const Package = z
	.object({
		name: z.string().min(1).max(214).optional(),
		version: z.string().min(1).max(200).optional(),
		link: z.boolean().optional(),
	})
	.passthrough();
const Lock = z
	.object({
		lockfileVersion: z.union([z.literal(2), z.literal(3)]),
		packages: z.record(z.string().max(4096), Package),
	})
	.passthrough();
const Snapshot = z
	.object({
		schemaVersion: z.literal(1),
		source: z.literal("OSV"),
		retrievedAt: z.string().datetime(),
		advisories: z
			.array(
				z
					.object({
						id: z.string().min(1).max(200),
						modified: z.string().datetime(),
						withdrawn: z.string().datetime().optional(),
						affected: z
							.array(
								z
									.object({
										package: z
											.object({
												ecosystem: z.string().max(80),
												name: z.string().max(214),
											})
											.passthrough(),
										versions: z
											.array(z.string().min(1).max(200))
											.max(10000)
											.optional(),
										ranges: z.array(z.unknown()).max(100).optional(),
									})
									.passthrough(),
							)
							.max(100),
					})
					.passthrough(),
			)
			.max(2000),
	})
	.strict();
/** Explicit, read-only lockfile and hash-pinned imported OSV evidence; no network/install/hooks. */
export async function resolvedDependencyEvidence(
	options: unknown,
	signal?: AbortSignal,
) {
	const q = DependencyEvidenceOptionsSchema.parse(options);
	const bytes = await readCandidateFile(q.lockfile, 8 * 1024 * 1024, signal);
	if (candidateHash(bytes) !== q.lockfile_sha256)
		throw new Error("Lockfile hash mismatch");
	const doc = Lock.parse(
		JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)),
	);
	const entries = Object.entries(doc.packages);
	if (entries.length > 10000) throw new Error("Lockfile entry budget exceeded");
	const resolved: {
		path: string;
		name: string;
		version: string;
		link: boolean;
	}[] = [];
	const unresolved: { path: string; reason: string }[] = [];
	for (const [path, row] of entries) {
		signal?.throwIfAborted();
		if (path === "") continue;
		if (
			path.includes("\\") ||
			path.split("/").some((p) => p === ".." || p === ".") ||
			path.startsWith("/")
		)
			throw new Error("Invalid lockfile package path");
		const segment = path.split("node_modules/").at(-1)!;
		const name = row.name ?? segment;
		if (
			!/^(?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/i.test(name) ||
			!row.version ||
			row.link
		) {
			unresolved.push({
				path,
				reason: row.link
					? "Workspace/link resolution requires separate evidence"
					: "No exact registry package name/version",
			});
			continue;
		}
		resolved.push({ path, name, version: row.version, link: false });
	}
	const matches: {
		id: string;
		modified: string;
		package: string;
		version: string;
		path: string;
		evidence: string;
	}[] = [];
	const rangeChecks: { id: string; package: string; reason: string }[] = [];
	let snapshot:
		| { sha256: string; source: string; retrievedAt: string; authority: string }
		| undefined;
	if (q.advisory_snapshot) {
		const raw = await readCandidateFile(
			q.advisory_snapshot.path,
			8 * 1024 * 1024,
			signal,
		);
		if (candidateHash(raw) !== q.advisory_snapshot.sha256)
			throw new Error("Advisory snapshot hash mismatch");
		const data = Snapshot.parse(
			JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)),
		);
		snapshot = {
			sha256: q.advisory_snapshot.sha256,
			source: data.source,
			retrievedAt: data.retrievedAt,
			authority:
				"caller-supplied snapshot; hash verifies selected bytes, not publisher identity or freshness",
		};
		const ids = new Set<string>();
		const packages = new Map<string, typeof resolved>();
		for (const row of resolved) {
			const list = packages.get(row.name) ?? [];
			list.push(row);
			packages.set(row.name, list);
		}
		let comparisons = 0;
		for (const advisory of data.advisories) {
			signal?.throwIfAborted();
			if (ids.has(advisory.id)) throw new Error("Duplicate advisory ID");
			ids.add(advisory.id);
			if (advisory.withdrawn) continue;
			for (const affected of advisory.affected) {
				signal?.throwIfAborted();
				if (++comparisons > 200000)
					throw new Error("Advisory comparison budget exceeded");
				if (affected.package.ecosystem !== "npm") continue;
				const candidates = packages.get(affected.package.name);
				if (!candidates) continue;
				const versions = new Set(affected.versions ?? []);
				for (const row of candidates) {
					if (++comparisons > 200000)
						throw new Error("Advisory comparison budget exceeded");
					if (versions.has(row.version)) {
						if (matches.length >= 2000)
							throw new Error("Advisory match output budget exceeded");
						matches.push({
							id: advisory.id,
							modified: advisory.modified,
							package: row.name,
							version: row.version,
							path: row.path,
							evidence:
								"exact affected.versions membership in hash-pinned imported snapshot",
						});
					}
				}
				if (affected.ranges?.length) {
					if (rangeChecks.length >= 2000)
						throw new Error("Advisory range output budget exceeded");
					rangeChecks.push({
						id: advisory.id,
						package: affected.package.name,
						reason:
							"Version-range events are not evaluated by this exact-version adapter",
					});
				}
			}
		}
	}
	return {
		status: "partial",
		effect: "read",
		lockfileSha256: candidateHash(bytes),
		lockfileVersion: doc.lockfileVersion,
		resolved,
		unresolved,
		advisorySnapshot: snapshot,
		advisoryMatches: matches,
		unevaluatedRanges: rangeChecks,
		riskVerdict: "unknown",
		observedExecution: false,
		limitations: [
			"npm package-lock v2/v3 selected entries only; not an install receipt or proof of artifacts present on disk.",
			"Imported advisory exact-version membership is checked; publisher authenticity, completeness and freshness are not established. Range events are explicit unresolved work; no clean-risk verdict.",
			"No network, package installation, lifecycle scripts, URL credential disclosure or runtime execution.",
		],
	};
}
