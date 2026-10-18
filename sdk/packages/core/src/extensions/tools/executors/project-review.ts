import { constants } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { z } from "zod";
import { candidateHash, rejectCandidateLinks } from "./candidate-files";
const Hash = z.string().regex(/^[a-f0-9]{64}$/);
const Relative = z
	.string()
	.min(1)
	.max(1024)
	.superRefine((value, c) => {
		const parts = value.split("/");
		if (
			Buffer.byteLength(value, "utf8") > 1024 ||
			parts.some(
				(p) =>
					!p ||
					p === "." ||
					p === ".." ||
					/[\\:<>"|?*]/.test(p) ||
					[...p].some((character) => character.charCodeAt(0) < 32) ||
					/[. ]$/.test(p) ||
					/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(p),
			)
		)
			c.addIssue({
				code: "custom",
				message: "Canonical portable relative path required",
			});
	});
export const ProjectInventoryRequestSchema = z
	.object({
		protocol: z.literal("cline-project-inventory-request/v1"),
		baseline_directory: Relative,
		candidate_directory: Relative,
	})
	.strict();
export const ProjectReviewManifestSchema = z
	.object({
		protocol: z.literal("cline-project-review/v1"),
		baseline: z
			.object({ directory: Relative, inventory_sha256: Hash })
			.strict(),
		candidate: z
			.object({ directory: Relative, inventory_sha256: Hash })
			.strict(),
		approved_changes: z
			.array(
				z
					.object({
						path: Relative,
						before_sha256: Hash.nullable(),
						after_sha256: Hash.nullable(),
					})
					.strict()
					.refine(
						(c) => c.before_sha256 !== c.after_sha256,
						"Change must alter, add or remove exact file bytes",
					),
			)
			.max(256),
	})
	.strict();
type FileEntry = { path: string; bytes: number; sha256: string };
type Inventory = {
	files: FileEntry[];
	sha256: string;
	stamps: string[];
	bytes: number;
};
const MAX_FILES = 4096,
	MAX_FILE = 16 * 1024 * 1024,
	MAX_BYTES = 64 * 1024 * 1024;
const order = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
export function projectInventoryHash(files: FileEntry[]) {
	return candidateHash(
		JSON.stringify({
			protocol: "cline-project-inventory/v1",
			files: [...files].sort((a, b) => order(a.path, b.path)),
		}),
	);
}
const contains = (parent: string, child: string) => {
	const rel = path.relative(parent, child);
	return (
		!rel ||
		(!path.isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${path.sep}`))
	);
};
const stamp = (s: import("node:fs").Stats) =>
	[s.dev, s.ino, s.mode, s.nlink, s.size, s.mtimeMs, s.ctimeMs].join(":");
/** All regular file bytes, no ignores or execution. Repeated scans are not an OS sandbox. */
export async function reviewProjectFiles(
	manifestPath: string,
	raw: unknown,
	signal?: AbortSignal,
	inventoryOnly = false,
) {
	signal?.throwIfAborted();
	const request = inventoryOnly
		? ProjectInventoryRequestSchema.parse(raw)
		: undefined;
	const manifest = request
		? {
				protocol: "cline-project-review/v1",
				baseline: {
					directory: request.baseline_directory,
					inventory_sha256: "",
				},
				candidate: {
					directory: request.candidate_directory,
					inventory_sha256: "",
				},
				approved_changes: [],
			}
		: ProjectReviewManifestSchema.parse(raw);
	await rejectCandidateLinks(manifestPath);
	const base = await fs.realpath(path.dirname(manifestPath));
	const resolveRoot = async (relative: string) => {
		const root = path.resolve(base, ...relative.split("/"));
		if (!contains(base, root) || root === base)
			throw Error("Project root must be below manifest directory");
		await rejectCandidateLinks(root);
		const real = await fs.realpath(root),
			s = await fs.lstat(root);
		if (!s.isDirectory() || real !== root)
			throw Error("Project root must be a real directory without aliases");
		return real;
	};
	const beforeRoot = await resolveRoot(manifest.baseline.directory),
		afterRoot = await resolveRoot(manifest.candidate.directory);
	if (contains(beforeRoot, afterRoot) || contains(afterRoot, beforeRoot))
		throw Error("Baseline and candidate project roots must be disjoint");
	const approved = new Map<
			string,
			(typeof manifest.approved_changes)[number]
		>(),
		approvedAliases = new Set<string>();
	for (const c of manifest.approved_changes) {
		const alias = c.path.toLowerCase();
		if (approvedAliases.has(alias))
			throw Error("Duplicate or case-ambiguous approved path");
		approvedAliases.add(alias);
		approved.set(c.path, c);
	}
	const snapshot = async (
		root: string,
		budget: { bytes: number },
	): Promise<Inventory> => {
		const files: FileEntry[] = [],
			stamps: string[] = [],
			names = new Set<string>();
		let entries = 0,
			bytes = 0;
		const directoryNames = async (dir: string, countEntries: boolean) => {
			const stream = await fs.opendir(dir, { bufferSize: 32 });
			const found: string[] = [];
			try {
				while (true) {
					signal?.throwIfAborted();
					const entry = await stream.read();
					if (!entry) break;
					if (
						found.length >= MAX_FILES ||
						(countEntries && ++entries > MAX_FILES)
					)
						throw Error("Project entry budget exceeded");
					found.push(entry.name);
				}
			} finally {
				await stream.close();
			}
			return found.sort(order);
		};
		const walk = async (dir: string, prefix: string, depth: number) => {
			signal?.throwIfAborted();
			if (depth > 16) throw Error("Project depth budget exceeded");
			await rejectCandidateLinks(dir);
			const opened = await fs.lstat(dir);
			if (!opened.isDirectory()) throw Error("Project directory changed");
			const namesBefore = await directoryNames(dir, true);
			stamps.push(prefix + ":" + stamp(opened));
			for (const name of namesBefore) {
				signal?.throwIfAborted();
				const relative = prefix ? `${prefix}/${name}` : name;
				Relative.parse(relative);
				if (names.has(relative.toLowerCase()))
					throw Error("Case-ambiguous project paths");
				names.add(relative.toLowerCase());
				const full = path.join(dir, name),
					s = await fs.lstat(full);
				if (s.isSymbolicLink()) throw Error("Project links are unsupported");
				if (s.isDirectory()) {
					await walk(full, relative, depth + 1);
					continue;
				}
				if (!s.isFile() || s.nlink !== 1)
					throw Error("Only distinct regular project files are supported");
				if (s.size > MAX_FILE || budget.bytes + s.size > MAX_BYTES)
					throw Error("Project byte budget exceeded");
				await rejectCandidateLinks(full);
				const handle = await fs.open(
					full,
					constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
				);
				try {
					const initial = await handle.stat();
					if (!initial.isFile() || stamp(initial) !== stamp(s))
						throw Error("Project file identity changed");
					const data = Buffer.alloc(s.size + 1);
					let used = 0;
					while (used < data.length) {
						signal?.throwIfAborted();
						const part = await handle.read(
							data,
							used,
							data.length - used,
							used,
						);
						if (!part.bytesRead) break;
						used += part.bytesRead;
					}
					signal?.throwIfAborted();
					if (
						used !== s.size ||
						stamp(await handle.stat()) !== stamp(initial) ||
						stamp(await fs.lstat(full)) !== stamp(initial)
					)
						throw Error("Project file changed during read");
					budget.bytes += used;
					bytes += used;
					files.push({
						path: relative,
						bytes: used,
						sha256: candidateHash(data.subarray(0, used)),
					});
					stamps.push(relative + ":" + stamp(initial));
				} finally {
					await handle.close();
				}
			}
			if (
				JSON.stringify(namesBefore) !==
					JSON.stringify(await directoryNames(dir, false)) ||
				stamp(await fs.lstat(dir)) !== stamp(opened)
			)
				throw Error("Project directory changed during inventory");
		};
		await walk(root, "", 0);
		files.sort((a, b) => order(a.path, b.path));
		return { files, sha256: projectInventoryHash(files), stamps, bytes };
	};
	signal?.throwIfAborted();
	const budget = { bytes: 0 },
		before = await snapshot(beforeRoot, budget),
		after = await snapshot(afterRoot, budget);
	if (
		!inventoryOnly &&
		(before.sha256 !== manifest.baseline.inventory_sha256 ||
			after.sha256 !== manifest.candidate.inventory_sha256)
	)
		throw Error(
			"Project inventory fingerprint changed or does not match manifest",
		);
	const beforeFiles = new Map(before.files.map((f) => [f.path, f.sha256])),
		afterFiles = new Map(after.files.map((f) => [f.path, f.sha256]));
	const paths = [
			...new Set([...beforeFiles.keys(), ...afterFiles.keys()]),
		].sort(order),
		changes: Array<{
			path: string;
			kind: string;
			before_sha256: string | null;
			after_sha256: string | null;
			approved: boolean;
		}> = [];
	for (const file of paths) {
		const a = beforeFiles.get(file) ?? null,
			b = afterFiles.get(file) ?? null;
		if (a === b) continue;
		const allow = approved.get(file);
		changes.push({
			path: file,
			kind: a === null ? "added" : b === null ? "removed" : "changed",
			before_sha256: a,
			after_sha256: b,
			approved:
				!!allow && allow.before_sha256 === a && allow.after_sha256 === b,
		});
	}
	const missingApprovals = [...approved.keys()].filter(
		(p) => !changes.some((c) => c.path === p),
	);
	// Re-read all file contents and directory identities before claiming scope completion.
	const finalBudget = { bytes: 0 },
		beforeAgain = await snapshot(beforeRoot, finalBudget),
		afterAgain = await snapshot(afterRoot, finalBudget);
	if (
		beforeAgain.sha256 !== before.sha256 ||
		afterAgain.sha256 !== after.sha256 ||
		JSON.stringify(beforeAgain.stamps) !== JSON.stringify(before.stamps) ||
		JSON.stringify(afterAgain.stamps) !== JSON.stringify(after.stamps)
	)
		throw Error("Project mutated during review; no passing scope receipt");
	signal?.throwIfAborted();
	if (inventoryOnly)
		return {
			protocol: "cline-project-file-inventory/v1",
			status: changes.length > 256 ? "blocked" : "previewed-not-approved",
			published: false,
			observedExecution: false,
			baselineInventorySha256: before.sha256,
			candidateInventorySha256: after.sha256,
			baselineFiles: before.files.length,
			candidateFiles: after.files.length,
			bytesPerPass: budget.bytes,
			passes: 2,
			changedFiles: changes.length,
			proposedManifest:
				changes.length > 256
					? null
					: {
							protocol: "cline-project-review/v1",
							baseline: {
								directory: manifest.baseline.directory,
								inventory_sha256: before.sha256,
							},
							candidate: {
								directory: manifest.candidate.directory,
								inventory_sha256: after.sha256,
							},
							approved_changes: changes.map(
								({ path, before_sha256, after_sha256 }) => ({
									path,
									before_sha256,
									after_sha256,
								}),
							),
						},
			limitations: [
				"Read-only inventory draft, not approval or a passing change review. No manifest is written. Inspect every proposed changed path/hash; any selected manifest publication and subsequent review require separate approvals.",
				"More than 256 actual changes blocks a complete draft; never silently truncate an approval allowlist.",
				"All regular file bytes/relative names including dotfiles; empty directories, metadata, ACLs/alternate streams/runtime behavior and hostile-filesystem races remain outside scope.",
			],
		};
	return {
		protocol: "cline-project-file-review/v1",
		status:
			changes.every((c) => c.approved) && missingApprovals.length === 0
				? "completed"
				: "failed",
		published: false,
		observedExecution: false,
		baselineInventorySha256: before.sha256,
		candidateInventorySha256: after.sha256,
		baselineFiles: before.files.length,
		candidateFiles: after.files.length,
		bytesPerPass: budget.bytes,
		passes: 2,
		changedFiles: changes.length,
		unexpectedChanges: changes.filter((c) => !c.approved).length,
		missingDeclaredChanges: missingApprovals,
		changes: changes.slice(0, 200),
		truncated: changes.length > 200,
		limitations: [
			"All regular file contents and relative names under the two exact bounded roots, including dotfiles; no ignore rules. Empty directories, permissions, timestamps, ACLs, alternate streams and runtime behavior are not reviewed.",
			"Read-only repeated filesystem scans detect ordinary mutations, not a hostile-filesystem sandbox or atomic snapshot. Inventory hashes establish byte identity, not producer authentication or human approval.",
			"No writes, builds, signing, installation, shell, file execution, network, automatic repair or replay.",
		],
	};
}
