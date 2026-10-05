import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { z } from "zod";
import type { AdvancedResult } from "./advanced-analysis";

export const REVIEWED_RIZIN_PACKS = {
	"rizin-0.9.1-linux-x64": {
		platform: "linux",
		entry: "bin/rizin",
		sha256: "9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf",
	},
	"rizin-0.9.1-windows-x64": {
		platform: "win32",
		entry: "rizin-win-installer-clang_cl-64/bin/rizin.exe",
		sha256: "45ffa004e26653eaee8d262b8e6eeae09402a7d319c1f20a2ba794bd6af1cc28",
	},
} as const;
const PackId = z.enum(["rizin-0.9.1-linux-x64", "rizin-0.9.1-windows-x64"]);
const Hash = z.string().regex(/^[a-f0-9]{64}$/);
const Identity = z.object({ packId: PackId, receiptSha256: Hash }).strict();
const Registry = z
	.object({
		schemaVersion: z.literal(1),
		active: Identity.nullable(),
		history: z.array(Identity.nullable()).max(16),
	})
	.strict();
const Receipt = z
	.object({
		schemaVersion: z.literal(1),
		packId: PackId,
		archiveSha256: Hash,
		entry: z.string().max(1024),
		sourceUrl: z.string().max(2048),
		health: z
			.object({
				version: z.literal("0.9.1"),
				ownedStaticBytes: z.literal(true),
				targetExecuted: z.literal(false),
			})
			.strict(),
		files: z
			.array(
				z
					.object({
						path: z.string().min(1).max(1024),
						bytes: z.number().int().min(0).max(1073741824),
						sha256: Hash,
					})
					.strict(),
			)
			.min(1)
			.max(4096),
		licenseNotice: z.string().max(4096),
	})
	.strict();
export function safePackPath(name: string) {
	const parts = name.split("/");
	if (
		name.length > 1024 ||
		/[\\:]/.test(name) ||
		name.includes(String.fromCharCode(0)) ||
		parts.some(
			(p) =>
				!p ||
				p === "." ||
				p === ".." ||
				/[ .]$/.test(p) ||
				/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(p),
		)
	)
		throw new Error("Unsafe managed pack path");
	return name;
}
async function boundedFile(
	path: string,
	max: number,
	deadline: number,
	signal?: AbortSignal,
) {
	if (signal?.aborted || Date.now() >= deadline)
		throw new Error("Managed pack verification cancelled or timed out");
	const f = await open(
		path,
		constants.O_RDONLY |
			(process.platform === "win32"
				? 0
				: constants.O_NOFOLLOW | constants.O_NONBLOCK),
	);
	try {
		const before = await f.stat();
		if (!before.isFile() || before.size > max)
			throw new Error("Managed pack file byte budget exceeded");
		const hash = createHash("sha256"),
			chunks: Buffer[] = [];
		const buffer = Buffer.alloc(Math.min(65536, max + 1));
		let bytes = 0;
		for (;;) {
			if (signal?.aborted || Date.now() >= deadline)
				throw new Error("Managed pack verification cancelled or timed out");
			const part = await f.read(buffer, 0, buffer.length, null);
			if (!part.bytesRead) break;
			bytes += part.bytesRead;
			if (bytes > max)
				throw new Error("Managed pack file byte budget exceeded");
			const data = buffer.subarray(0, part.bytesRead);
			hash.update(data);
			if (max <= 1048576) chunks.push(Buffer.from(data));
		}
		const after = await f.stat();
		if (
			before.size !== bytes ||
			before.size !== after.size ||
			before.mtimeMs !== after.mtimeMs
		)
			throw new Error("Managed pack changed during verification");
		return {
			bytes,
			sha256: hash.digest("hex"),
			text: max <= 1048576 ? Buffer.concat(chunks).toString("utf8") : undefined,
		};
	} finally {
		await f.close();
	}
}
export async function managedRizinStatus(
	root: string | undefined,
	signal?: AbortSignal,
) {
	if (!root)
		return {
			status: "unconfigured" as const,
			entry: undefined,
			healthIsImportTimeOnly: true,
		};
	if (!isAbsolute(root) || (await realpath(root)) !== resolve(root))
		throw new Error("Canonical absolute managed pack root required");
	const metadata = await lstat(root);
	if (
		!metadata.isDirectory() ||
		metadata.isSymbolicLink() ||
		(process.platform !== "win32" &&
			((metadata.mode & 0o077) !== 0 ||
				(process.getuid && metadata.uid !== process.getuid())))
	)
		throw new Error("Private host-owned managed pack root required");
	const deadline = Date.now() + 30000;
	const reg = Registry.parse(
		JSON.parse(
			(await boundedFile(join(root, "active.json"), 65536, deadline, signal))
				.text ?? "",
		),
	);
	if (!reg.active)
		return {
			status: "inactive" as const,
			entry: undefined,
			healthIsImportTimeOnly: true,
		};
	const spec = REVIEWED_RIZIN_PACKS[reg.active.packId];
	if (process.platform !== spec.platform || process.arch !== "x64")
		throw new Error("Managed pack platform mismatch");
	const revision = join(root, "revisions", reg.active.packId),
		payload = join(revision, "payload");
	for (const directory of [join(root, "revisions"), revision, payload])
		if (
			(await realpath(directory)) !== resolve(directory) ||
			(await lstat(directory)).isSymbolicLink()
		)
			throw new Error("Managed revision path link forbidden");
	const raw = await boundedFile(
		join(revision, "receipt.json"),
		1048576,
		deadline,
		signal,
	);
	if (raw.sha256 !== reg.active.receiptSha256)
		throw new Error("Managed receipt hash mismatch");
	const receipt = Receipt.parse(JSON.parse(raw.text ?? ""));
	if (
		receipt.packId !== reg.active.packId ||
		receipt.archiveSha256 !== spec.sha256 ||
		receipt.entry !== spec.entry
	)
		throw new Error("Managed receipt identity mismatch");
	const expected = new Set<string>();
	let total = 0;
	for (const file of receipt.files) {
		const name = safePackPath(file.path);
		if (expected.has(name.toLowerCase()))
			throw new Error("Duplicate managed pack path");
		expected.add(name.toLowerCase());
		total += file.bytes;
		if (total > 1073741824)
			throw new Error("Managed pack expansion budget exceeded");
	}
	let visited = 0;
	const actual = new Set<string>();
	async function walk(path: string, prefix: string) {
		if (signal?.aborted || Date.now() >= deadline)
			throw new Error("Managed pack verification cancelled or timed out");
		for (const item of await readdir(path, { withFileTypes: true })) {
			if (++visited > 8192 || item.isSymbolicLink())
				throw new Error("Managed pack links or inventory overrun");
			const name = `${prefix}${item.name}`;
			safePackPath(name);
			if (item.isDirectory()) await walk(join(path, item.name), `${name}/`);
			else if (item.isFile()) {
				if (actual.has(name.toLowerCase()))
					throw new Error("Duplicate installed managed path");
				actual.add(name.toLowerCase());
			} else throw new Error("Managed pack special file forbidden");
		}
	}
	await walk(payload, "");
	if (
		actual.size !== expected.size ||
		[...actual].some((name) => !expected.has(name))
	)
		throw new Error("Managed pack inventory mismatch");
	if (!receipt.files.some((file) => file.path === spec.entry))
		throw new Error("Managed engine missing from inventory");
	for (const file of receipt.files) {
		const result = await boundedFile(
			join(payload, file.path),
			file.bytes,
			deadline,
			signal,
		);
		if (result.bytes !== file.bytes || result.sha256 !== file.sha256)
			throw new Error("Managed pack file integrity mismatch");
	}
	return {
		status: "verified" as const,
		entry: join(payload, spec.entry),
		packId: receipt.packId,
		archiveSha256: receipt.archiveSha256,
		receiptSha256: raw.sha256,
		filesVerified: receipt.files.length,
		bytesVerified: total,
		health: receipt.health,
		healthIsImportTimeOnly: true,
	};
}
export async function resolveRizinTool(signal?: AbortSignal) {
	if (process.env.CLINE_RE_RIZIN) return process.env.CLINE_RE_RIZIN;
	return (await managedRizinStatus(process.env.CLINE_RE_TOOLPACK_ROOT, signal))
		.entry;
}
export async function managedToolPackResult(
	signal?: AbortSignal,
): Promise<AdvancedResult> {
	const status = await managedRizinStatus(
		process.env.CLINE_RE_TOOLPACK_ROOT,
		signal,
	);
	return {
		protocol: "cline-advanced-analysis/v1",
		status: status.status === "verified" ? "completed" : "blocked",
		engine: "managed-rizin-packs",
		engineVersion: "reviewed-offline-pack/v1",
		evidence: status,
		limitations: [
			"Read-only full-file integrity verification, not a current engine execution probe or measured containment.",
			"Only Rizin 0.9.1 packs are managed. Python is required for explicit offline host installation; engines are not installer-bundled.",
			"Local hashes do not authenticate metadata against privileged or non-cooperating host tampering. Windows ACLs remain a host responsibility.",
		],
	};
}
