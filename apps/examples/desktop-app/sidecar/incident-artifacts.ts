import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";
import { inflateRawSync } from "node:zlib";
export const digest = (value: string | Uint8Array) =>
	createHash("sha256").update(value).digest("hex");
export const MAX_CONTAINER = 64 * 1024 * 1024;
export async function ownedFile(
	root: string,
	input: string,
	limit = MAX_CONTAINER,
) {
	const base = await realpath(root),
		path = await realpath(resolve(base, input)),
		child = relative(base, path);
	if (!child || isAbsolute(child) || child.split(/[\\/]/).includes(".."))
		throw new Error("Artifact must be an existing workspace file");
	const handle = await open(
		path,
		constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
	);
	try {
		const st = await handle.stat();
		if (!st.isFile() || st.size > limit)
			throw new Error("Artifact byte budget exceeded");
		const bytes = Buffer.alloc(st.size);
		let readBytes = 0;
		while (readBytes < st.size) {
			const read = await handle.read(
				bytes,
				readBytes,
				st.size - readBytes,
				readBytes,
			);
			if (!read.bytesRead) break;
			readBytes += read.bytesRead;
		}
		if (readBytes !== st.size || (await handle.stat()).size !== st.size)
			throw new Error("Artifact changed while reading");
		if (bytes.length !== st.size || bytes.length > limit)
			throw new Error("Artifact changed while reading");
		return { path, bytes, sha256: digest(bytes), size: bytes.length };
	} finally {
		await handle.close();
	}
}
function range(b: Buffer, at: number, size: number) {
	if (!Number.isSafeInteger(at) || at < 0 || size < 0 || at + size > b.length)
		throw new Error("Invalid container bounds");
}
function crc32(b: Buffer) {
	let crc = 0xffffffff;
	for (const value of b) {
		crc ^= value;
		for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
	}
	return (crc ^ 0xffffffff) >>> 0;
}
export type ArchiveMember = {
	name: string;
	bytes: number;
	compressedBytes: number;
	offset: number;
	flags: number;
	method: number;
	crc: number;
	safe: boolean;
};
export function archiveMembers(b: Buffer): ArchiveMember[] {
	let eocd = -1;
	for (let at = b.length - 22; at >= Math.max(0, b.length - 65557); at--)
		if (
			b.readUInt32LE(at) === 0x06054b50 &&
			at + 22 + b.readUInt16LE(at + 20) === b.length
		) {
			eocd = at;
			break;
		}
	if (eocd < 0) throw new Error("Not a supported ZIP container");
	if (
		b.readUInt16LE(eocd + 4) ||
		b.readUInt16LE(eocd + 6) ||
		b.readUInt16LE(eocd + 8) !== b.readUInt16LE(eocd + 10)
	)
		throw new Error("Split ZIP unsupported");
	const count = b.readUInt16LE(eocd + 10),
		length = b.readUInt32LE(eocd + 12),
		start = b.readUInt32LE(eocd + 16);
	if (
		count === 65535 ||
		count > 10000 ||
		length > 8 * 1024 * 1024 ||
		start + length > eocd
	)
		throw new Error("ZIP64/directory budget unsupported");
	range(b, start, length);
	let at = start;
	const rows: ArchiveMember[] = [],
		seen = new Set<string>(),
		counts = new Map<string, number>();
	for (let i = 0; i < count; i++) {
		range(b, at, 46);
		if (b.readUInt32LE(at) !== 0x02014b50)
			throw new Error("Invalid central directory");
		const n = b.readUInt16LE(at + 28),
			extra = b.readUInt16LE(at + 30),
			comment = b.readUInt16LE(at + 32);
		range(b, at + 46, n + extra + comment);
		const name = b.subarray(at + 46, at + 46 + n).toString("utf8"),
			normalized = name.replaceAll("\\", "/");
		const flags = b.readUInt16LE(at + 8),
			method = b.readUInt16LE(at + 10),
			mode = b.readUInt32LE(at + 38) >>> 16;
		const safe =
			!!name &&
			((flags & 2048) !== 0 || /^[\x20-\x7e]+$/.test(name)) &&
			!/^[\\/]|^[A-Za-z]:/.test(name) &&
			!normalized.split("/").some((p) => p === ".." || p === ".") &&
			!Array.from(name).some(
				(c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127,
			) &&
			!seen.has(normalized) &&
			(mode & 0xf000) !== 0xa000 &&
			!(flags & 1) &&
			[0, 8].includes(method) &&
			!name.endsWith("/");
		rows.push({
			name,
			bytes: b.readUInt32LE(at + 24),
			compressedBytes: b.readUInt32LE(at + 20),
			offset: b.readUInt32LE(at + 42),
			flags,
			method,
			crc: b.readUInt32LE(at + 16),
			safe,
		});
		seen.add(normalized);
		counts.set(normalized, (counts.get(normalized) ?? 0) + 1);
		at += 46 + n + extra + comment;
	}
	if (at !== start + length) throw new Error("Directory size mismatch");
	// All duplicate aliases are blocked, including the first occurrence.
	return rows.map((row) => ({
		...row,
		safe: row.safe && (counts.get(row.name.replaceAll("\\", "/")) ?? 0) === 1,
	}));
}
export function archiveRead(b: Buffer, name: string, limit = 2 * 1024 * 1024) {
	const matches = archiveMembers(b).filter((r) => r.name === name);
	if (matches.length !== 1 || !matches[0].safe)
		throw new Error("Unsafe, encrypted or ambiguous archive member");
	const r = matches[0];
	if (
		r.bytes > limit ||
		r.compressedBytes > limit ||
		r.bytes > Math.max(1024, r.compressedBytes * 200)
	)
		throw new Error("Archive member expansion budget exceeded");
	range(b, r.offset, 30);
	if (
		b.readUInt32LE(r.offset) !== 0x04034b50 ||
		b.readUInt16LE(r.offset + 6) !== r.flags ||
		b.readUInt16LE(r.offset + 8) !== r.method
	)
		throw new Error("Local header mismatch");
	const nl = b.readUInt16LE(r.offset + 26),
		el = b.readUInt16LE(r.offset + 28);
	range(b, r.offset + 30, nl + el);
	if (b.subarray(r.offset + 30, r.offset + 30 + nl).toString("utf8") !== name)
		throw new Error("Member name mismatch");
	const at = r.offset + 30 + nl + el;
	let directoryOffset = -1;
	for (let e = b.length - 22; e >= Math.max(0, b.length - 65557); e--)
		if (
			b.readUInt32LE(e) === 0x06054b50 &&
			e + 22 + b.readUInt16LE(e + 20) === b.length
		) {
			directoryOffset = b.readUInt32LE(e + 16);
			break;
		}
	if (r.offset >= directoryOffset || at + r.compressedBytes > directoryOffset)
		throw new Error("Member overlaps central directory");
	range(b, at, r.compressedBytes);
	const source = b.subarray(at, at + r.compressedBytes),
		bytes =
			r.method === 0
				? Buffer.from(source)
				: inflateRawSync(source, { maxOutputLength: limit });
	if (bytes.length !== r.bytes || crc32(bytes) !== r.crc)
		throw new Error("Archive member integrity mismatch");
	return {
		bytes,
		sha256: digest(bytes),
		source: "archive-member-not-standalone-file" as const,
	};
}
/** Android binary XML manifest: bounded string pool and package attribute only. */
export function apkPackage(apk: Buffer): string {
	const b = archiveRead(apk, "AndroidManifest.xml").bytes;
	if (b.length < 8 || b.readUInt16LE(0) !== 3 || b.readUInt32LE(4) !== b.length)
		throw new Error("Binary Android manifest required");
	let strings: string[] = [],
		at = b.readUInt16LE(2);
	while (at < b.length) {
		range(b, at, 8);
		const type = b.readUInt16LE(at),
			head = b.readUInt16LE(at + 2),
			size = b.readUInt32LE(at + 4);
		if (head < 8 || size < head) throw new Error("Manifest chunk bounds");
		range(b, at, size);
		if (type === 1) {
			range(b, at, 28);
			const count = b.readUInt32LE(at + 8),
				flags = b.readUInt32LE(at + 16),
				offset = b.readUInt32LE(at + 20);
			if (
				count > 10000 ||
				head < 28 ||
				head + count * 4 > size ||
				offset < head + count * 4
			)
				throw new Error("Manifest pool budget");
			strings = Array.from({ length: count }, (_, i) => {
				let p = at + offset + b.readUInt32LE(at + head + i * 4);
				range(b, p, 2);
				const len8 = () => {
					range(b, p, 1);
					const n = b[p++];
					if (n & 128) {
						range(b, p, 1);
						return ((n & 127) << 8) | b[p++];
					}
					return n;
				};
				if (flags & 256) {
					len8();
					const n = len8();
					range(b, p, n + 1);
					if (p + n + 1 > at + size || b[p + n] !== 0)
						throw new Error("UTF8 pool bounds");
					return b.subarray(p, p + n).toString("utf8");
				}
				let n = b.readUInt16LE(p);
				p += 2;
				if (n & 32768) {
					range(b, p, 2);
					n = (n & 32767) * 65536 + b.readUInt16LE(p);
					p += 2;
				}
				range(b, p, n * 2 + 2);
				if (p + n * 2 + 2 > at + size || b.readUInt16LE(p + n * 2) !== 0)
					throw new Error("UTF16 pool bounds");
				return b.subarray(p, p + n * 2).toString("utf16le");
			});
		}
		if (type === 0x102) {
			range(b, at, 36);
			if (strings[b.readUInt32LE(at + 20)] === "manifest") {
				const attrs = at + 16 + b.readUInt16LE(at + 24),
					width = b.readUInt16LE(at + 26),
					count = b.readUInt16LE(at + 28);
				if (
					head !== 16 ||
					attrs < at + 36 ||
					width < 20 ||
					count > 1000 ||
					attrs + width * count > at + size
				)
					throw new Error("Manifest attribute bounds");
				for (let i = 0; i < count; i++) {
					const a = attrs + i * width;
					if (strings[b.readUInt32LE(a + 4)] !== "package") continue;
					const raw = b.readUInt32LE(a + 8),
						typed = b.readUInt32LE(a + 16),
						value = strings[raw === 0xffffffff ? typed : raw];
					if (
						(raw === 0xffffffff && b[a + 15] !== 3) ||
						!/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/.test(value ?? "")
					)
						throw new Error("Invalid package identity");
					return value;
				}
			}
		}
		at += size;
	}
	throw new Error("Package identity missing");
}
export async function inspectArtifactEvidence(root: string, path: string) {
	const base = await realpath(root),
		resolved = resolve(base, path),
		child = relative(base, resolved);
	if (/^(https?:|content:|ssh:)/i.test(path))
		return {
			path,
			workspace: base,
			classification: "remote-reference",
			size: 0,
			sha256: undefined,
			blockedReason: "Remote references are not local workspace files",
			members: undefined,
			membersTruncated: false,
		};
	if (!child || isAbsolute(child) || child.split(/[\\/]/).includes(".."))
		throw new Error("Evidence file must belong to originating workspace");
	let f: Awaited<ReturnType<typeof ownedFile>>;
	try {
		f = await ownedFile(root, path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT")
			return {
				path: resolved,
				workspace: base,
				classification: "missing-file",
				size: 0,
				sha256: undefined,
				blockedReason:
					"No standalone file exists at this path; archive members require selecting their container",
				members: undefined,
				membersTruncated: false,
			};
		throw error;
	}
	let members: ArchiveMember[] | undefined;
	let blockedReason: string | undefined;
	try {
		members = archiveMembers(f.bytes);
	} catch (error) {
		if (
			/\.(zip|apk|jar|xlsx|docx|pptx)$/i.test(path) ||
			f.bytes.subarray(0, 2).toString() === "PK"
		)
			blockedReason =
				error instanceof Error ? error.message : "Unsupported archive";
	}
	return {
		path: f.path,
		workspace: await realpath(root),
		sha256: f.sha256,
		size: f.size,
		classification: members
			? "archive-container"
			: blockedReason
				? "blocked-archive"
				: "standalone-file",
		blockedReason,
		members: members
			?.slice(0, 200)
			.map(({ name, bytes, safe }) => ({ name, bytes, safe })),
		membersTruncated: !!members && members.length > 200,
	};
}
export async function previewArchiveMember(
	root: string,
	path: string,
	member: string,
	expectedHash: string,
) {
	if (!/^[a-f0-9]{64}$/.test(expectedHash))
		throw new Error("Expected SHA-256 required");
	if (member.length > 2048) throw new Error("Member name budget");
	const f = await ownedFile(root, path);
	if (f.sha256 !== expectedHash)
		throw new Error("Archive changed since inspection");
	const r = archiveRead(f.bytes, member);
	const text = /\.(md|txt|json|xml|csv|log|ya?ml|smali|java|js|ts)$/i.test(
		member,
	);
	return {
		path: f.path,
		member,
		containerSha256: f.sha256,
		sha256: r.sha256,
		size: r.bytes.length,
		classification: r.source,
		kind: text ? "text" : "metadata",
		content: text ? r.bytes.toString("utf8") : undefined,
		reason: text
			? undefined
			: "Binary archive member: hash/size only. No extraction or execution performed.",
	};
}
