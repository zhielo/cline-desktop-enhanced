import { createHash } from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";

/** Shared byte fingerprint for existing Android builders and reviewed snapshots. */
export async function scanAndroidProject(
	directory: string,
	options: { signal?: AbortSignal; copyTo?: string } = {},
) {
	if ((await fs.lstat(directory)).isSymbolicLink())
		throw new Error("Android project root must not be a symbolic link");
	if (!(await fs.lstat(directory)).isDirectory())
		throw new Error("Android project must be a directory");
	const hash = createHash("sha256"),
		roots: string[] = [];
	let entries = 0,
		bytes = 0,
		files = 0;
	if (options.copyTo) await fs.mkdir(options.copyTo, { mode: 0o700 });
	const visit = async (current: string, depth = 0): Promise<void> => {
		options.signal?.throwIfAborted();
		if (depth > 48) throw new Error("Android directory depth budget exceeded");
		const names = [];
		const dir = await fs.opendir(current);
		for await (const entry of dir) {
			if (++entries > 25000)
				throw new Error("Android directory entry budget exceeded");
			names.push(entry);
		}
		names.sort((a, b) => a.name.localeCompare(b.name));
		for (const entry of names) {
			options.signal?.throwIfAborted();
			const absolute = path.join(current, entry.name),
				relative = path.relative(directory, absolute).replace(/\\/g, "/"),
				out = options.copyTo ? path.join(options.copyTo, relative) : undefined;
			const stat = await fs.lstat(absolute);
			if (stat.isSymbolicLink())
				throw new Error(
					"Symbolic links are not allowed in Smali/APK build inputs",
				);
			if (stat.isDirectory()) {
				hash.update(`D\0${relative}\0`);
				if (
					depth === 0 &&
					/^smali(?:_classes[2-9][0-9]*|_classes1[0-9]+)?$/.test(entry.name)
				)
					roots.push(entry.name);
				if (out) await fs.mkdir(out, { mode: 0o700 });
				await visit(absolute, depth + 1);
			} else if (stat.isFile()) {
				if (bytes + stat.size > 512 * 1024 * 1024)
					throw new Error("Android directory byte budget exceeded");
				hash.update(`F\0${relative}\0`);
				const source = await fs.open(absolute, "r");
				let dest: Awaited<ReturnType<typeof fs.open>> | undefined;
				try {
					const opened = await source.stat();
					if (!opened.isFile() || opened.size !== stat.size)
						throw new Error("Android input changed before read");
					if (out) dest = await fs.open(out, "wx", 0o600);
					const chunk = Buffer.alloc(65536);
					let read = 0;
					for (;;) {
						options.signal?.throwIfAborted();
						const r = await source.read(chunk, 0, chunk.length, null);
						if (!r.bytesRead) break;
						read += r.bytesRead;
						bytes += r.bytesRead;
						if (bytes > 512 * 1024 * 1024 || read > stat.size)
							throw new Error("Android input grew beyond byte budget");
						const data = chunk.subarray(0, r.bytesRead);
						hash.update(data);
						if (dest) await dest.writeFile(data);
					}
					if (read !== stat.size)
						throw new Error("Android input changed during read");
				} finally {
					await source.close();
					await dest?.close();
				}
				files++;
				hash.update("\0");
			} else
				throw new Error(
					"Android project contains a non-regular filesystem entry",
				);
		}
	};
	await visit(directory);
	return {
		sha256: hash.digest("hex"),
		entries,
		files,
		bytes,
		smaliRoots: roots,
	};
}
export async function sha256Directory(directory: string) {
	return (await scanAndroidProject(directory)).sha256;
}
