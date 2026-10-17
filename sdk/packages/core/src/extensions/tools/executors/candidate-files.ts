import { createHash, randomUUID } from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
export const candidateHash = (data: Uint8Array | string) =>
	createHash("sha256").update(data).digest("hex");
export async function rejectCandidateLinks(file: string, missingLeaf = false) {
	if (!path.isAbsolute(file))
		throw new Error("Absolute candidate paths required");
	let current = path.resolve(file),
		leaf = true;
	for (;;) {
		try {
			if ((await fs.lstat(current)).isSymbolicLink())
				throw new Error("Candidate path contains a symbolic link");
		} catch (e) {
			if (
				!(leaf && missingLeaf && (e as NodeJS.ErrnoException).code === "ENOENT")
			)
				throw e;
		}
		const parent = path.dirname(current);
		if (parent === current) break;
		current = parent;
		leaf = false;
	}
}
export async function readCandidateFile(
	file: string,
	maxBytes = 16 * 1024 * 1024,
	signal?: AbortSignal,
) {
	signal?.throwIfAborted();
	await rejectCandidateLinks(file);
	const handle = await fs.open(file, "r");
	try {
		const stat = await handle.stat();
		if (!stat.isFile() || stat.size > maxBytes)
			throw new Error("Candidate input exceeds regular-file byte budget");
		const bytes = Buffer.alloc(Math.min(stat.size + 1, maxBytes + 1));
		let used = 0;
		while (used < bytes.length) {
			signal?.throwIfAborted();
			const r = await handle.read(bytes, used, bytes.length - used, used);
			if (!r.bytesRead) break;
			used += r.bytesRead;
		}
		if (used !== stat.size)
			throw new Error("Input changed size during bounded read");
		return bytes.subarray(0, used);
	} finally {
		await handle.close();
	}
}
export async function assertNewCandidate(source: string, output: string) {
	if (!path.isAbsolute(output) || path.resolve(source) === path.resolve(output))
		throw new Error("Choose a distinct absolute new candidate output_file");
	await rejectCandidateLinks(output, true);
	try {
		await fs.lstat(output);
		throw new Error("Candidate output exists; no overwrite permitted");
	} catch (e) {
		if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
	}
}
export async function publishCandidate(
	source: string,
	output: string,
	expectedHash: string,
	bytes: Buffer,
	signal?: AbortSignal,
) {
	await assertNewCandidate(source, output);
	if (
		candidateHash(await readCandidateFile(source, 16 * 1024 * 1024, signal)) !==
		expectedHash
	)
		throw new Error("Source changed before publication");
	let published = false,
		cleanupWarning: string | undefined;
	const temp = path.join(
		path.dirname(output),
		`.cline-candidate-${randomUUID()}.tmp`,
	);
	try {
		const f = await fs.open(temp, "wx", 0o600);
		try {
			await f.writeFile(bytes);
			await f.sync();
		} finally {
			await f.close();
		}
		signal?.throwIfAborted();
		await rejectCandidateLinks(output, true);
		await fs.link(temp, output);
		published = true; // Atomic no-clobber; no overwrite fallback.
	} finally {
		try {
			await fs.rm(temp, { force: true });
		} catch {
			// Preserve the original publication error if publication failed.
			if (published)
				cleanupWarning =
					"Candidate published, but private temporary hard-link cleanup failed; inspect candidate directory.";
		}
	}
	return { cleanupWarning };
}
