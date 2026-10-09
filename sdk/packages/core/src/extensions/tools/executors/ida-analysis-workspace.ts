import { createHash, randomUUID } from "node:crypto";
import { constants, createReadStream } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";

const POINTER = "cline-ida-database.json";
const MAX_DATABASE = 512 * 1024 * 1024;
async function fingerprint(file: string) {
	const info = await fs.lstat(file);
	if (
		!info.isFile() ||
		info.isSymbolicLink() ||
		info.size === 0 ||
		info.size > MAX_DATABASE
	)
		throw new Error("IDA database must be a bounded non-linked regular file");
	const digest = createHash("sha256");
	for await (const chunk of createReadStream(file)) digest.update(chunk);
	return digest.digest("hex");
}
/** Database compatibility deliberately excludes function selectors and output scripts. */
export function idaDatabaseKey(
	targetHash: string,
	engineHash: string | undefined,
	configHash: string | undefined,
) {
	return createHash("sha256")
		.update(
			JSON.stringify({
				schema: "ida-database/v1",
				targetHash,
				engineHash,
				configHash,
			}),
		)
		.digest("hex");
}
/** Called under the existing cross-process workspace lease. Never overwrite or delete prior databases. */
export async function prepareIdaAttempt(
	workspace: string,
	key: string,
	reuse: boolean,
) {
	const root = await fs.realpath(workspace);
	const attempt = await fs.mkdtemp(path.join(root, "ida-attempt-"));
	let reusedAnalysis = false;
	if (reuse) {
		try {
			const pointerFile = path.join(root, POINTER);
			const info = await fs.lstat(pointerFile);
			if (!info.isFile() || info.isSymbolicLink() || info.size > 8192)
				throw new Error("Invalid IDA pointer");
			const pointer = JSON.parse(await fs.readFile(pointerFile, "utf8"));
			if (
				pointer.schema !== "ida-database/v1" ||
				pointer.key !== key ||
				!/^ida-attempt-[A-Za-z0-9_-]+$/.test(pointer.attempt) ||
				!/^[a-f0-9]{64}$/.test(pointer.sha256)
			)
				throw new Error("Incompatible IDA database");
			const sourceDir = path.join(root, pointer.attempt);
			if (
				(await fs.lstat(sourceDir)).isSymbolicLink() ||
				(await fs.realpath(sourceDir)) !== sourceDir
			)
				throw new Error("Linked IDA database directory forbidden");
			const source = path.join(sourceDir, "analysis.i64");
			if ((await fingerprint(source)) !== pointer.sha256)
				throw new Error("IDA database integrity changed");
			await fs.copyFile(
				source,
				path.join(attempt, "analysis.i64"),
				constants.COPYFILE_EXCL,
			);
			// Verify the copied snapshot too. The prior accepted snapshot remains untouched.
			if (
				(await fingerprint(path.join(attempt, "analysis.i64"))) !==
				pointer.sha256
			)
				throw new Error("IDA database copy integrity changed");
			reusedAnalysis = true;
		} catch {
			// Invalid or stale snapshots cause a separate fresh attempt, not deletion/overwrite.
			// A partially copied file cannot become a fresh -o destination.
			if (
				await fs
					.lstat(path.join(attempt, "analysis.i64"))
					.catch(() => undefined)
			)
				return prepareIdaAttempt(workspace, key, false);
		}
	}
	return { outputDir: attempt, reusedAnalysis };
}
export async function publishIdaDatabase(
	workspace: string,
	attempt: string,
	key: string,
) {
	const root = await fs.realpath(workspace);
	const canonical = await fs.realpath(attempt);
	const name = path.basename(attempt);
	if (
		path.dirname(canonical) !== root ||
		canonical !== attempt ||
		!/^ida-attempt-[A-Za-z0-9_-]+$/.test(name)
	)
		throw new Error("Invalid IDA publication directory");
	const sha256 = await fingerprint(path.join(attempt, "analysis.i64"));
	const temporary = path.join(root, `${POINTER}.${randomUUID()}.tmp`);
	await fs.writeFile(
		temporary,
		JSON.stringify({ schema: "ida-database/v1", key, attempt: name, sha256 }),
		{ flag: "wx", mode: 0o600 },
	);
	await fs.rename(temporary, path.join(root, POINTER));
	return sha256;
}
