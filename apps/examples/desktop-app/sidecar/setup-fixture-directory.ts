import { mkdtemp, lstat, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, isAbsolute, sep } from "node:path";

/** Setup receipts stay durable; engine-owned test projects use the executor's
 * existing temporary-output boundary. Never broadens permitted output roots or
 * sets acknowledge_external_output on behalf of the user. */
export async function createSetupFixtureDirectory(engine: "ida" | "ghidra") {
	if (engine !== "ida" && engine !== "ghidra")
		throw new Error("Unsupported setup fixture engine");
	const parent = await realpath(tmpdir());
	const root = await mkdtemp(join(parent, `cline-owned-${engine}-`));
	const canonical = await realpath(root);
	const rel = relative(parent, canonical);
	const info = await lstat(root);
	if (
		!info.isDirectory() ||
		info.isSymbolicLink() ||
		!rel ||
		rel === ".." ||
		rel.startsWith(`..${sep}`) ||
		isAbsolute(rel)
	)
		throw new Error("Setup fixture escaped its private temporary directory");
	return canonical;
}
