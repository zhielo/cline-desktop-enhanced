import { readFile, readdir } from "node:fs/promises";
import { resolve, relative, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
const root = fileURLToPath(
	new URL(
		"../sdk/packages/core/src/analysis/semantic-engine/upstream/",
		import.meta.url,
	),
);
const manifest = JSON.parse(
	await readFile(resolve(root, "PROVENANCE.json"), "utf8"),
);
if (
	manifest.revision !== "d0067ba34a39ea47dd7e11bb2e6169bc0938cc3f" ||
	manifest.license !== "MIT"
)
	throw Error("Unexpected provenance");
const expected = new Set(["PROVENANCE.json", "LICENSE"]);
for (const file of manifest.files) {
	const path = resolve(root, file.path),
		rel = relative(root, path);
	if (rel.startsWith("..") || isAbsolute(rel) || expected.has(file.path))
		throw Error("Invalid source path");
	expected.add(file.path);
	const hash = createHash("sha256")
		.update(await readFile(path))
		.digest("hex");
	if (hash !== (file.localSha256 ?? file.sha256))
		throw Error(`Source digest mismatch: ${file.path}`);
	if (file.localSha256 && !file.adaptation)
		throw Error("Undocumented source adaptation");
}
async function scan(dir) {
	for (const entry of await readdir(dir, { withFileTypes: true })) {
		const path = resolve(dir, entry.name);
		if (entry.isSymbolicLink()) throw Error("Linked source not allowed");
		if (entry.isDirectory()) await scan(path);
		else if (!expected.has(relative(root, path).replaceAll("\\", "/")))
			throw Error(`Untracked port source: ${path}`);
	}
}
await scan(root);
const license = await readFile(resolve(root, "LICENSE"), "utf8");
if (!license.includes("Copyright (c) 2026 morluto"))
	throw Error("Missing attribution");
console.log(
	`Semantic source provenance passed: ${manifest.files.length} files; no REA runtime installed.`,
);
