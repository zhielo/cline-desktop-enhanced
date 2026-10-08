import { createHash } from "node:crypto";
import { readdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
const root = resolve(process.argv[2] ?? "");
if (!process.argv[2]) throw new Error("Runtime root required");
const files: Record<string, string> = {};
async function walk(directory: string, prefix = "") {
	for (const entry of await readdir(directory, { withFileTypes: true })) {
		const name = `${prefix}${entry.name}`;
		if (entry.isSymbolicLink()) throw new Error("Runtime links forbidden");
		if (entry.isDirectory())
			await walk(join(directory, entry.name), `${name}/`);
		else if (entry.isFile() && name !== "runtime-manifest.json")
			files[name] = createHash("sha256")
				.update(await readFile(join(directory, entry.name)))
				.digest("hex");
	}
}
await walk(root);
const distributions = [];
for (const entry of await readdir(join(root, "Lib/site-packages"))) {
	if (!entry.endsWith(".dist-info")) continue;
	const metadata = await readFile(
		join(root, "Lib/site-packages", entry, "METADATA"),
		"utf8",
	);
	distributions.push({
		name: /^Name: (.+)$/m.exec(metadata)?.[1],
		version: /^Version: (.+)$/m.exec(metadata)?.[1],
		licenseFiles: Object.keys(files).filter(
			(p) =>
				p.startsWith(`Lib/site-packages/${entry}/`) &&
				/license|copying|notice/i.test(p),
		),
	});
}
const manifest = {
	schemaVersion: 1,
	runtimeId: "cpython-3.13.12-windows-x64-v1",
	pythonVersion: "3.13.12",
	platform: "win32",
	archiveSha256:
		"76f238f606250c87c6beac75dccd35ee99070a13490555936abb6cb64ecce3d0",
	fixtureVersion: "analysis-readiness/v1",
	distributions,
	files,
};
await writeFile(
	join(root, "runtime-manifest.json"),
	JSON.stringify(manifest, null, 2) + "\n",
);
console.log(
	`Runtime manifest: ${Object.keys(files).length} files; ${distributions.length} distributions (licenses retained).`,
);
