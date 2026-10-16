/** Source-lock inventory, not a claim of complete binary/transitive composition. */
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import ts from "typescript";
import tools from "./binary-triage-tools.lock.json";

const output = process.argv[2];
if (!output) throw new Error("Output filename required");
const bunText = await readFile("bun.lock", "utf8");
const parsed = ts.parseConfigFileTextToJson("bun.lock", bunText);
if (parsed.error || !parsed.config?.packages)
	throw new Error("Invalid Bun lockfile");
const cargoText = await readFile(
	"apps/examples/desktop-app/src-tauri/Cargo.lock",
	"utf8",
);
const cargo = Bun.TOML.parse(cargoText) as {
	package: { name: string; version: string; checksum?: string }[];
};
const components = new Map<string, Record<string, unknown>>();
for (const value of Object.values(parsed.config.packages) as unknown[][]) {
	const pinned = value[0];
	if (typeof pinned !== "string") continue;
	const split = pinned.lastIndexOf("@");
	if (split < 1 || pinned.includes("workspace:")) continue;
	const name = pinned.slice(0, split),
		version = pinned.slice(split + 1);
	const purl = `pkg:npm/${name.replace("@", "%40")}@${encodeURIComponent(version)}`;
	components.set(purl, {
		type: "library",
		name,
		version,
		purl,
		"bom-ref": purl,
	});
}
for (const pkg of cargo.package) {
	const purl = `pkg:cargo/${pkg.name}@${pkg.version}`;
	components.set(purl, {
		type: "library",
		name: pkg.name,
		version: pkg.version,
		purl,
		"bom-ref": purl,
		...(pkg.checksum
			? { hashes: [{ alg: "SHA-256", content: pkg.checksum }] }
			: {}),
	});
}
for (const file of [
	"sdk/packages/core/scripts/requirements-advanced-windows.txt",
	"sdk/packages/core/scripts/requirements-advanced-full-windows.txt",
]) {
	for (const line of (await readFile(file, "utf8")).split(/\r?\n/)) {
		const match = line.match(/^([A-Za-z0-9_.-]+)==([^\s;#]+)/);
		if (!match) continue;
		const [, name, version] = match,
			purl = `pkg:pypi/${name.toLowerCase().replace(/_/g, "-")}@${version}`;
		components.set(purl, {
			type: "library",
			name,
			version,
			purl,
			"bom-ref": purl,
		});
	}
}
for (const tool of tools.tools)
	components.set(tool.id, {
		type: "application",
		name: tool.id,
		version: tool.version,
		"bom-ref": `binary-triage:${tool.id}`,
		hashes: [{ alg: "SHA-256", content: tool.sha256 }],
		externalReferences: [{ type: "distribution", url: tool.url }],
	});
await mkdir(dirname(output), { recursive: true });
await writeFile(
	output,
	JSON.stringify(
		{
			bomFormat: "CycloneDX",
			specVersion: "1.5",
			version: 1,
			metadata: {
				timestamp: new Date().toISOString(),
				component: {
					type: "application",
					name: "cline-desktop-enhanced",
					version: process.env.VERSION || "source-build",
				},
				properties: [
					{
						name: "cline:scope",
						value:
							"Source Bun/Cargo locks, pinned direct Windows Python requirements and Binary Triage archive inputs; not complete installed distribution or transitive Python/PyInstaller inventory. No dependency graph or license-completeness claim.",
					},
					{
						name: "cline:bun-lock-sha256",
						value: createHash("sha256").update(bunText).digest("hex"),
					},
					{
						name: "cline:cargo-lock-sha256",
						value: createHash("sha256").update(cargoText).digest("hex"),
					},
				],
			},
			components: Array.from(components.values()).sort((a, b) =>
				String(a["bom-ref"]).localeCompare(String(b["bom-ref"])),
			),
		},
		null,
		2,
	) + "\n",
);
console.log(`Wrote ${components.size} source inventory components`);
