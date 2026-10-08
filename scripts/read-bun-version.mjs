import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

export function supportedBunVersion(packageJson) {
	const match = /^bun@(\d+\.\d+\.\d+)$/.exec(packageJson.packageManager ?? "");
	if (!match || packageJson.engines?.bun !== match[1])
		throw new Error("packageManager and engines.bun must name the same exact supported Bun version");
	return match[1];
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	console.log(supportedBunVersion(JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"))));
}