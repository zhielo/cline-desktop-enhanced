import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";
export function buildJavaScriptIsolation(output: string) {
	if (process.platform !== "win32" || process.arch !== "x64")
		throw new Error("Windows x64 AppContainer build host required");
	mkdirSync(output, { recursive: true });
	const source = resolve(import.meta.dir, "../native/JavaScriptIsolation.cs");
	const compiler = join(
		process.env.SystemRoot ?? "C:\\Windows",
		"Microsoft.NET",
		"Framework64",
		"v4.0.30319",
		"csc.exe",
	);
	const host = join(output, "javascript-isolation-host.exe"),
		runtime = join(output, "javascript-isolation-runtime.exe");
	const compiled = spawnSync(
		compiler,
		[
			"/nologo",
			"/platform:x64",
			"/target:exe",
			"/reference:System.Web.Extensions.dll",
			`/out:${host}`,
			source,
		],
		{ encoding: "utf8", timeout: 30000 },
	);
	if (compiled.status !== 0)
		throw new Error(
			`AppContainer host compile failed: ${compiled.stdout.slice(0, 4000)} ${compiled.stderr.slice(0, 1000)}`,
		);
	const runner = spawnSync(
		process.execPath,
		[
			"build",
			resolve(import.meta.dir, "../sidecar/javascript-isolation-entry.ts"),
			"--compile",
			"--target=bun-windows-x64",
			"--no-compile-autoload-dotenv",
			"--no-compile-autoload-bunfig",
			"--outfile",
			runtime,
		],
		{ encoding: "utf8", timeout: 120000 },
	);
	if (runner.status !== 0)
		throw new Error(
			`Standalone runtime compile failed: ${runner.stderr.slice(0, 2000)}`,
		);
	const manifest = {
		schemaVersion: 1,
		profile: "cline-js-appcontainer/1",
		files: Object.fromEntries(
			[host, runtime].map((file) => [
				file.endsWith("host.exe")
					? "javascript-isolation-host.exe"
					: "javascript-isolation-runtime.exe",
				createHash("sha256").update(readFileSync(file)).digest("hex"),
			]),
		),
	};
	writeFileSync(join(output, "manifest.json"), JSON.stringify(manifest) + "\n");
	return createHash("sha256")
		.update(readFileSync(join(output, "manifest.json")))
		.digest("hex");
}
if (import.meta.main)
	console.log(
		buildJavaScriptIsolation(
			resolve(process.argv[2] ?? "src-tauri/bin/javascript-isolation"),
		),
	);
