import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";
// Build-time budgets only. These never widen target execution or AppContainer policy.
export const ISOLATION_BUILD_BUDGET = {
	hostMs: 90000,
	runtimeMs: 120000,
	totalMs: 240000,
} as const;
export function isolationCompileFailure(
	stage: "host" | "runtime",
	result: {
		status: number | null;
		signal: string | null;
		error?: { code?: string };
		stdout?: string | null;
		stderr?: string | null;
	},
) {
	const status = Number.isSafeInteger(result.status)
		? String(result.status)
		: "none";
	const signal = ["SIGTERM", "SIGKILL", "SIGABRT", "SIGINT"].includes(
		result.signal ?? "",
	)
		? result.signal
		: "none";
	const timedOut = result.error?.code === "ETIMEDOUT";
	const output = (value: unknown, limit: number) =>
		typeof value === "string" ? value.slice(0, limit) : "";
	return new Error(
		`Isolation ${stage} compile failed: status=${status} signal=${signal} timedOut=${timedOut} stdout=${output(result.stdout, 4000)} stderr=${output(result.stderr, 1000)}`,
	);
}
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
		{ encoding: "utf8", timeout: ISOLATION_BUILD_BUDGET.hostMs },
	);
	if (compiled.status !== 0) throw isolationCompileFailure("host", compiled);
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
		{ encoding: "utf8", timeout: ISOLATION_BUILD_BUDGET.runtimeMs },
	);
	if (runner.status !== 0) throw isolationCompileFailure("runtime", runner);
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
