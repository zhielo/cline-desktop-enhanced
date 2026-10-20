// Real headless Ghidra acceptance on an owned ELF; never executes target code.
import { createHash } from "node:crypto";
import { mkdtemp, writeFile, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createReverseEngineeringExecutor } from "../sdk/packages/core/src/extensions/tools/executors/reverse-engineering";
import { ghidraAnalysisCacheRoot } from "../sdk/packages/core/src/extensions/tools/executors/ghidra-project-path";
import fixture from "./fixtures/owned-native-elf.json";
const root = await mkdtemp(join(tmpdir(), "cline ghidra acceptance-"));
const execute = createReverseEngineeringExecutor();
const previousCache = process.env.CLINE_RE_CACHE_DIR;
try {
	const target = join(root, "owned.so"),
		output = join(root, "project");
	const bytes = Buffer.from(fixture.base64, "base64");
	if (createHash("sha256").update(bytes).digest("hex") !== fixture.sha256)
		throw new Error("Owned fixture fingerprint mismatch");
	await writeFile(target, bytes);
	async function run(extra: Record<string, unknown> = {}) {
		const result = JSON.parse(
			await execute(
				{
					engine: "ghidra",
					operation: "analyze",
					target,
					output_directory: output,
					timeout_ms: 120000,
					max_cpu: 2,
					...extra,
				},
				{} as never,
			),
		);
		if (
			!result.succeeded ||
			!result.databaseVerified ||
			!result.artifactVerified ||
			result.sha256 !== fixture.sha256
		)
			throw new Error(
				`Ghidra owned acceptance failed: ${JSON.stringify(result)}`,
			);
		return result;
	}
	const first = await run();
	if (first.reusedAnalysis) throw new Error("Unexpected initial cache reuse");
	const second = await run();
	if (!second.reusedAnalysis) throw new Error("Expected exact-input reuse");
	const renamed = join(root, "renamed.so");
	await writeFile(renamed, bytes);
	const third = await run({ target: renamed });
	if (third.reusedAnalysis)
		throw new Error("Renamed program reused incompatible identity");
	const custom = join(root, "custom scripts");
	await mkdir(custom);
	const script = join(custom, "OwnedNoop.java");
	await writeFile(
		script,
		'import ghidra.app.script.GhidraScript; public class OwnedNoop extends GhidraScript { protected void run() { println("Owned no-op completed"); } }',
	);
	const fourth = await run({
		target: renamed,
		operation: "decompile",
		function_selector: { address: fixture.functionAddress },
		script_path: script,
	});
	if (
		!(await readFile(join(output, "decompiled.c"), "utf8")).includes("return")
	)
		throw new Error("Owned pseudocode missing");
	if (!fourth.stdout.includes("Owned no-op completed"))
		throw new Error("Second script directory was not executed");
	// Exercise the production default-root builder with an isolated owned home.
	// Previously the shared ~/.cline default failed before import.
	const cache = ghidraAnalysisCacheRoot(root, undefined);
	process.env.CLINE_RE_CACHE_DIR = cache;
	const cached = await run({ output_directory: undefined });
	if (
		cached.reusedAnalysis ||
		cached.outputDirectory !== join(cache, fixture.sha256, "ghidra")
	)
		throw new Error("Ghidra-specific persistent cache path was not used");
	const reused = await run({ output_directory: undefined });
	if (!reused.reusedAnalysis)
		throw new Error("Persistent Ghidra cache was not reused");
	try {
		await run({ output_directory: join(root, ".cline", "project") });
		throw new Error("Dot-prefixed Ghidra output was accepted");
	} catch (error) {
		if (!(error instanceof Error) || !error.message.includes("dot-prefixed"))
			throw error;
	}
	console.log(
		JSON.stringify(
			{
				status: "passed",
				engine: "ghidra",
				version: fourth.engineVersion,
				fixtureSha256: fixture.sha256,
				checks: [
					"fresh-project-receipt",
					"exact-program-cache-reuse",
					"renamed-program-reimport",
					"selected-decompilation-and-two-script-directories",
					"ghidra-specific-persistent-cache-and-reuse",
					"dot-prefixed-project-path-preflight",
				],
				scope: "Owned x86-64 static fixture only; no target execution",
			},
			null,
			2,
		),
	);
} finally {
	if (previousCache === undefined) delete process.env.CLINE_RE_CACHE_DIR;
	else process.env.CLINE_RE_CACHE_DIR = previousCache;
	await rm(root, { recursive: true, force: true });
}
