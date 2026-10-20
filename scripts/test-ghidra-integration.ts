// Real headless Ghidra acceptance on an owned ELF; never executes target code.
import { createHash } from "node:crypto";
import { mkdtemp, writeFile, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createReverseEngineeringExecutor } from "../sdk/packages/core/src/extensions/tools/executors/reverse-engineering";
import fixture from "./fixtures/owned-native-elf.json";
const root = await mkdtemp(join(tmpdir(), "cline ghidra acceptance-"));
const execute = createReverseEngineeringExecutor();
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
				],
				scope: "Owned x86-64 static fixture only; no target execution",
			},
			null,
			2,
		),
	);
} finally {
	await rm(root, { recursive: true, force: true });
}
