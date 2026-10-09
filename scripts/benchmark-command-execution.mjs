import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { cpus, hostname, release } from "node:os";
import { dirname } from "node:path";
import { createShellExecutor } from "../sdk/packages/core/dist/index.js";
import { comparePerformance } from "./performance-budget.mjs";
import { readFile } from "node:fs/promises";

/** Fixed owned workload through the real shared executor; never target code. */
export async function benchmarkCommandExecution(samples = 7) {
	if (!Number.isInteger(samples) || samples < 3 || samples > 20)
		throw new Error("Benchmark sample count must be 3..20");
	const shell = createShellExecutor({ timeoutMs: 10000 });
	const context = { agentId: "owned-command-benchmark", iteration: 1 };
	const script = "process.stdout.write('owned-ready')";
	const quote = value => process.platform === "win32"
		? `'${value.replaceAll("'", "''")}'`
		: `'${value.replaceAll("'", "'\\''")}'`;
	const shellCommand = process.platform === "win32"
		? `& ${quote(process.execPath)} -e ${quote(script)}; exit $LASTEXITCODE`
		: `${quote(process.execPath)} -e ${quote(script)}`;
	const metrics = { ownedDirectReadyMs: [], ownedShellReadyMs: [] };
	for (let index = -1; index < samples; index++) {
		// Alternate order to reduce a consistent warm-cache ordering advantage.
		const modes = index % 2 === 0 ? ["direct","shell"] : ["shell","direct"];
		for (const mode of modes) {
			const start = performance.now();
			const output = await shell(mode === "direct"
				? { command: process.execPath, args: ["-e", script] }
				: shellCommand, process.cwd(), context);
			if (output.trim() !== "owned-ready") throw new Error("Owned benchmark execution failed");
			if (index >= 0) metrics[mode === "direct" ? "ownedDirectReadyMs" : "ownedShellReadyMs"].push(performance.now() - start);
		}
	}
	return {
		schemaVersion: 1,
		sourceCommit: process.env.GITHUB_SHA ?? "local-working-tree",
		environmentId: createHash("sha256").update(JSON.stringify({
			host: hostname(), platform: process.platform, arch: process.arch,
			os: release(), cpu: cpus()[0]?.model, runtime: process.version,
		})).digest("hex"),
		workloadVersion: "owned-shared-executor-ready/v1",
		metrics,
		units: "milliseconds",
		limitations: [
			"Fixed native runtime startup through the shared executor; not installed UI startup, model latency or target-analysis speed.",
			"One warmup discarded; alternating execution order. Compare only the same hardware, runtime and workload.",
		],
	};
}
if (process.argv[1]?.endsWith("benchmark-command-execution.mjs")) {
	const output = process.argv[process.argv.indexOf("--out") + 1];
	if (!process.argv.includes("--out") || !output) throw new Error("--out required");
	const measured = await benchmarkCommandExecution();
	const baselineIndex = process.argv.indexOf("--baseline");
	const baseline = baselineIndex >= 0
		? JSON.parse(await readFile(process.argv[baselineIndex + 1], "utf8")) : undefined;
	const comparison = comparePerformance(measured, baseline);
	await mkdir(dirname(output), {recursive:true});
	await writeFile(output, JSON.stringify({ ...measured, comparison }, null, 2));
	console.log(`Owned command performance: ${comparison.status}`);
	if (comparison.status === "failed") process.exitCode = 1;
}