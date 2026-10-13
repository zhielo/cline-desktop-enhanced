import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { cpus, hostname, release } from "node:os";
import { dirname } from "node:path";
import { pathToFileURL } from "node:url";
import { createShellExecutor } from "../sdk/packages/core/dist/index.js";
import { comparePerformance } from "./performance-budget.mjs";

// Match the shared executor's production default, not a separate 10 s startup gate.
export const COMMAND_TIMEOUT_MS = 30000;
const workloadVersion = "owned-shared-executor-ready/v2";

/** Fixed owned workload through the real shared executor; never target code. */
export async function benchmarkCommandExecution(
	samples = 7,
	execute = createShellExecutor({ timeoutMs: COMMAND_TIMEOUT_MS }),
) {
	if (!Number.isInteger(samples) || samples < 3 || samples > 20)
		throw new Error("Benchmark sample count must be 3..20");
	const script = "process.stdout.write('owned-ready')";
	const quote = (value) =>
		process.platform === "win32"
			? `'${value.replaceAll("'", "''")}'`
			: `'${value.replaceAll("'", "'\\''")}'`;
	const shellCommand =
		process.platform === "win32"
			? `& ${quote(process.execPath)} -e ${quote(script)}; exit $LASTEXITCODE`
			: `${quote(process.execPath)} -e ${quote(script)}`;
	const report = {
		schemaVersion: 2,
		status: "completed",
		sourceCommit: process.env.GITHUB_SHA ?? "local-working-tree",
		environmentId: createHash("sha256")
			.update(
				JSON.stringify({
					host: hostname(),
					platform: process.platform,
					arch: process.arch,
					os: release(),
					cpu: cpus()[0]?.model,
					runtime: process.version,
				}),
			)
			.digest("hex"),
		workloadVersion,
		policy: {
			commandTimeoutMs: COMMAND_TIMEOUT_MS,
			samplesPerMode: samples,
			warmupsPerMode: 1,
		},
		metrics: { ownedDirectReadyMs: [], ownedShellReadyMs: [] },
		attempts: [],
		units: "milliseconds",
		limitations: [
			"Fixed native runtime startup through the shared executor; not installed UI startup, model latency or target-analysis speed.",
			"One warmup per mode retained separately, excluded from metrics; alternating order. Compare only the same hardware, runtime and workload.",
			"A 30-second execution deadline is not a performance target or proof of improvement; incomplete runs fail and are never compared.",
		],
	};
	for (let index = -1; index < samples; index++) {
		const modes = index % 2 === 0 ? ["direct", "shell"] : ["shell", "direct"];
		for (const mode of modes) {
			const start = performance.now();
			const attempt = {
				phase: index < 0 ? "warmup" : "sample",
				index,
				mode,
				status: "completed",
				elapsedMs: 0,
			};
			try {
				const output = await execute(
					mode === "direct"
						? { command: process.execPath, args: ["-e", script] }
						: shellCommand,
					process.cwd(),
					{ agentId: "owned-command-benchmark", iteration: 1 },
				);
				attempt.elapsedMs = performance.now() - start;
				if (output.trim() !== "owned-ready") {
					attempt.status = "unexpected-output";
				}
			} catch (error) {
				attempt.elapsedMs = performance.now() - start;
				// Never retain exception messages, environment, command paths or raw output.
				attempt.status =
					error?.name === "TimeoutError" ? "timed-out" : "execution-failed";
			}
			report.attempts.push(attempt);
			if (attempt.status !== "completed") {
				report.status = "failed";
				return report; // No retry, replacement sample or fabricated latency.
			}
			if (index >= 0)
				report.metrics[
					mode === "direct" ? "ownedDirectReadyMs" : "ownedShellReadyMs"
				].push(attempt.elapsedMs);
		}
	}
	return report;
}

export function assessBenchmark(measured, baseline) {
	if (measured.status !== "completed")
		return {
			status: "failed",
			reason:
				"Owned workload did not complete; partial samples are not comparable",
		};
	try {
		return comparePerformance(measured, baseline);
	} catch {
		return {
			status: "failed",
			reason: "Invalid or incomparable performance baseline",
		};
	}
}

if (
	process.argv[1] &&
	import.meta.url === pathToFileURL(process.argv[1]).href
) {
	const output = process.argv[process.argv.indexOf("--out") + 1];
	if (!process.argv.includes("--out") || !output)
		throw new Error("--out required");
	const measured = await benchmarkCommandExecution();
	let comparison;
	try {
		const baselineIndex = process.argv.indexOf("--baseline");
		const baseline =
			baselineIndex >= 0
				? JSON.parse(await readFile(process.argv[baselineIndex + 1], "utf8"))
				: undefined;
		comparison = assessBenchmark(measured, baseline);
	} catch {
		comparison = {
			status: "failed",
			reason: "Performance baseline could not be read",
		};
	}
	await mkdir(dirname(output), { recursive: true });
	await writeFile(output, JSON.stringify({ ...measured, comparison }, null, 2));
	const failed = measured.attempts.find(
		(attempt) => attempt.status !== "completed",
	);
	console.log(
		`Owned command performance: ${comparison.status}${failed ? `; ${failed.phase}/${failed.mode}/${failed.index}: ${failed.status} (${Math.round(failed.elapsedMs)} ms)` : ""}`,
	);
	if (comparison.status === "failed") process.exitCode = 1;
}
