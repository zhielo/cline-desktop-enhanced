import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
	assessBenchmark,
	benchmarkCommandExecution,
	COMMAND_TIMEOUT_MS,
} from "./benchmark-command-execution.mjs";
import { comparePerformance } from "./performance-budget.mjs";

test("records fixed owned attempts, excludes warmups and alternates sample ordering", async () => {
	const calls = [];
	const measured = await benchmarkCommandExecution(3, async (command) => {
		calls.push(command);
		return "owned-ready";
	});
	expect(COMMAND_TIMEOUT_MS).toBe(30000);
	expect(measured.status).toBe("completed");
	expect(measured.workloadVersion).toBe("owned-shared-executor-ready/v2");
	expect(measured.policy).toEqual({
		commandTimeoutMs: 30000,
		samplesPerMode: 3,
		warmupsPerMode: 1,
	});
	expect(measured.attempts.map((a) => a.mode)).toEqual([
		"shell",
		"direct",
		"direct",
		"shell",
		"shell",
		"direct",
		"direct",
		"shell",
	]);
	expect(measured.attempts.filter((a) => a.phase === "warmup")).toHaveLength(2);
	expect(measured.metrics.ownedDirectReadyMs).toHaveLength(3);
	expect(measured.metrics.ownedShellReadyMs).toHaveLength(3);
	expect(calls).toHaveLength(8);
	expect(
		calls
			.filter((c) => typeof c !== "string")
			.every(
				(c) =>
					c.command === process.execPath &&
					c.args[0] === "-e" &&
					c.args[1] === "process.stdout.write('owned-ready')",
			),
	).toBe(true);
	expect(assessBenchmark(measured)).toMatchObject({
		status: "baseline-required",
	});
});

test("retains a warmup timeout as failed evidence, never retrying or inventing samples", async () => {
	let calls = 0;
	const measured = await benchmarkCommandExecution(3, async () => {
		calls++;
		throw Object.assign(new Error("API_KEY=secret and private-path"), {
			name: "TimeoutError",
		});
	});
	expect(calls).toBe(1);
	expect(measured.status).toBe("failed");
	expect(measured.attempts).toHaveLength(1);
	expect(measured.attempts[0]).toMatchObject({
		phase: "warmup",
		mode: "shell",
		index: -1,
		status: "timed-out",
	});
	expect(measured.metrics.ownedShellReadyMs).toHaveLength(0);
	expect(measured.metrics.ownedDirectReadyMs).toHaveLength(0);
	expect(JSON.stringify(measured)).not.toContain("secret");
	expect(JSON.stringify(measured)).not.toContain("private-path");
	expect(assessBenchmark(measured).status).toBe("failed");
});

test("stops on a measured timeout with bounded partial evidence and no replacement sample", async () => {
	let calls = 0;
	const measured = await benchmarkCommandExecution(3, async () => {
		if (++calls === 4)
			throw Object.assign(new Error("discard"), { name: "TimeoutError" });
		return "owned-ready";
	});
	expect(calls).toBe(4);
	expect(measured.attempts.at(-1)).toMatchObject({
		phase: "sample",
		mode: "shell",
		index: 0,
		status: "timed-out",
	});
	expect(measured.metrics.ownedDirectReadyMs).toHaveLength(1);
	expect(measured.metrics.ownedShellReadyMs).toHaveLength(0);
	expect(assessBenchmark(measured).status).toBe("failed");
});

test("unexpected owned output fails without retaining its value", async () => {
	const measured = await benchmarkCommandExecution(
		3,
		async () => "secret-content",
	);
	expect(measured.attempts[0].status).toBe("unexpected-output");
	expect(JSON.stringify(measured)).not.toContain("secret-content");
	expect(assessBenchmark(measured).status).toBe("failed");
});

test("valid complete metrics cannot make a failed candidate or baseline comparable", () => {
	const complete = {
		status: "completed",
		environmentId: "owned",
		workloadVersion: "v2",
		metrics: { ready: [1, 2, 3] },
	};
	expect(() =>
		comparePerformance({ ...complete, status: "failed" }, complete),
	).toThrow("Incomplete");
	expect(() =>
		comparePerformance(complete, { ...complete, status: "failed" }),
	).toThrow("Incomplete");
	expect(
		assessBenchmark(complete, { ...complete, workloadVersion: "v1" }).status,
	).toBe("failed");
});

test("rejects invalid sample counts without invoking owned execution", async () => {
	let calls = 0;
	for (const samples of [0, 2, 21, 3.5, NaN])
		await expect(
			benchmarkCommandExecution(samples, async () => {
				calls++;
				return "owned-ready";
			}),
		).rejects.toThrow();
	expect(calls).toBe(0);
});

test("CLI persists completed or partial evidence before applying its failure exit", () => {
	const source = readFileSync(
		new URL("./benchmark-command-execution.mjs", import.meta.url),
		"utf8",
	);
	expect(source.indexOf("await writeFile(output")).toBeLessThan(
		source.indexOf('if (comparison.status === "failed") process.exitCode = 1'),
	);
	expect(source).toContain("measured.attempts.find");
	const executor = readFileSync(
		new URL(
			"../sdk/packages/core/src/extensions/tools/executors/bash.ts",
			import.meta.url,
		),
		"utf8",
	);
	expect(executor).toContain("timeoutMs = 30000");
});
