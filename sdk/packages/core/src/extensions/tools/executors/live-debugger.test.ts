import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createLiveDebuggerExecutor } from "./live-debugger";

const originalPath = process.env.PATH;
const directories: string[] = [];
afterEach(async () => {
	process.env.PATH = originalPath;
	await Promise.all(
		directories
			.splice(0)
			.map((entry) => fs.rm(entry, { recursive: true, force: true })),
	);
});

it("discovers and invokes a supervised one-shot debugger", async () => {
	if (process.platform === "win32") return;
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), "cline-debugger-"));
	directories.push(directory);
	const gdb = path.join(directory, "gdb");
	await fs.writeFile(gdb, '#!/bin/sh\nprintf "%s\\n" "$@"\n', { mode: 0o700 });
	process.env.PATH = `${directory}${path.delimiter}${originalPath ?? ""}`;
	const target = path.join(directory, "sample program");
	await fs.writeFile(target, "sample", { mode: 0o700 });
	const execute = createLiveDebuggerExecutor();
	const discovery = JSON.parse(
		await execute(
			{ operation: "discover", debugger: "auto", target_kind: "local" },
			{} as never,
		),
	);
	expect(
		discovery.backends.find(
			(entry: { backend: string }) => entry.backend === "gdb",
		).command,
	).toBe("gdb");
	const result = JSON.parse(
		await execute(
			{
				operation: "launch",
				debugger: "gdb",
				target_kind: "local",
				target,
				acknowledge_risk: true,
			},
			{} as never,
		),
	);
	expect(result.exitCode).toBe(0);
	expect(result.args).toEqual(expect.arrayContaining(["--args", target]));
});

it("requires explicit risk acknowledgement", async () => {
	await expect(
		createLiveDebuggerExecutor()(
			{
				operation: "backtrace",
				debugger: "auto",
				target_kind: "local",
				pid: 123,
			},
			{} as never,
		),
	).rejects.toThrow("acknowledge_risk=true");
});
