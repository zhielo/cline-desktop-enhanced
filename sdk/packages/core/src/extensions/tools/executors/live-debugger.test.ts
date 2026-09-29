import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { LiveDebuggerInputSchema } from "../schemas";
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

it("requires separate confirmation before resuming execution", async () => {
	await expect(
		createLiveDebuggerExecutor()(
			{
				operation: "continue",
				debugger: "auto",
				target_kind: "local",
				pid: 123,
				acknowledge_risk: true,
			},
			{} as never,
		),
	).rejects.toThrow("confirm_execution_control=true");
});

it("inspects Windows minidump metadata without launching the target", async () => {
	const directory = await fs.mkdtemp(path.join(os.tmpdir(), "cline-minidump-"));
	directories.push(directory);
	const dump = path.join(directory, "sample.dmp");
	const header = Buffer.alloc(32);
	header.write("MDMP", 0, "ascii");
	header.writeUInt32LE(0x0000a793, 4);
	header.writeUInt32LE(3, 8);
	header.writeUInt32LE(32, 12);
	header.writeUInt32LE(1_700_000_000, 20);
	header.writeBigUInt64LE(2n, 24);
	await fs.writeFile(dump, header);
	const result = JSON.parse(
		await createLiveDebuggerExecutor()(
			{
				operation: "inspect_dump",
				debugger: "auto",
				target_kind: "local",
				target: dump,
			},
			{} as never,
		),
	);
	expect(result.metadata).toMatchObject({
		signature: "MDMP",
		streamCount: 3,
		streamDirectoryRva: 32,
		flags: "0x2",
	});
	if (result.debuggerAvailable === false) {
		expect(result.hint).toContain("cdb.exe");
	} else {
		expect(result.backend).toBe("cdb");
	}
	await expect(
		createLiveDebuggerExecutor()(
			{
				operation: "inspect_dump",
				debugger: "auto",
				target_kind: "local",
				target: dump,
				symbol_path: "srv*cache;quit",
			},
			{} as never,
		),
	).rejects.toThrow("symbol_path");
});

describe("debugger location validation", () => {
	it("accepts bounded symbols and addresses", () => {
		for (const breakpoint of ["main", "Namespace::method", "0x401000"]) {
			expect(
				LiveDebuggerInputSchema.parse({
					operation: "launch",
					target: "/tmp/sample",
					breakpoint,
				}).breakpoint,
			).toBe(breakpoint);
		}
	});

	it("rejects breakpoint values that could introduce debugger commands", () => {
		for (const breakpoint of [
			"main; shell whoami",
			"main\nshell whoami",
			"main -ex quit",
		]) {
			expect(() =>
				LiveDebuggerInputSchema.parse({
					operation: "launch",
					target: "/tmp/sample",
					breakpoint,
				}),
			).toThrow();
		}
	});
});
