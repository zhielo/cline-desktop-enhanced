import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import {
	commandAvailable,
	launchDetachedGui,
	runSupervised,
} from "./supervised-process";

async function script(body: string, windowsBody: string) {
	const directory = await fs.mkdtemp(
		path.join(os.tmpdir(), "cline-supervisor space-"),
	);
	const target = path.join(
		directory,
		process.platform === "win32" ? "tool with spaces.exe" : "tool with spaces",
	);
	const args: string[] = [];
	if (process.platform === "win32") {
		await fs.copyFile(process.execPath, target);
		const entry = path.join(directory, "owned-fixture.cjs");
		await fs.writeFile(entry, windowsBody);
		args.push(entry);
	} else await fs.writeFile(target, `#!/bin/sh\n${body}\n`, { mode: 0o700 });
	return { directory, target, args };
}

describe("supervised process lifecycle", () => {
	it("accepts executable paths with spaces and drains final output", async () => {
		const fixture = await script(
			'printf "first\\n"; printf "final\\n"',
			'process.stdout.write("first\\nfinal\\n")',
		);
		try {
			expect(await commandAvailable(fixture.target)).toBe(true);
			const result = await runSupervised(fixture.target, fixture.args, 5_000);
			expect(result.exitCode).toBe(0);
			expect(result.stdout).toBe("first\nfinal\n");
		} finally {
			await fs.rm(fixture.directory, { recursive: true, force: true });
		}
	});

	it("reports an immediately failing GUI instead of optimistic success", async () => {
		const fixture = await script("exit 7", "process.exit(7)");
		try {
			const result = await launchDetachedGui(
				fixture.target,
				fixture.args,
				5_000,
			);
			expect(result).toMatchObject({
				launched: false,
				status: "exited_early",
				exitCode: 7,
			});
		} finally {
			await fs.rm(fixture.directory, { recursive: true, force: true });
		}
	});

	it("marks timed-out process groups", async () => {
		const fixture = await script("sleep 30", "setInterval(() => {}, 1000)");
		try {
			const result = await runSupervised(fixture.target, fixture.args, 50);
			expect(result.timedOut).toBe(true);
		} finally {
			await fs.rm(fixture.directory, { recursive: true, force: true });
		}
	});
});

it("bounds orphan-inherited output handles rather than hanging after parent exit", async () => {
	if (process.platform === "win32") return; // Windows native Job Object fixture covers owned descendant termination.
	const result = await runSupervised(
		process.execPath,
		[
			"-e",
			`require('child_process').spawn(process.execPath,['-e','setTimeout(()=>{},30000)'],{stdio:['ignore','inherit','inherit']});process.exit(0)`,
		],
		10000,
	);
	expect(result.outputDrainTimedOut).toBe(true);
	expect(result.exitCode).toBe(0);
}, 15000);
it("preserves split UTF-8 and redacts retained credential output", async () => {
	const result = await runSupervised(
		process.execPath,
		[
			"-e",
			`process.stdout.write(Buffer.from([0xe2]));setTimeout(()=>{process.stdout.write(Buffer.from([0x82,0xac]));process.stdout.write(' token=ownedsecret')},20)`,
		],
		5000,
	);
	expect(result.stdout).toContain("€");
	expect(result.stdout).not.toContain("ownedsecret");
});
