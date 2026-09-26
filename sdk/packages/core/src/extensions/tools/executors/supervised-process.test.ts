import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import {
	commandAvailable,
	launchDetachedGui,
	runSupervised,
} from "./supervised-process";

async function script(body: string) {
	const directory = await fs.mkdtemp(
		path.join(os.tmpdir(), "cline-supervisor space-"),
	);
	const target = path.join(directory, "tool with spaces");
	await fs.writeFile(target, `#!/bin/sh\n${body}\n`, { mode: 0o700 });
	return { directory, target };
}

describe("supervised process lifecycle", () => {
	it("accepts executable paths with spaces and drains final output", async () => {
		const fixture = await script('printf "first\\n"; printf "final\\n"');
		try {
			expect(await commandAvailable(fixture.target)).toBe(true);
			const result = await runSupervised(fixture.target, [], 5_000);
			expect(result.exitCode).toBe(0);
			expect(result.stdout).toBe("first\nfinal\n");
		} finally {
			await fs.rm(fixture.directory, { recursive: true, force: true });
		}
	});

	it("reports an immediately failing GUI instead of optimistic success", async () => {
		const fixture = await script("exit 7");
		try {
			const result = await launchDetachedGui(fixture.target, [], 300);
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
		const fixture = await script("sleep 30");
		try {
			const result = await runSupervised(fixture.target, [], 50);
			expect(result.timedOut).toBe(true);
		} finally {
			await fs.rm(fixture.directory, { recursive: true, force: true });
		}
	});
});
