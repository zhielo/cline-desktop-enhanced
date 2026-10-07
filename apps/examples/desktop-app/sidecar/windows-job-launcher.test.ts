import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { expect, it } from "vitest";
import {
	WINDOWS_JOB_SOURCE,
	windowsJobInvocation,
} from "./windows-job-launcher";

it("uses suspended launch before assignment and has no hard-limit fallback", () => {
	expect(WINDOWS_JOB_SOURCE.indexOf("if(!CreateProcess")).toBeLessThan(
		WINDOWS_JOB_SOURCE.indexOf("if(!AssignProcess"),
	);
	expect(WINDOWS_JOB_SOURCE.indexOf("if(!AssignProcess")).toBeLessThan(
		WINDOWS_JOB_SOURCE.indexOf("if(ResumeThread"),
	);
	if (process.platform !== "win32")
		expect(() => windowsJobInvocation("node", [], "/tmp", 512, 4)).toThrow(
			"no silent",
		);
});
it.runIf(process.platform === "win32")(
	"launches a real Windows job and preserves spaced native argv",
	async () => {
		const root = await mkdtemp(join(tmpdir(), "native job fixture "));
		try {
			const invocation = windowsJobInvocation(
					process.execPath,
					[
						"-e",
						"process.stdout.write(JSON.stringify(process.argv.slice(1)))",
						"space value",
						'quote"value',
						"tail\\",
					],
					root,
					512,
					4,
				),
				result = await promisify(execFile)(
					invocation.executable,
					invocation.args,
					{ cwd: root, timeout: 30000, maxBuffer: 65536 },
				);
			expect(JSON.parse(result.stdout)).toEqual([
				"space value",
				'quote"value',
				"tail\\",
			]);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	},
	40000,
);
it.runIf(process.platform === "win32")(
	"enforces active-process limits rather than reporting logical limits",
	async () => {
		const invocation = windowsJobInvocation(
				process.execPath,
				[
					"-e",
					"require('child_process').spawn(process.execPath,['-e','process.exit(0)']).on('error',()=>process.stdout.write('job-limit-enforced'))",
				],
				process.cwd(),
				512,
				1,
			),
			result = await promisify(execFile)(
				invocation.executable,
				invocation.args,
				{ timeout: 30000, maxBuffer: 65536 },
			);
		expect(result.stdout).toContain("job-limit-enforced");
	},
	40000,
);
