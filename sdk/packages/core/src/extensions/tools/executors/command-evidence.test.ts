import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createShellExecutor } from "./bash";
import { createShellTool } from "../definitions";
import { inspectCommandArtifacts } from "./command-evidence";

const context = { agentId: "owned-command-evidence", iteration: 1 };
describe("structured command evidence", () => {
	it("keeps stderr warnings separate from actual failure and needs no streaming consumer", async () => {
		const tool = createShellTool(createShellExecutor());
		const [result] = await tool.execute(
			{
				commands: [
					{
						command: process.execPath,
						args: [
							"-e",
							"process.stdout.write('ok');process.stderr.write('warning')",
						],
					},
				],
			},
			context,
		);
		expect(result).toMatchObject({
			success: true,
			execution: {
				status: "completed",
				exitCode: 0,
				stdout: "ok",
				stderr: "warning",
			},
		});
	});
	it("preserves a failing native exit code and its stderr", async () => {
		const tool = createShellTool(createShellExecutor());
		const [result] = await tool.execute(
			{
				commands: [
					{
						command: process.execPath,
						args: [
							"-e",
							"process.stderr.write('owned failure');process.exit(7)",
						],
					},
				],
			},
			context,
		);
		expect(result).toMatchObject({
			success: false,
			execution: { status: "failed", exitCode: 7, stderr: "owned failure" },
		});
	});
	it("preflights missing inputs, validates fresh outputs and rejects stale files", async () => {
		const root = await mkdtemp(join(tmpdir(), "cline owned 中文 "));
		try {
			const marker = join(root, "artifact.txt");
			const tool = createShellTool(createShellExecutor(), { cwd: root });
			const command = {
				command: process.execPath,
				args: [
					"-e",
					"require('node:fs').writeFileSync('artifact.txt','owned')",
				],
			};
			const [missing] = await tool.execute(
				{ commands: [{ ...command, required_files: ["missing.so"] }] },
				context,
			);
			expect(missing).toMatchObject({ success: false });
			await expect(readFile(marker)).rejects.toThrow();
			const [written] = await tool.execute(
				{ commands: [{ ...command, expected_output_files: ["artifact.txt"] }] },
				context,
			);
			expect(written).toMatchObject({
				success: true,
				artifacts: [{ bytes: 5 }],
			});
			const [stale] = await tool.execute(
				{
					commands: [
						{
							command: process.execPath,
							args: ["-e", ""],
							expected_output_files: ["artifact.txt"],
						},
					],
				},
				context,
			);
			expect(stale).toMatchObject({
				success: false,
				error: expect.stringContaining("not refreshed"),
			});
			expect(
				await inspectCommandArtifacts(["artifact.txt"], root),
			).toHaveLength(1);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});
	it("never promotes outputs of a failed command", async () => {
		const root = await mkdtemp(join(tmpdir(), "cline-failed-output-"));
		try {
			await writeFile(join(root, "old.txt"), "old");
			const tool = createShellTool(createShellExecutor(), { cwd: root });
			const [result] = await tool.execute(
				{
					commands: [
						{
							command: process.execPath,
							args: ["-e", "process.exit(3)"],
							expected_output_files: ["old.txt"],
						},
					],
				},
				context,
			);
			expect(result.success).toBe(false);
			expect(result.artifacts).toBeUndefined();
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});
	it("marks unavailable executables as launch failures, not empty success", async () => {
		const tool = createShellTool(createShellExecutor());
		const [result] = await tool.execute(
			{
				commands: [
					{ command: "cline-owned-missing-executable-13290", args: [] },
				],
			},
			context,
		);
		expect(result).toMatchObject({
			success: false,
			execution: { status: "launch_failed", exitCode: null },
		});
	});
	it("reports timeout separately and does not invent confirmed termination", async () => {
		const tool = createShellTool(createShellExecutor({ timeoutMs: 100 }));
		const [result] = await tool.execute(
			{
				commands: [
					{
						command: process.execPath,
						args: ["-e", "setInterval(()=>{},1000)"],
					},
				],
			},
			context,
		);
		expect(result).toMatchObject({
			success: false,
			execution: { status: "timed_out" },
		});
		// taskkill can report a native nonzero exit before its own completion;
		// POSIX signal termination usually has null exitCode. Neither is success.
		expect(result.execution?.exitCode === null || Number.isInteger(result.execution?.exitCode)).toBe(true);
		expect(typeof result.execution?.terminationConfirmed).toBe("boolean");
	});
	it("does not expose environment secrets in structured receipts", async () => {
		const tool = createShellTool(
			createShellExecutor({
				env: { TEST_API_KEY: "owned-receipt-secret" },
				allowedSensitiveEnvironmentVariables: ["TEST_API_KEY"],
			}),
		);
		const [result] = await tool.execute(
			{
				commands: [
					{
						command: process.execPath,
						args: ["-e", "process.stderr.write(process.env.TEST_API_KEY)"],
					},
				],
			},
			context,
		);
		expect(JSON.stringify(result)).not.toContain("owned-receipt-secret");
		expect(result.execution?.stderr).toContain("[REDACTED]");
	});
});
