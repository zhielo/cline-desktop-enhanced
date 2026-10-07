import {
	mkdtempSync,
	realpathSync,
	rmSync,
	mkdirSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { handleCommand, windowsExplorerRevealArgs } from "./commands";
import type { SidecarContext } from "./types";

let workspace: string;
let context: SidecarContext;

beforeEach(() => {
	workspace = mkdtempSync(join(tmpdir(), "cline-workbench-"));
	context = {
		activeEnvironmentId: "local",
		localWorkspaceRoot: workspace,
		liveSessions: new Map(),
		sessionEnvironmentIds: new Map(),
		runtimeBindings: new Map([
			[
				"local",
				{
					kind: "local",
					environmentId: "local",
					workspaceRoot: workspace,
					hubClient: { getUrl: () => null, isConnected: () => false },
					sessionManager: {},
				},
			],
		]),
	} as unknown as SidecarContext;
});

afterEach(() => rmSync(workspace, { recursive: true, force: true }));

describe("desktop execution workbench boundaries", () => {
	it("uses Explorer's canonical single-argument select syntax for files", () => {
		expect(
			windowsExplorerRevealArgs(
				"C:\\Users\\Pzhielo\\work\\PATCH_REPORT.md",
				false,
			),
		).toEqual(['/select,"C:\\Users\\Pzhielo\\work\\PATCH_REPORT.md"']);
		expect(windowsExplorerRevealArgs("C:\\Users\\Pzhielo\\work", true)).toEqual(
			["C:\\Users\\Pzhielo\\work"],
		);
	});

	it("requires explicit Full Access confirmation before starting a host terminal", async () => {
		await expect(
			handleCommand(context, "workspace_terminal_start", { cwd: workspace }),
		).rejects.toThrow("explicit Full Access confirmation");
	});

	it("rejects non-static reverse-engineering operations from the workbench", async () => {
		await expect(
			handleCommand(context, "run_static_analysis", {
				cwd: workspace,
				input: { operation: "script", engine: "auto", target: "sample.exe" },
			}),
		).rejects.toThrow("not part of the static-analysis allowlist");
	});

	it("requires authorization before any debugger action", async () => {
		await expect(
			handleCommand(context, "run_debugger_action", {
				cwd: workspace,
				input: { operation: "attach_snapshot", debugger: "auto", pid: 42 },
			}),
		).rejects.toThrow("target is authorized");
	});

	it("prepares exact analysis plans and exposes runtime diagnostics", async () => {
		const plan = (await handleCommand(context, "prepare_analysis_task", {
			cwd: workspace,
			kind: "static",
			request: {
				operation: "inspect",
				engine: "auto",
				target: "sample.exe",
				timeout_ms: 120_000,
			},
		})) as {
			id: string;
			status: string;
			permission: string;
			target: string;
			requestHash: string;
		};
		expect(plan).toMatchObject({
			status: "awaiting-approval",
			permission: "Inspect",
			target: join(realpathSync.native(workspace), "sample.exe"),
		});
		expect(plan.requestHash).toMatch(/^[a-f0-9]{64}$/);
		const diagnostics = (await handleCommand(
			context,
			"get_analysis_diagnostics",
			{ cwd: workspace },
		)) as {
			dynamicAnalysisOnHost: boolean;
			processSessions: { pipeFallback: boolean };
		};
		expect(diagnostics.dynamicAnalysisOnHost).toBe(false);
		expect(diagnostics.processSessions.pipeFallback).toBe(true);
	});
});

describe("Android capture authorization before retrieval or execution", () => {
	it("requires previous approval and capture-write consent for GET recovery", async () => {
		await expect(
			handleCommand(context, "recover_android_capture", {
				cwd: workspace,
				planId: "unknown",
			}),
		).rejects.toThrow("write confirmation");
		await expect(
			handleCommand(context, "recover_android_capture", {
				cwd: workspace,
				planId: "unknown",
				confirmCaptureWrite: true,
			}),
		).rejects.toThrow("Previously approved");
	});
	it("refuses execution without independent upload and authorized execution confirmations", async () => {
		await expect(
			handleCommand(context, "run_dynamic_analysis", {
				cwd: workspace,
				input: { operation: "android_capture" },
			}),
		).rejects.toThrow("execution and artifact upload confirmation");
	});
	it("requires explicit investigation metadata write consent", async () => {
		await expect(
			handleCommand(context, "mutate_investigation", {
				cwd: workspace,
				input: { action: "create", title: "Owned" },
			}),
		).rejects.toThrow();
	});
});

describe("artifact workspace resolution", () => {
	it("previews a project-relative Markdown report instead of the desktop startup directory", async () => {
		const project = join(workspace, "owned-project"),
			out = join(project, "out");
		mkdirSync(out, { recursive: true });
		writeFileSync(
			join(out, "REPORT.md"),
			"# Owned report\n\nVerified fixture.",
		);
		const result = await handleCommand(context, "read_artifact_preview", {
			path: "out/REPORT.md",
			cwd: project,
			environmentId: "local",
		});
		expect(result).toMatchObject({
			path: join(out, "REPORT.md"),
			kind: "text",
			content: "# Owned report\n\nVerified fixture.",
		});
	});
	it.each([
		"read_artifact_preview",
		"open_artifact",
		"reveal_artifact_in_folder",
	])("keeps %s blocked for SSH artifacts", async (command) => {
		context.runtimeBindings.set("ssh-owned", {
			kind: "ssh",
			environmentId: "ssh-owned",
			workspaceRoot: "/owned/remote",
		} as never);
		await expect(
			handleCommand(context, command, {
				path: "out/REPORT.md",
				cwd: "/owned/remote",
				environmentId: "ssh-owned",
			}),
		).rejects.toThrow(/remote/i);
	});
	it("does not pretend an archive member is a standalone workspace file", async () => {
		await expect(
			handleCommand(context, "read_artifact_preview", {
				path: "xl/worksheets/sheet1.xml",
				cwd: workspace,
				environmentId: "local",
			}),
		).rejects.toThrow(
			`Artifact not found: ${join(workspace, "xl/worksheets/sheet1.xml")}`,
		);
	});
});
