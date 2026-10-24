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
import {
	handleCommand,
	executeModelInvestigation,
	windowsExplorerRevealArgs,
} from "./commands";
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

describe("fixed project output routing", () => {
	it("previews an absolute generated report outside the source workspace", async () => {
		const output = mkdtempSync(join(tmpdir(), "cline-absolute-output-"));
		try {
			const report = join(output, "REPORT.md");
			writeFileSync(report, "# Project output");
			expect(
				await handleCommand(context, "read_artifact_preview", {
					path: report,
					cwd: workspace,
					environmentId: "local",
				}),
			).toMatchObject({
				path: report,
				kind: "text",
				content: "# Project output",
			});
		} finally {
			rmSync(output, { recursive: true, force: true });
		}
	});

	it.each([
		"get_project_output_location",
		"open_project_output_folder",
	])("blocks %s for SSH before touching local files", async (command) => {
		context.runtimeBindings.set("ssh-owned", {
			kind: "ssh",
			environmentId: "ssh-owned",
			workspaceRoot: "/remote",
		} as never);
		await expect(
			handleCommand(context, command, {
				cwd: "/remote",
				environmentId: "ssh-owned",
			}),
		).rejects.toThrow(/local Windows only/);
	});
});
it("authenticated originless integrations cannot mint analysis execution approval tokens", async () => {
	await expect(
		handleCommand(
			context,
			"approve_analysis_task",
			{
				cwd: workspace,
				planId: "owned-plan",
				requirements: ["Read"],
				requestHash: "owned-hash",
			},
			{
				connection: {
					data: { authenticated: true, canApproveTools: false },
				} as never,
			},
		),
	).rejects.toThrow("trusted desktop connection");
	await expect(
		handleCommand(context, "approve_analysis_task", {
			cwd: workspace,
			planId: "owned-plan",
		}),
	).rejects.toThrow("trusted desktop connection");
});

it("returns only a static catalog without requiring a live session", async () => {
	const catalog = (await handleCommand(context, "analysis_command_catalog", {
		cwd: workspace,
		environmentId: "local",
	})) as { entries: { command: string }[]; unavailable: string[] };
	expect(
		catalog.entries.some((entry) => entry.command === "patch_smali_method"),
	).toBe(true);
	expect(
		catalog.entries.some((entry) => entry.command === "patch_binary"),
	).toBe(true);
	expect(catalog.unavailable).toContain("general_native_rewriting");
});
it.each([
	"export_bundle_recovery",
	"patch_binary",
	"apply_ast_transform",
	"patch_dotnet_constant",
	"patch_jvm_constant",
	"apply_candidate_batch",
	"build_apk",
	"recompile_smali",
	"validate_smali_project",
	"patch_smali_method",
	"patch_smali",
])("workbench adapter %s cannot bypass trusted write approval", async (operation) => {
	await expect(
		handleCommand(context, "run_static_analysis", {
			cwd: workspace,
			input: { operation, target: join(workspace, "owned.smali") },
		}),
	).rejects.toThrow("trusted desktop connection");
});

it("routes candidate verification by retained plan ID, not a caller-supplied APK or hash", async () => {
	await expect(
		handleCommand(context, "prepare_candidate_verification", {
			cwd: workspace,
			planId: "missing-owned-plan",
			target: join(workspace, "injected.apk"),
			expected_sha256: "a".repeat(64),
		}),
	).rejects.toThrow("Analysis plan was not found");
});

it("JSON-shaped model grants cannot authorize recovery export or arbitrary writes", async () => {
	const id = "owned";
	context.liveSessions.set(id, {
		busy: true,
		transitioningProvider: false,
		config: { permissionProfile: "full-access" },
	} as never);
	for (const operation of ["export_bundle_recovery", "patch_binary"]) {
		await expect(
			handleCommand(
				context,
				"run_static_analysis",
				{
					cwd: workspace,
					sessionId: id,
					input: { operation, target: join(workspace, "owned.js") },
				},
				{
					modelGrant: {
						key: Symbol("host-model-investigation"),
						sessionId: id,
						workspace,
						mode: "static",
					},
				} as never,
			),
		).rejects.toThrow("trusted desktop connection");
	}
});

for (const engine of ["literal", "wakaru"] as const)
	it.skipIf(engine === "wakaru" && !process.env.CLINE_TEST_WAKARU_ROOT)(
		`publishes real ${engine} saved recovery through the approved owning busy model host route`,
		async () => {
			const { randomUUID } = await import("node:crypto"),
				{ readFile } = await import("node:fs/promises"),
				{ byteDigest, digest } = await import("@cline/core"),
				{ execFileSync } = await import("node:child_process"),
				{ fileURLToPath } = await import("node:url"),
				{ firstPartyStore } = await import("./first-party-analysis");
			workspace = realpathSync(workspace);
			context.localWorkspaceRoot = workspace;
			const id = randomUUID(),
				source = Buffer.from(
					"(self.webpackChunkowned=self.webpackChunkowned||[]).push([[1],{42:function(module,exports,require){exports.value=7}}]);",
				),
				target = join(workspace, "bundle.js");
			writeFileSync(target, source);
			const store = firstPartyStore();
			store.setMode(id, workspace, "static");
			const executable = execFileSync(
				"bun",
				["--eval", "console.log(process.execPath)"],
				{ encoding: "utf8" },
			).trim();
			const previousHost = process.env.CLINE_FIRST_PARTY_ANALYSIS_HOST;
			const previousNativeRoot = process.env.CLINE_BUNDLED_ANALYSIS_ROOT;
			if (engine === "wakaru")
				process.env.CLINE_BUNDLED_ANALYSIS_ROOT =
					process.env.CLINE_TEST_WAKARU_ROOT;
			process.env.CLINE_FIRST_PARTY_ANALYSIS_HOST = JSON.stringify({
				executable,
				args: [
					fileURLToPath(
						new URL(
							"../../../../scripts/semantic-worker-entry.ts",
							import.meta.url,
						),
					),
				],
			});
			const saved = {
				id,
				status: "idle",
				workspaceRoot: workspace,
				cwd: workspace,
			};
			const binding = context.runtimeBindings.get("local")!;
			binding.workspaceRoot = workspace;
			binding.sessionManager = {
				get: async () => saved,
				list: async () => [saved],
			} as never;
			context.sessionEnvironmentIds.set(id, "local");
			const live = {
				busy: false,
				transitioningProvider: false,
				config: { permissionProfile: "full-access" },
			};
			context.liveSessions.set(id, live as never);
			try {
				const artifact = (await handleCommand(
					context,
					"open_binary",
					{ sessionId: id, environmentId: "local", input: { target } },
					{ connection: { data: { canApproveTools: true } } as never },
				)) as { id: string };
				live.busy = true;
				saved.status = "running";
				const recoveryRaw = await executeModelInvestigation(
					context,
					"recover_bundle_sources",
					{ artifactId: artifact.id, engine },
					{
						sessionId: id,
						agentId: "owned-agent",
						toolCallId: "owned-recovery",
					} as never,
					async (details) => {
						expect(details).toMatchObject({
							independentAnalysisApproval: true,
						});
						return true;
					},
				);
				const recovered = JSON.parse(recoveryRaw).result;
				expect(recovered.status, recovered.error).toBe("partial");
				const receiptId = recovered.id,
					result = store.get(id, receiptId).result!;
				expect(result.bundleRecovery?.modules).toHaveLength(1);
				const name = Buffer.from("owned.pyc\0"),
					toc = Buffer.alloc(18 + name.length),
					cookie = Buffer.alloc(88);
				toc.writeUInt32BE(toc.length);
				toc.writeUInt32BE(3, 8);
				toc.writeUInt32BE(3, 12);
				toc[17] = 115;
				name.copy(toc, 18);
				Buffer.from("MEI\x0c\x0b\x0a\x0b\x0e").copy(cookie);
				cookie.writeUInt32BE(3 + toc.length + 88, 8);
				cookie.writeUInt32BE(3, 12);
				cookie.writeUInt32BE(toc.length, 16);
				cookie.writeUInt32BE(313, 20);
				cookie.write("python313.dll", 24);
				const archive = join(workspace, "owned-pyinstaller.bin");
				writeFileSync(
					archive,
					Buffer.concat([Buffer.from("abc"), toc, cookie]),
				);
				const archiveArtifact = JSON.parse(
					await executeModelInvestigation(
						context,
						"open_binary",
						{ target: archive },
						{
							sessionId: id,
							agentId: "owned-agent",
							toolCallId: "owned-open-metadata",
						} as never,
						async () => true,
					),
				) as { id: string };
				const metadataRaw = await executeModelInvestigation(
					context,
					"inspect_artifact_metadata",
					{ artifactId: archiveArtifact.id, reader: "pyinstaller" },
					{
						sessionId: id,
						agentId: "owned-agent",
						toolCallId: "owned-metadata",
					} as never,
					async () => true,
				);
				const metadata = JSON.parse(metadataRaw).result;
				expect(metadata.status, metadata.error).toBe("partial");
				expect(
					store.get(id, metadata.id).result?.artifactMetadata?.reader,
				).toBe("pyinstaller");
				let reviews = 0;
				const raw = await executeModelInvestigation(
					context,
					"publish_bundle_recovery",
					{
						artifactId: artifact.id,
						receiptId,
						reportHash: digest(result.bundleRecovery),
						outputFile: join(workspace, "recovery.json"),
					},
					{
						sessionId: id,
						agentId: "owned-agent",
						toolCallId: "owned-call",
					} as never,
					async (details) => {
						reviews++;
						expect(details).toMatchObject({
							independentAnalysisApproval: true,
						});
						expect(
							(details.plan as { requirements: string[] }).requirements,
						).toContain("new-output-no-overwrite");
						return true;
					},
				);
				expect(reviews).toBe(1);
				expect(raw).not.toContain("executionToken");
				const published = JSON.parse(
					await readFile(join(workspace, "recovery.json"), "utf8"),
				);
				expect(published.report.modules).toHaveLength(1);
				expect(published.report.sourceSha256).toBe(byteDigest(source));
			} finally {
				store.setMode(id, workspace, "off");
				if (previousNativeRoot === undefined)
					delete process.env.CLINE_BUNDLED_ANALYSIS_ROOT;
				else process.env.CLINE_BUNDLED_ANALYSIS_ROOT = previousNativeRoot;
				if (previousHost === undefined)
					delete process.env.CLINE_FIRST_PARTY_ANALYSIS_HOST;
				else process.env.CLINE_FIRST_PARTY_ANALYSIS_HOST = previousHost;
			}
		},
	);
