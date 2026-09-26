import { existsSync, readFileSync } from "node:fs";

const requiredMarkers: Array<{
	path: string;
	markers: string[];
}> = [
	{
		path: "CUSTOMIZATIONS.md",
		markers: [
			"AI task execution UI",
			"Permanent Custom AI Instructions",
			"Windows reliability",
			"Command execution performance",
			"Required validation",
			"vitest.config.mts",
		],
	},
	{
		path: ".github/workflows/build-custom-windows-installer.yml",
		markers: [
			"Build unsigned custom Windows installer",
			"Verify custom fork preservation",
			"Get-AuthenticodeSignature",
			"Upload unsigned setup.exe",
			"CUSTOMIZATIONS.md",
			"BUILD-INFO.txt",
			"CLINE_TEST_SIDECAR_BIN",
			"scripts/desktop-startup.test.ts",
			"Record installer smoke-test result",
			"always() && steps.installer.outcome == 'success'",
		],
	},
	{
		path: "apps/examples/desktop-app/scripts/desktop-startup.test.ts",
		markers: [
			"SIDECAR_READY_TIMEOUT_MS = 30_000",
			"Backend never became ready",
		],
	},
	{
		path: "vitest.config.mts",
		markers: [
			"vitest/config",
			"defineConfig",
			"sdk/packages/core/vitest.config.ts",
		],
	},
	{
		path: "apps/examples/vscode/vitest.config.mts",
		markers: ["vitest/config", "defineConfig", "src/**/*.test.ts"],
	},
	{
		path: "apps/examples/desktop-app/vitest.config.mts",
		markers: ["vitest/config", "import.meta.url", "defineConfig"],
	},
	{
		path: "apps/examples/desktop-app/package.json",
		markers: ["vitest.config.mts", "test:sidecar", "test:windows-installer"],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/chat-schema.ts",
		markers: ["TaskProtocolEventSchema", "taskStepId", "taskEvent"],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/task-report.ts",
		markers: ["formatTaskReportText", "plan.updated", "taskStepId"],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/task-report-panel.tsx",
		markers: ["AI task report", "Copy report", "evidenceByStep"],
	},
	{
		path: "apps/examples/desktop-app/sidecar/desktop-settings.ts",
		markers: ["customAiInstructions", "mergeDesktopAiInstructions"],
	},
	{
		path: "apps/examples/desktop-app/sidecar/commands.ts",
		markers: [
			"set_custom_ai_instructions",
			"filesystemPathKey",
			"rev-parse",
			"worktree",
			"update-ref",
			'"rundll32"',
			"url.dll,FileProtocolHandler",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/chat-session.ts",
		markers: ["mergeDesktopAiInstructions", "taskToolStepIds"],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/settings/settings-view.tsx",
		markers: ["Custom AI instructions", "set_custom_ai_instructions"],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/image-attachments.test.ts",
		markers: ["IS_REACT_ACT_ENVIRONMENT"],
	},
	{
		path: "apps/examples/desktop-app/sidecar/oauth-login.ts",
		markers: [
			"loginClineOAuth",
			"useWorkOSDeviceAuth: false",
			"original browser callback flow",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/schemas.ts",
		markers: ["StructuredCommandInputSchema", "invoke an executable directly"],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/definitions.ts",
		markers: [
			"cline.run_commands.duration_ms",
			"cline.run_commands.time_to_first_output_ms",
			"cline.run_commands.output_chunk_count",
			"emittedCommandMetadata",
			"Prefer { command, args } with explicit argv",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/bash.ts",
		markers: [
			"COMMAND_PROGRESS_FLUSH_INTERVAL_MS",
			"emittedOutput",
			"prepareProcessEnvironment",
			"allowedSensitiveEnvironmentVariables",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/process-environment-policy.ts",
		markers: [
			"prepareProcessEnvironment",
			"isSensitiveEnvironmentVariable",
			"createStreamingSecretRedactor",
			"OTEL_EXPORTER_OTLP_HEADERS",
			"PRIVATE_KEY_PATTERN",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/process-session-manager.ts",
		markers: [
			"ProcessSessionManager",
			"DEFAULT_MAX_PROCESS_SESSIONS = 64",
			"DEFAULT_PROCESS_OUTPUT_BYTES = 1024 * 1024",
			"interactive: false",
			"highestDroppedCursor",
			"process.kill(-child.pid",
			"taskkill.exe",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts",
		markers: [
			'path.join(process.env.USERPROFILE, "Documents")',
			"listMatchingDirectories(parent, prefixes, 2)",
			"GHIDRA_INSTALL_DIR",
			"cline_decompile_all.py",
			"ida_hexrays.decompile(function)",
			"artifactVerified",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/supervised-process.ts",
		markers: [
			'child.once("close"',
			"process.kill(-child.pid",
			"exited_early",
			"childExited",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/live-debugger.ts",
		markers: ["acknowledge_risk=true", "persistentSession", "process detach"],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/schemas.ts",
		markers: ["SAFE_DEBUGGER_LOCATION_PATTERN"],
	},
	{
		path: "docs/LIVE_DEBUGGING.md",
		markers: [
			"one-shot",
			"acknowledge_risk: true",
			"Remote debugging is rejected",
		],
	},
	{
		path: "docs/ANDROID_DEVICE_AUTOMATION.md",
		markers: ["Unrestricted shell", "acknowledge_risk: true", "screenChanged"],
	},
	{
		path: "docs/CODEX_LIKE_COMMAND_EXECUTION.md",
		markers: [
			"Structured direct execution",
			"Immediate first output",
			"cline.run_commands.time_to_first_output_ms",
			"Prewarmed PowerShell worker",
			"Do not publish a GitHub Release",
		],
	},
	{
		path: "docs/CODEX_PARITY_ROADMAP.md",
		markers: [
			"Resumable process sessions",
			"Durable task state machine",
			"Worktree-first isolation and handoff",
			"Additive permission profiles",
			"Parallel agent orchestration",
			"prewarmed PowerShell worker",
			"Scoped computer use",
			"Do not publish a GitHub Release",
		],
	},
	{
		path: "docs/PROCESS_ENVIRONMENT_SECURITY.md",
		markers: [
			"allowedSensitiveEnvironmentVariables",
			"Output redaction",
			"Security boundary",
			"does not publish a GitHub Release",
		],
	},
	{
		path: "apps/examples/desktop-app/CUSTOM_DESKTOP.md",
		markers: [
			"bounded two-level search",
			"ida_hexrays.decompile()",
			"acknowledge_risk: true",
		],
	},
];

const forbiddenPaths = [
	"vitest.config.ts",
	"apps/examples/vscode/vitest.config.ts",
	"apps/examples/desktop-app/vitest.config.ts",
];
const failures: string[] = [];

for (const forbiddenPath of forbiddenPaths) {
	if (existsSync(forbiddenPath)) {
		failures.push(`${forbiddenPath}: obsolete file must remain deleted`);
	}
}

for (const requirement of requiredMarkers) {
	let source: string;
	try {
		source = readFileSync(requirement.path, "utf8");
	} catch {
		failures.push(`${requirement.path}: file is missing`);
		continue;
	}
	for (const marker of requirement.markers) {
		if (!source.includes(marker)) {
			failures.push(`${requirement.path}: missing ${JSON.stringify(marker)}`);
		}
	}
}

if (failures.length > 0) {
	console.error("Custom fork preservation check failed:");
	for (const failure of failures) console.error(`- ${failure}`);
	console.error(
		"If the customization changed intentionally, update CUSTOMIZATIONS.md and this verifier in the same commit.",
	);
	process.exit(1);
}

console.log(
	`Custom fork preservation check passed (${requiredMarkers.length} source contracts; ${forbiddenPaths.length} obsolete path blocked).`,
);
