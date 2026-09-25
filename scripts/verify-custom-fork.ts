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
		markers: ["COMMAND_PROGRESS_FLUSH_INTERVAL_MS", "emittedOutput"],
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
