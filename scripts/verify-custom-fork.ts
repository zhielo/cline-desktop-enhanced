import { readFileSync } from "node:fs";

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
		],
	},
	{
		path: ".github/workflows/build-custom-windows-installer.yml",
		markers: [
			"Build unsigned custom Windows installer",
			"Get-AuthenticodeSignature",
			"Upload unsigned setup.exe",
		],
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
		markers: ["set_custom_ai_instructions", "filesystemPathKey"],
	},
	{
		path: "apps/examples/desktop-app/sidecar/chat-session.ts",
		markers: ["mergeDesktopAiInstructions", "taskToolStepIds"],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/settings/settings-view.tsx",
		markers: ["Custom AI instructions", "set_custom_ai_instructions"],
	},
];

const failures: string[] = [];
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
	`Custom fork preservation check passed (${requiredMarkers.length} source contracts).`,
);
