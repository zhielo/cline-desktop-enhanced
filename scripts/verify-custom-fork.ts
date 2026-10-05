import { existsSync, readFileSync } from "node:fs";

const requiredMarkers: Array<{
	path: string;
	markers: string[];
}> = [
 {path:"apps/examples/desktop-app/sidecar/transport-auth.ts",markers:["timingSafeEqual", "MAX_TOKEN_BYTES", "values.length > 1", "hasSidecarAuthentication"]},
 {path:"apps/examples/desktop-app/sidecar/server.ts",markers:["hasSidecarAuthentication(req, approvalToken, true)", "authenticated: true", "ws.data?.authenticated !== true", "MAX_ERROR_REPORT_BYTES"]},
 {path:"apps/examples/desktop-app/webview/lib/desktop-transport-security.ts",markers:["redactDesktopTransportSecrets", "knownToken", "[redacted]"]},
 {path:"apps/examples/desktop-app/scripts/desktop-startup.test.ts",markers:["Authenticated transport smoke timed out", "shutdownDenied.status", "stale.status"]},
 {path:"docs/DESKTOP_TRANSPORT_AUTH.md",markers:["all WebSocket commands", "Originless integrations", "No TLS"]},
 {path:"sdk/packages/core/scripts/android-investigation-worker.py",markers:["MAX_WORK", "DEX Adler32 mismatch", "verifiedBinding", "methodsTruncated", "unsafe/duplicate/encrypted ZIP member", "Not evidence of encryption"]},
 {path:"sdk/packages/core/src/extensions/tools/executors/android-investigation-index.ts",markers:["cline-android-investigation/v1", "content hash mismatch", "await link(stagedFile, file)", "Queries only cover indexed evidence"]},
 {path:"sdk/packages/core/src/extensions/tools/schemas.ts",markers:["artifact_discovery", "android_relationships", "android_method", "investigation_query"]},
 {path:"scripts/validate-advanced-build.mjs",markers:["Check Android worker embed", "android-investigation.test.ts", "android-investigation-index.test.ts"]},
 {path:"docs/ANDROID_INVESTIGATION.md",markers:["Not a runtime sandbox", "RegisterNatives", "Not yet implemented"]},
 {path:"apps/examples/desktop-app/scripts/desktop-startup.test.ts",markers:["HUB_BOOTSTRAP_TIMEOUT_MS","timeout: HUB_BOOTSTRAP_TIMEOUT_MS","SIDECAR_READY_TIMEOUT_MS","expect(health.ok).toBe(true)","expect(restartedHealth.ok).toBe(true)","duplicate session fork operation id"]},

 {path:"scripts/validate-advanced-build.mjs",markers:["Test desktop chat UI","Run desktop customization tests","analysis-task-orchestrator.test.ts","analysis-sandbox-client.test.ts","engineering-control-plane.test.ts","engineering-git-review.test.ts","engineering-worktree-manager.test.ts","engineering-workspace.test.tsx","commands-workbench.test.ts","process-session-manager.test.ts","reverse-engineering.test.ts","runtime-builder.test.ts","repository-tool.test.ts","notion-agent-bridge.test.ts","notion-agent-patch.test.ts","functions-view.test.tsx","notion-provenance.test.ts","permission-profile.test.ts","Verify custom fork preservation","Build SDK packages","Run required desktop sidecar regression suite","Test Windows installer configuration","Test AI task report","Test desktop chat UI","Run desktop customization tests","Run focused SDK safety tests","--testTimeout=60000","runValidation","runJobs","timeoutMs","summary.json"]},

 {path:"sdk/packages/core/src/extensions/tools/executors/advanced-analysis.ts",markers:["CLINE_RE_ALLOW_DECRYPTION","CLINE_RE_PRIVATE_KEY_FILE","host-gated-authenticated-decryption"]},
 {path:"sdk/packages/core/src/extensions/tools/executors/analysis-evidence-graph.ts",markers:["buildEvidenceGraph","queryEvidenceGraph","content-identity-not-authentication"]},
 {path:"sdk/packages/core/src/extensions/tools/executors/analysis-notebook.ts",markers:["prepareNotebook","runAnalysisNotebook","Input changed during analysis","Checkpoint budget exceeded"]},
  {path:"sdk/packages/core/src/extensions/tools/executors/advanced-analysis.ts",markers:["cline-advanced-analysis/v1","prepareProcessEnvironment","external-adapter-required","killTree","advancedEvidenceBundle"]},
	{
		path: "CUSTOMIZATIONS.md",
		markers: [
			"Separate Notion-assisted Functions",
			"AI task execution UI",
			"Permanent Custom AI Instructions",
			"Windows reliability",
			"Command execution performance",
			"Scoped Windows computer use",
			"Lightweight built-in browser",
			"Objective Codex-parity benchmark",
			"Required validation",
			"vitest.config.mts",
		],
	},
	{
		path: "docs/BUILT_IN_BROWSER.md",
		markers: [
			"structured `browser` tool",
			"WebView2 runtime",
			"Password fields are rejected",
			"not an operating-system sandbox",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/browser-manager.ts",
		markers: [
			"DesktopBrowserManager",
			"MAX_SESSIONS = 8",
			"MAX_SESSION_AGE_MS",
			"Child agents cannot start",
		],
	},
	{
		path: "apps/examples/desktop-app/src-tauri/src/built_in_browser.rs",
		markers: [
			"built_in_browser_start",
			"built_in_browser_cdp",
			"CallDevToolsProtocolMethod",
			"accepts only http and https URLs",
		],
	},
	{
		path: ".github/workflows/build-custom-windows-installer.yml",
		markers: ["Run consolidated custom fork validation", "validate:advanced", "include-hidden-files: true",
			"Build custom Windows installer",
			"Get-AuthenticodeSignature",
			"Upload verified setup.exe",
			"CUSTOMIZATIONS.md",
			"BUILD-INFO.txt",
			"CLINE_TEST_SIDECAR_BIN",
            "scripts/desktop-startup.test.ts",
			"Record installer smoke-test result",
			"Run process-session terminal smoke test",
			"always() && steps.installer.outcome == 'success'",
			"process-session-terminal-smoke.ts",
			'BUN_VERSION: "1.3.14"',
			"bun-version: ${{ env.BUN_VERSION }}",
      "SBOM.spdx.json",
      "actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a",
		],
	},
  {
    path: "apps/examples/desktop-app/sidecar/analysis-task-orchestrator.ts",
    markers: [
      "AnalysisTaskOrchestrator",
      "awaiting-approval",
      "executionToken",
      "canonical full-request one-time token",
      "timingSafeEqual",
      "targetIdentity",
      "expiresAt",
      "resultHash",
    ],
  },
  {
    path: "apps/examples/desktop-app/webview/components/views/chat/analysis-workbench.tsx",
    markers: [
      "prepare_analysis_task",
      "approve_analysis_task",
      "Approval boundary",
      "Evidence ledger",
      "Deep check",
      "Export evidence bundle",
    ],
  },
  {
    path: "apps/examples/desktop-app/sidecar/analysis-sandbox-client.ts",
    markers: [
      "cline-analysis-worker/v1",
      "pinned public key",
      "ephemeralSnapshots",
      "attestation signature",
    ],
  },
  {
    path: "apps/examples/desktop-app/sidecar/engineering-control-plane.ts",
    markers: [
      "EngineeringControlPlane",
      "PRAGMA journal_mode = WAL",
      "requireWorktreeForWrites",
      "claimReadyTasks",
      "Only the agent that claimed the task may update it",
      "Repository-writing tasks require worktree evidence",
      "evaluateExecutionPolicy",
      "scoreReviewRisk",
      "routeEngineeringModel",
      "isolated-vm",
    ],
  },
  {
    path: "apps/examples/desktop-app/sidecar/engineering-worktree-manager.ts",
    markers: [
      "EngineeringWorktreeManager",
      "cline/engineering/",
      "baseRevision",
      "outside the managed root",
      "explicit discard confirmation",
    ],
  },
  {
    path: "apps/examples/desktop-app/sidecar/engineering-git-review.ts",
    markers: [
      "buildEngineeringGitReview",
      "Invalid Git comparison base",
      "sensitiveFiles",
      "publicApiChanged",
      "symbols",
    ],
  },
  {
    path: "apps/examples/desktop-app/webview/components/views/engineering/engineering-workspace.tsx",
    markers: [
      "Engineering Control Center",
      "Normal Cline chat remains unchanged",
      "plan_engineering_mission",
      "claim_engineering_tasks",
      "Prepare next agent drafts",
      "Git review evidence",
      "Secure execution",
      "Parallel agents",
      "Git review",
      "Model intelligence",
    ],
  },
  {
    path: "docs/ENGINEERING_CONTROL_CENTER.md",
    markers: [
      "Trust boundary",
      "Normal chat isolation",
      "Windows Sandbox",
      "isolated VM",
      "does not execute a mission",
    ],
  },
  {
    path: "docs/ANALYSIS_TRUST_BOUNDARY.md",
    markers: [
      "complete normalized request",
      "single-use token",
      "Dynamic analysis",
      "administrator responsibility",
    ],
  },
	{
		path: "apps/examples/desktop-app/sidecar/repository-tool.ts",
		markers: [
			"createRepositoryExecutor",
			"confirm_write=true",
			"confirm_remote=true",
			"--ff-only",
			"--set-upstream",
			"GH_PROMPT_DISABLED",
		],
	},
	{
		path: "docs/STRUCTURED_REPOSITORY_AND_DIAGNOSTICS.md",
		markers: [
			"Structured repository tool",
			"Browser page diagnostics",
			"Diagnostics center",
			"does not create a GitHub Release",
		],
	},
	{
		path: "evals/parity/codex-parity.ts",
		markers: [
			"evaluateParity",
			"coveragePercent",
			"weightedCandidateScore",
			"weightedReferenceScore",
			"parityPercent",
			"Unknown parity scenario",
		],
	},
	{
		path: "evals/parity/corpus.v1.json",
		markers: [
			"repository-repair",
			"generic-computer-use-form",
			"restricted-profile-escape",
			"background-automation-retry",
		],
	},
	{
		path: "evals/parity/README.md",
		markers: [
			"versioned task",
			"comparable environment",
			"deliberately omits a Codex-relative percentage",
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
		path: "sdk/packages/core/src/hub/daemon/index.ts",
		markers: ["HUB_STARTUP_TIMEOUT_MS = 30_000"],
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
		markers: [
			"vitest/config",
			"import.meta.url",
			"defineConfig",
			'new URL("./test/vitest-setup.ts", import.meta.url)',
		],
	},
	{
		path: "apps/examples/desktop-app/test/vitest-setup.ts",
		markers: [
			'"ResizeObserver" in globalThis',
			"ResizeObserverStub",
			"disconnect()",
		],
	},
	{
		path: "apps/examples/desktop-app/package.json",
		markers: ["vitest.config.mts", "test:sidecar", "test:windows-installer"],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/chat-schema.ts",
		markers: [
			"TaskProtocolEventSchema",
			"TaskExecutionStatusSchema",
			"acceptanceCriteria",
			"transitions",
			"taskStepId",
			"taskEvent",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/task-state-machine.ts",
		markers: [
			"advanceDurableTaskState",
			"persistDurableTaskState",
			"readDurableTaskState",
			"readOrMigrateDurableTaskState",
			"rollbackDurableTaskState",
			"Skipped task step requires a reason",
			"Only one task step may be in progress",
			"Work cannot advance past a failed step",
			"sharedSessionTaskStatePath",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/task-validation.ts",
		markers: [
			"runDurableTaskValidations",
			"validationCandidates",
			"Validation timed out",
		],
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
		markers: [
			"customAiInstructions",
			"mergeDesktopAiInstructions",
			"computerUseEnabled",
			"computerUseAllowedApplications",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/computer-use-manager.ts",
		markers: [
			"DesktopComputerUseManager",
			"MAX_ACTIONS = 200",
			"MAX_SESSION_AGE_MS",
			"Child agents cannot start computer control",
			"target_agent_id",
			"updateComputerUseMetrics",
			"Foreground application instance changed",
			"Coordinates are outside the allowlisted foreground window",
			"Post-action verification failed",
			"Password controls cannot be targeted",
			"Foreground application left the allowlisted executable",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/computer-use-metrics.ts",
		markers: [
			"ComputerUseMetrics",
			"accessibilityActions",
			"coordinateActions",
			"focusLossPauses",
			"updateQueue",
		],
	},
	{
		path: "apps/examples/desktop-app/scripts/computer-use-windows.test.ts",
		markers: [
			"deterministic Windows computer-use fixture",
			"commitButton",
			"passwordBox",
			"taskkill.exe",
		],
	},
	{
		path: "apps/examples/desktop-app/scripts/windows-installer.test.ts",
		markers: [
			"terminateProcessTree",
			"taskkill.exe",
			"Timed out after 90000ms",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/commands.ts",
		markers: [
			"set_custom_ai_instructions",
			"set_computer_use_settings",
			"take_over_computer_use",
			"prepare_notion_agent_bridge",
			"filesystemPathKey",
			"rev-parse",
			"worktree",
			"update-ref",
			"handoff_git_worktree",
			"Apply to Local conflicted",
			"Discard requires explicit confirmation",
			'"rundll32"',
			"url.dll,FileProtocolHandler",
			"onAuthorization",
			"authorizationUrl",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/team/spawn-agent-tool.ts",
		markers: [
			"SubAgentControlHandle",
			"onSubAgentControlReady",
			"consumePendingUserMessage",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/team/writer-worktree.ts",
		markers: [
			"createWriterWorktree",
			"listWriterWorktreeChanges",
			"ownerAgentId",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/worktree-handoff-bar.tsx",
		markers: [
			"Apply to Local",
			"Create Branch",
			"Open PR",
			"Keep",
			"Discard worktree",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/agent-header.tsx",
		markers: [
			"onControlAgent",
			'"stop"',
			'"steer"',
			'"retry"',
			"Guidance for",
			"Handoff blocked by overlapping edits",
			"Open worktree to resolve",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/team/multi-agent.ts",
		markers: ["cancelAgentWork", "pendingSteerMessage", "maxConcurrentRuns"],
	},
	{
		path: "apps/examples/desktop-app/sidecar/chat-session.ts",
		markers: ["mergeDesktopAiInstructions", "taskToolStepIds"],
	},
	{
		path: "sdk/packages/core/src/runtime/orchestration/runtime-builder.ts",
		markers: [
			"OFFICIAL_NOTION_MCP_URL",
			"isOfficialNotionRegistration",
			"officialNotionOnly",
			"minimumToolTimeoutMs",
			"Notion session preflight failed",
			'"project-notion-bridge"',
		],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/notion-agent-routing.ts",
		markers: [
			"requestsProjectNotionBridge",
			"NOTION_AGENT_TARGET",
			"LOCAL_PROJECT_CONTEXT",
		],
	},
	{
		path: "docs/PROJECT_NOTION_BRIDGE.md",
		markers: [
			"Project + Notion Agent runtime",
			"fails session startup",
			"never represent a local file as an upload",
			"Evidence-grounded review loop",
			"five-minute MCP request floor",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/settings/functions-view.tsx",
		markers: [
			"Notion-assisted functions",
			"Uses your current Cline model",
			"https://mcp.notion.com/mcp",
			"No special database",
			"Open in new session",
			"Local function audit",
			"Create reusable function",
			"Pinned Notion context",
			"Prepare Notion Agent handoff",
			"Import Notion Agent review",
			"Project Intelligence workspace",
			"Visual approval center",
			"Analyze project intelligence",
			"Run Notion health check",
			"Export audit",
			"Notion Agent Bridge",
			"Deep evidence review",
			"Complete project evidence manifest",
			"Evidence transfer batches",
			"Prepare secure preview",
			"Ask Notion Agent",
			"Discover agents",
			"Notion Agent review-to-patch",
			"Dry-run patch",
			"Apply on isolated branch",
			"Agent Bridge privacy and provenance",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/notion-agent-bridge.ts",
		markers: [
			"prepareNotionAgentBridgePackage",
			"git",
			"--exclude-standard",
			"sensitive filename",
			"[REDACTED:token]",
			"Bridge path escapes the workspace",
			"buildEvidenceBatches",
			"metadata-only",
			"Transfer protocol",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/notion-agent-patch.ts",
		markers: [
			"previewNotionAgentPatch",
			"applyNotionAgentPatch",
			"rollbackNotionAgentPatch",
			"git",
			"--check",
			"Patch target changed after sharing with Notion",
			"notion-agent/",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/desktop-app-state.ts",
		markers: ["initialPromptDraft?: string", 'type: "new-thread"'],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/settings/settings-view.tsx",
		markers: [
			"Custom AI instructions",
			"set_custom_ai_instructions",
			"Agent permission capability matrix",
			"Full interaction",
			"DiagnosticsContent",
			"Copy sanitized report",
			"Scoped computer use",
			"set_computer_use_settings",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/app/page.tsx",
		markers: ["Computer control active", "Stop and take over"],
	},
	{
		path: "apps/examples/desktop-app/webview/hooks/use-chat-session.ts",
		markers: ['process.env.NODE_ENV === "test"', "shouldLogVerboseCoreLogs()"],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/desktop-client.ts",
		markers: ['process.env.NODE_ENV === "development"'],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/welcome-workspace-controls.test.tsx",
		markers: ["async function renderControls", "await act(async () =>"],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/image-attachments.test.ts",
		markers: ["IS_REACT_ACT_ENVIRONMENT"],
	},
	{
		path: "apps/examples/desktop-app/sidecar/oauth-login.ts",
		markers: [
			"startClineDeviceAuth",
			"completeClineDeviceAuth",
			"onAuthorization",
			"verificationUriComplete",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/hooks/use-oauth-user-code.ts",
		markers: [
			'desktopClient.subscribe("provider_oauth_user_code"',
			"lifetime of the mounted login surface",
			"authorizationUrl",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/oauth-authorization-prompt.tsx",
		markers: ["Cline sign-in URL", "Open sign-in page", "Copy sign-in link"],
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
		path: "sdk/packages/core/src/extensions/tools/permission-profile.ts",
		markers: [
			"createPermissionProfileExtension",
			'"read-only"',
			'"workspace-network"',
			'"full-access"',
			'"notion-functions"',
			'"project-notion-bridge"',
			"only the official Notion MCP tools",
			"only read-only local inspection",
			"unclassified plugin or MCP tool",
			"not an operating-system sandbox",
			"desktop computer control is disabled",
		],
	},
	{
		path: "docs/SCOPED_COMPUTER_USE.md",
		markers: [
			"disabled by default",
			"exact absolute Windows `.exe` paths",
			"Stop and take over",
			"Password controls",
			"revoke_delegation",
			"Aggregate local diagnostics",
			"post-action `verify`",
			"not an operating-system sandbox",
		],
	},
	{
		path: "docs/PERMISSION_PROFILES.md",
		markers: [
			"beforeTool",
			"delegated agents",
			"not an operating-system sandbox",
			"no-release policy",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/process-session-manager.ts",
		markers: [
			"ProcessSessionManager",
			"DEFAULT_MAX_PROCESS_SESSIONS = 64",
			"DEFAULT_PROCESS_OUTPUT_BYTES = 1024 * 1024",
			"spawnBunTerminalProcess",
			"new bun.Terminal",
			"terminalColumns",
			"resize(",
			"highestDroppedCursor",
			"process.kill(-pid",
			"taskkill.exe",
			"initializeRecovery",
			"processStartToken",
			"recoveredAfterRestart",
			"prior output and stdin are unavailable",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/schemas.ts",
		markers: [
			"ProcessSessionInputSchema",
			'action: z.literal("start")',
			'action: z.literal("resize")',
			"Windows ConPTY",
			"signal: z",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/definitions.ts",
		markers: [
			'name: "process_session"',
			"requireProcessSessionOwner",
			"createProcessSessionTool",
			"Windows ConPTY",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/runtime.ts",
		markers: ["process_session", "enableProcessSessions"],
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
			"acknowledge_external_output=true",
			"boundedUserRegex",
			"external-approved",
			"MAX_ARTIFACT_HASH_BYTES",
			"FORENSIC_REPORT_STATE",
			"apkSecurityInspection",
			"renderForensicHtml",
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
		markers: [
			"acknowledge_risk=true",
			"confirm_execution_control=true",
			"inspect_dump",
			"inspectMinidump",
			"inspect-only",
			"persistentSession",
			"process detach",
		],
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
		path: "sdk/packages/core/src/extensions/tools/executors/android-device.ts",
		markers: [
			"redactSensitiveText",
			"confirm_package_change=true",
			"confirm_log_clear=true",
		],
	},
	{
		path: "docs/FORENSIC_TOOL_RELIABILITY.md",
		markers: [
			"Forensic tool reliability",
			"acknowledge_external_output: true",
			"confirm_execution_control: true",
			"confirm_package_change: true",
			"native Windows sandboxing",
		],
	},
	{
		path: "docs/ADVANCED_FORENSIC_ANALYSIS.md",
		markers: [
			"Advanced forensic analysis",
			"cline-forensic-report-state.json",
			"apk_security_report",
			"inspect_dump",
			"does not publish a GitHub Release",
		],
	},
	{
		path: "sdk/packages/core/src/extensions/tools/executors/command-latency-baseline.ts",
		markers: [
			"MIN_SHELL_BASELINE_SAMPLES",
			"MIN_SHELL_STARTUP_RATIO",
			"evaluatePowerShellWorkerEligibility",
		],
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
		path: "docs/EXECUTION_WORKBENCH.md",
		markers: [
			"Desktop execution and analysis workbench",
			"not an operating-system sandbox",
			"strict subset",
			"owned or authorized",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/ui/markdown.tsx",
		markers: [
			"isInlinePreviewArtifactPath",
			'primaryAction={previewsInApp ? "preview" : "open"}',
			"event.preventDefault()",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/artifact-context-menu.tsx",
		markers: [
			'primaryAction?: "open" | "preview"',
			"cloneElement",
			"Open with default app",
			"Show in folder",
		],
	},
	{
		path: "apps/examples/desktop-app/sidecar/commands.ts",
		markers: [
			"spawnDetachedAndWait",
			"windowsExplorerRevealArgs",
			'/select,"',
			"windowsVerbatimArguments",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/workspace-terminal.tsx",
		markers: [
			"workspace_terminal_start",
			"confirmFullAccess",
			"workspace_terminal_signal",
			"secret-redacted output",
		],
	},
	{
		path: "apps/examples/desktop-app/webview/components/views/chat/analysis-workbench.tsx",
		markers: [
			"discover_analysis_tools",
			"run_static_analysis",
			"run_debugger_action",
			"confirmAuthorized",
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
			"isolated-writer",
			"prewarmed PowerShell worker",
			"Scoped computer use",
			"atomically persists a versioned task-state artifact",
			"Do not publish a GitHub Release",
		],
	},
	{
		path: "docs/WORKTREE_HANDOFF.md",
		markers: [
			"Apply to Local",
			"explicit confirmation",
			"Cleanup is idempotent",
			"does not publish a GitHub Release",
		],
	},
	{
		path: "docs/DURABLE_TASK_EXECUTION.md",
		markers: [
			"Automatic validation",
			"Checkpoint rollback",
			"migration.projected-report",
			"does not publish a GitHub Release",
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

requiredMarkers.push(
 {path:"sdk/packages/core/src/extensions/tools/executors/analysis-program-evidence.ts",markers:["analyzeProgramCfg","analyzeProgramTrace","not-proven","output budget"]},
 {path:"apps/examples/desktop-app/sidecar/analysis-document-store.ts",markers:["confirmWrite","validateNotebook","expectedSha256","Document changed since review"]},
 {path:"apps/examples/desktop-app/sidecar/analysis-sandbox-client.ts",markers:["bindRuntimeAnalysisRequest","submitAnalysisSandbox","worker_key_sha256","redirect:\"error\"","Receipt does not bind approved job"]},
 {path:"apps/examples/desktop-app/sidecar/notion-agent-bridge.ts",markers:["evidenceId","serialized","split"]},
);
requiredMarkers.push({path:"apps/examples/desktop-app/webview/components/views/chat/analysis-authoring.tsx",markers:["expectedSha256","Saving never executes analysis","graph_query"]},{path:".github/workflows/build-custom-windows-installer.yml",markers:["Validate portable Windows analysis engines","advanced-windows-engine-smoke.test.ts","Real portable engine execution failed"]});
requiredMarkers.push({path:"apps/examples/desktop-app/sidecar/analysis-document-store.test.ts",markers:["bounded atomic analysis document publication","bounds serialized bytes","allows exactly one concurrent","never deletes another caller"]},{path:"apps/examples/desktop-app/sidecar/analysis-document-store.ts",markers:["Serialized document byte budget exceeded","await link(stage,path)"]});
const forbiddenPaths = [
	"vitest.config.ts",
	"apps/examples/vscode/vitest.config.ts",
	"apps/examples/desktop-app/vitest.config.ts",
];
const failures: string[] = [];

requiredMarkers.push(
	{
		path: "sdk/packages/shared/src/hub.ts",
		markers: ["HUB_SESSION_LIFECYCLE_TIMEOUT_MS", 'case "session.create":', 'case "session.restore":'],
	},
	{
		path: "apps/examples/desktop-app/webview/lib/desktop-client.ts",
		markers: ["HUB_SESSION_LIFECYCLE_TIMEOUT_MS", "defaultCommandTimeoutMs", "SESSION_LIFECYCLE_TIMEOUT_MS"],
	},
	{
		path: "scripts/validate-advanced-build.mjs",
		markers: ["Test desktop transport recovery", "Test Hub lifecycle deadlines", "session-runtime-orchestrator.test.ts"],
	},
	{
		path: "docs/LONG_SESSION_RECOVERY.md",
		markers: ["Authentication is separate", "No automatic replay of sends", "ten minutes"],
	},
);

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
