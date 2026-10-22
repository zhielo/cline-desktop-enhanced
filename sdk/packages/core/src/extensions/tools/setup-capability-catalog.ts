/** Registered routes, not installed-engine, licensing or target-compatibility proof. */
export const SETUP_ENGINE_ROUTES = [
	{
		id: "lief",
		action: "native_inventory",
		purpose: "Parse bounded native binary metadata",
	},
	{
		id: "capstone",
		action: "native_disassemble",
		purpose: "Disassemble a selected bounded byte range",
	},
	{
		id: "z3",
		action: "compare_expressions",
		purpose: "Compare bounded bit-vector expressions",
	},
	{
		id: "triton",
		action: "triton_expression",
		purpose: "Evaluate bounded expression models, not target execution",
	},
	{
		id: "qbindiff",
		action: "match_native_functions",
		purpose: "Match two supplied BinExport inputs",
	},
	{
		id: "androguard",
		action: "dex_index",
		purpose: "Read bounded DEX class and method metadata",
	},
	{
		id: "miasm",
		action: "lift_native_ir",
		purpose: "Lift a selected bounded native block",
	},
	{
		id: "unicorn",
		action: "unicorn_emulate",
		purpose: "Emulate bounded supported bytes; not host target execution",
	},
	{
		id: "angr",
		action: "angr_lift",
		purpose: "Static VEX lifting using the separate angr interpreter",
	},
	{
		id: "qbdi",
		action: null,
		purpose:
			"Owned-fixture self-test only locally; arbitrary target tracing requires a separately authorized isolated worker",
	},
	{
		id: "cryptography",
		action: "decrypt_blob",
		purpose:
			"Host-enabled authenticated known-key decryption; keys are never tool parameters",
	},
] as const;
export function setupCapabilityCatalog() {
	return {
		schemaVersion: 1,
		status: "registered-routes-not-health-proof",
		providerCalls: 0,
		targetExecuted: false,
		engineRoutes: SETUP_ENGINE_ROUTES.map(({ id, action, purpose }) => ({
			id,
			purpose,
			tool: "reverse_engineer",
			operation: "advanced_analysis",
			advanced_action: action,
			availability: action ? "registered" : "owned-self-test-only",
			selfTest: id === "angr" ? "angr_readiness" : "full_readiness",
		})),
		specialistRoutes: [
			{
				id: "joern",
				tool: "reverse_engineer",
				operation: "advanced_analysis",
				advanced_action: "joern_query",
				selfTest: "specialist_readiness",
				selfTestOptions: { specialist_readiness: { engine: "joern" } },
				scope:
					"Single JavaScript/Java source; fixed callers/references/source-sink queries; decompiler output stays approximate",
				requirement:
					"Reviewed manifest-pinned Linux Joern runtime with bundled JDK; no arbitrary Scala; Windows launcher not enabled",
			},
			{
				id: "angr-symbolic",
				tool: "reverse_engineer",
				operation: "advanced_analysis",
				advanced_action: "angr_symbolic",
				selfTest: "specialist_readiness",
				selfTestOptions: { specialist_readiness: { engine: "angr" } },
				scope:
					"Selected raw AMD64 bytes, synthetic base 0x100000, one symbolic argument; no whole-binary solver",
				requirement:
					"Separate pinned angr interpreter and enforceable memory limits; candidate is model-specific",
			},
			{
				id: "speakeasy",
				availability: "trusted-dynamic-workbench",
				operation: "emulate_windows",
				prepareCommand: "prepare_analysis_task",
				runCommand: "run_dynamic_analysis",
				scope:
					"Fixed default PE entry in isolated Linux worker; modeled behavior, not native Windows execution",
				requirement:
					"Runtime mode, separate upload/execution approval, authenticated HTTPS, pinned Ed25519 key/runtime, disabled worker network",
			},
			{
				id: "qiling",
				availability: "evaluation-deferred",
				scope: "No executable route added",
				requirement:
					"Rootfs provenance, redistribution review and evidence of value beyond existing Unicorn/Speakeasy required",
			},
		],
		additionalRoutes: [
			{
				id: "ghidra",
				tool: "reverse_engineer",
				operation: "decompile",
				engine: "ghidra",
				requirement:
					"Installed Ghidra and compatible Java; exact function selector supported",
			},
			{
				id: "ida",
				tool: "reverse_engineer",
				operation: "decompile",
				engine: "ida",
				requirement:
					"Selected IDA executable; IDAPython and processor-specific Hex-Rays checked by actual invocation, not filenames",
			},
			{
				id: "jadx",
				tool: "reverse_engineer",
				operation: "decompile",
				engine: "jadx",
				requirement: "Installed or bundled JADX and supported input",
			},
			{
				id: "android-build-tools",
				tool: "reverse_engineer",
				operation: "analysis_command_catalog",
				requirement:
					"Use catalog recipes for Apktool, Smali, rebuild, alignment and signing; writes require separate approval",
			},
			{
				id: "android-device",
				tool: "android_device",
				operation: "discover",
				requirement:
					"Configured ADB and an explicitly authorized selected device",
			},
			{
				id: "isolated-worker",
				tool: "reverse_engineer",
				operation: "plan_runtime_observation",
				requirement:
					"Proposal only; actual runtime work requires separate approval, configured worker and signed capability proof",
			},
		],
		workbenchOnly: ["radare2", "yara", "capa", "floss"].map((id) => ({
			id,
			availability: "trusted-desktop-workbench-only",
			statusCommand: "binary_triage_status",
			selfTestCommand: "binary_triage_test",
			executionCommand: "binary_triage_run",
			limitation:
				"Visible to the AI as metadata, not callable through reverse_engineer. Requires the trusted desktop workbench, scoped evidence and explicit approval; do not bypass using model RPC or arbitrary shell commands.",
		})),
		firstParty: {
			id: "javascript-electron",
			tool: "reverse_engineer",
			operation: "javascript_analysis",
			savedEvidenceOperation: "analysis_evidence",
			requirement:
				"Owning session workspace and Analysis mode; static source inspection only",
		},
		inventory: {
			tool: "reverse_engineer",
			operation: "advanced_analysis",
			advanced_action: "toolchain",
		},
		selfTests: ["full_readiness", "angr_readiness"],
		limitations: [
			"Catalog reads do not execute tests, install packages, inspect licenses or grant approvals. Registered does not mean installed or ready.",
			"Request owned self-tests explicitly without target, compare_target or advanced_options. Actual completion, executionVerified and per-engine failures determine readiness.",
			"Library backends are reached through existing tools, not separate invented AI tools. Disabled tools, mode restrictions, host configuration and permissions still apply.",
			"IDA vendor licensing and missing processor plugins are not bypassed. No REA installation, CLI or MCP backend is required.",
		],
	};
}
