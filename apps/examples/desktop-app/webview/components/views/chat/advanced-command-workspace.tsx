"use client";
import { useEffect, useId, useState } from "react";
import { Button } from "@/components/ui/button";
import { desktopClient } from "@/lib/desktop-client";

type Entry = {
	route?: "static-review" | "ai-workflow";
	command: string;
	effect: string;
	availability: string;
	limitations: string;
};
type Catalog = {
	capabilities?: {
		command: string;
		declaredEffect: string;
		implementationScope: string;
		readiness: string;
		interfaces: {
			route: string;
			schemaRef: string;
			description: string;
			parameters?: unknown;
		}[];
	}[];
	recommendations?: {
		command: string;
		scope: "bounded" | "partial" | "not-implemented";
		limitations: string;
	}[];
	entries: Entry[];
	unavailable: string[];
	limitations: string[];
	runtimeCommands?: {
		command: string;
		workflow: string;
		limitations: string;
	}[];
};
function template(command: string) {
	const base: Record<string, unknown> = { target: "", timeout_ms: 120000 };
	if (command === "compare_versions")
		base.version_comparison = { kind: "project", max_results: 100 };
	if (command === "find_android_entrypoints")
		base.advanced_options = {
			entrypoints: { max_depth: 8, max_components: 64, max_dex_files: 32 },
		};
	if (command === "identify_artifact")
		base.artifact_discovery = { max_depth: 3, max_artifacts: 200 };
	if (
		[
			"preview_binary_patch",
			"patch_binary",
			"preview_ast_transform",
			"apply_ast_transform",
			"preview_dotnet_constant",
			"patch_dotnet_constant",
			"preview_jvm_constant",
			"patch_jvm_constant",
		].includes(command)
	) {
		base.output_file = "";
		base.acknowledge_external_output = false;
		base.candidate = {
			expected_sha256: "",
			...(command.startsWith("preview_") ? {} : { preview_sha256: "" }),
			...(command.includes("binary")
				? {
						byte_patch: {
							offset: 0,
							expected_hex: "00",
							replacement_hex: "01",
						},
					}
				: command.includes("ast")
					? { literal: { start: 0, expected: "0", replacement: "1" } }
					: command.includes("dotnet")
						? {
								managed: {
									method_token: "0x06000001",
									instruction_offset: 0,
									expected_value: 0,
									replacement_value: 1,
								},
							}
						: {
								jvm: {
									method_name: "value",
									descriptor: "()I",
									expected_value: 0,
									replacement_value: 1,
								},
							}),
		};
	}
	if (command === "trace_cross_language")
		base.cross_language = {
			kind: "android-jni",
			method: {
				class_descriptor: "LFixture;",
				name: "native_work",
				descriptor: "()V",
			},
			native_artifact: "lib/x86_64/libowned.so",
			max_candidates: 16,
			native_calls: {
				max_depth: 2,
				max_functions: 16,
				max_edges: 128,
				max_total_bytes: 32768,
			},
		};
	if (command === "trace_data_flow")
		base.evidence_trace = {
			start_id: "",
			max_depth: 6,
			max_nodes: 100,
			max_edges: 200,
		};
	if (command === "trace_source_sink")
		base.source_sink = {
			source_ids: [""],
			sink_ids: [""],
			stop_ids: [],
			relation: "data-flow",
			max_depth: 6,
			max_states: 1000,
			max_edge_visits: 4000,
		};
	if (command === "decompile_dotnet_method")
		base.managed_method = { method_token: "0x06000001" };
	if (command === "read_jvm_method")
		base.jvm_method = { method_name: "value", descriptor: "()I" };
	if (command === "apply_candidate_batch") {
		base.batch_preview_sha256 = "";
		base.acknowledge_external_output = false;
	}
	if (command === "preview_candidate_batch")
		base.acknowledge_external_output = false;

	if (["plan_investigation", "plan_batch"].includes(command))
		base.investigation_plan = {
			workflow: "artifact",
			goal: "Inspect the selected artifact",
		};
	if (command === "decompile_function") {
		base.engine = "ghidra";
		base.function_selector = { symbol: "" };
	}
	if (
		[
			"build_apk",
			"recompile_smali",
			"validate_smali_project",
			"preview_smali_patch",
			"patch_smali_method",
			"patch_smali",
		].includes(command)
	) {
		base.output_file = "";
		base.acknowledge_external_output = false;
	}
	if (
		["preview_smali_patch", "patch_smali_method", "patch_smali"].includes(
			command,
		)
	)
		base.smali_patch = {
			expected_sha256: "",
			class_descriptor: "",
			method_signature: "",
			expected_method: "",
			replacement_method: "",
			...(command !== "preview_smali_patch" ? { preview_sha256: "" } : {}),
		};

	if (["trace_source_symbol", "explain_behavior"].includes(command))
		base.workflow_query = { symbol: "", max_depth: 4, max_results: 100 };
	if (
		[
			"compare_public_api",
			"compare_versions",
			"diff_android_resources",
			"compare_native_functions",
			"explain_decompiler_disagreement",
			"verify_android_candidate",
		].includes(command)
	)
		base.compare_target = "";
	if (command === "verify_hypothesis")
		base.hypothesis = {
			statement: "Check the exact declared relationship",
			kind: "declared-edge",
			node_id: "",
			target_id: "",
			relation: "references-candidate",
			expected: true,
		};
	if (command === "trace_android_method")
		base.advanced_options = {
			method: { class_descriptor: "", name: "", descriptor: "" },
		};
	if (
		[
			"resolve_native_symbol",
			"trace_native_calls",
			"compare_native_functions",
			"decompile_function_bundle",
		].includes(command)
	)
		base.function_selector = { symbol: "" };
	if (command === "trace_native_calls")
		base.advanced_options = {
			native_calls: {
				max_depth: 2,
				max_functions: 16,
				max_edges: 128,
				max_total_bytes: 32768,
			},
		};
	if (command === "decompile_function_bundle") base.engine = "ghidra";
	if (
		["preview_android_candidate", "build_android_candidate"].includes(command)
	) {
		base.output_file = "";
		base.acknowledge_external_output = false;
	}
	if (
		["preview_android_candidate", "build_android_candidate"].includes(command)
	) {
		base.android_project_patch = {
			...(command === "build_android_candidate"
				? { expected_project_sha256: "", preview_sha256: "" }
				: {}),
			patches: [
				{
					path: "smali/example/Owned.smali",
					patch: {
						expected_sha256: "",
						class_descriptor: "Lexample/Owned;",
						method_signature: "value()I",
						expected_method: "",
						replacement_method: "",
					},
				},
			],
		};
	}
	if (command === "annotate_analysis_project") {
		base.engine = "ghidra";
		base.function_selector = { symbol: "" };
		base.project_edit = { mode: "preview" };
	}
	return JSON.stringify(base, null, 2);
}
/** Review-only preparation. Mounting never runs engines or grants approvals. */
export function AdvancedCommandWorkspace({
	environmentId,
	onPrepare,
}: {
	environmentId: string;
	onPrepare: (request: Record<string, unknown>) => unknown;
}) {
	const prefix = useId();
	const [catalog, setCatalog] = useState<Catalog | null>(null);
	const [command, setCommand] = useState("identify_artifact");
	const [request, setRequest] = useState(() => template("identify_artifact"));
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const local = environmentId === "local";
	useEffect(() => {
		let current = true;
		setCatalog(null);
		if (local)
			void desktopClient
				.invoke<Catalog>("analysis_command_catalog", { environmentId })
				.then((value) => {
					if (current) setCatalog(value);
				})
				.catch(() => {
					if (current)
						setError("Command catalog unavailable; no tools were run.");
				});
		return () => {
			current = false;
		};
	}, [environmentId, local]);
	async function prepare() {
		setError("");
		if (
			catalog?.entries.find((entry) => entry.command === command)?.route ===
			"ai-workflow"
		) {
			setError(
				"This command requires the owning AI investigation workflow, not a legacy static task.",
			);
			return;
		}
		setBusy(true);
		try {
			const parsed: unknown = JSON.parse(request);
			if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
				throw new Error("Request must be a JSON object");
			if (!catalog?.entries.some((entry) => entry.command === command))
				throw new Error("Choose an available command");
			await onPrepare({ ...parsed, operation: command });
		} catch (error) {
			setError(
				error instanceof Error ? error.message : "Unable to prepare command",
			);
		} finally {
			setBusy(false);
		}
	}
	const entry = catalog?.entries.find((value) => value.command === command);
	const hostOnly = entry?.route === "ai-workflow";
	const capability = catalog?.capabilities?.find(
		(value) => value.command === command,
	);
	return (
		<section aria-label="Advanced AI commands" className="space-y-3">
			<h3 className="font-semibold">Advanced AI commands</h3>
			<p className="text-xs">
				Fixed adapters reuse existing engines. Catalog availability is not tool
				readiness. Opening this panel runs no analysis, installs nothing, and
				grants no approvals.
			</p>
			{catalog?.recommendations && (
				<details>
					<summary>
						Original recommendation coverage ({catalog.recommendations.length}{" "}
						commands)
					</summary>
					<p className="text-xs">
						Bounded is not complete workflow coverage, engine readiness,
						installed validation or release certification. Partial and
						not-implemented entries are remaining work.
					</p>
					<ul className="max-h-64 overflow-auto text-xs">
						{catalog.recommendations.map((row) => (
							<li key={row.command}>
								<strong>{row.command}</strong> — {row.scope}: {row.limitations}
							</li>
						))}
					</ul>
				</details>
			)}
			{!local && <p>Advanced commands require a local environment.</p>}
			<label htmlFor={`${prefix}-command`}>Advanced command</label>
			<select
				id={`${prefix}-command`}
				className="w-full rounded border bg-background p-2 text-sm"
				value={command}
				disabled={!local || !catalog || busy}
				onChange={(event) => {
					setCommand(event.target.value);
					setRequest(template(event.target.value));
					setError("");
				}}
			>
				{(catalog?.entries ?? []).map((value) => (
					<option key={value.command} value={value.command}>
						{value.command} — {value.effect}
					</option>
				))}
			</select>
			{entry && <p className="text-xs">{entry.limitations}</p>}
			{capability && (
				<details aria-label="Command capability contract">
					<summary>Command contract — {capability.implementationScope}</summary>
					<p className="text-xs">
						Declared effect: {capability.declaredEffect}. Readiness:{" "}
						{capability.readiness}. Availability never grants approval or
						certifies target compatibility.
					</p>
					{capability.interfaces.map((value) => (
						<section
							key={value.route}
							aria-label={`${value.route} command interface`}
						>
							<h4>
								{value.route} — {value.schemaRef}
							</h4>
							<p className="text-xs">{value.description}</p>
							{value.parameters !== undefined && (
								<pre className="max-h-64 overflow-auto text-xs">
									{JSON.stringify(value.parameters, null, 2)}
								</pre>
							)}
						</section>
					))}
				</details>
			)}
			{hostOnly && (
				<output className="block text-xs">
					Ask the chat agent to use {command} through the owning AI
					investigation workflow. It gathers exact inputs and requests any
					independent human approval. This static JSON form cannot start it;
					selecting it runs nothing.
				</output>
			)}
			<label htmlFor={`${prefix}-request`}>
				Exact command parameters (JSON)
			</label>
			<textarea
				id={`${prefix}-request`}
				className="min-h-48 w-full rounded border bg-background p-2 font-mono text-xs"
				value={request}
				disabled={!local || busy || hostOnly}
				maxLength={150000}
				onChange={(event) => setRequest(event.target.value)}
			/>
			<p className="text-xs">
				In this static review form, run_batch and resume_investigation take a
				reviewed static notebook manifest as target. Their AI workflow interface
				instead uses the exact typed DAG or receipt schema shown in the command
				contract. These interfaces are not interchangeable and neither accepts
				shell commands. Candidate batches use a confined JSON manifest with up
				to eight independent files. They are not transactional and never replay
				writes. Smali patching publishes one file; assemble it in a separate
				candidate tree before rebuilding.
			</p>
			<Button
				disabled={!local || !entry || busy || hostOnly}
				onClick={() => void prepare()}
			>
				{hostOnly
					? "Use the AI investigation workflow"
					: busy
						? "Preparing…"
						: "Prepare advanced command for review"}
			</Button>
			{error && <p role="alert">{error}</p>}
			{catalog && (
				<>
					{catalog.runtimeCommands?.map((value) => (
						<p key={value.command} className="text-xs">
							{value.command}: {value.workflow}. {value.limitations}
						</p>
					))}
					<h4 className="font-semibold">Not available in this command pack</h4>
					<p className="text-xs">{catalog.unavailable.join(", ")}</p>
					<p className="text-xs">
						Runtime work uses separately authorized device/debugger workflows.
						No universal cross-language resolution, arbitrary native rewriting,
						complete .NET decompilation or verifier acceptance is implied.
					</p>
				</>
			)}
		</section>
	);
}
