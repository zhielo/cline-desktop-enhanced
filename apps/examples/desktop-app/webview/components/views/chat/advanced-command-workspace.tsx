"use client";
import { useEffect, useId, useState } from "react";
import { Button } from "@/components/ui/button";
import { desktopClient } from "@/lib/desktop-client";

type Entry = {
	command: string;
	effect: string;
	availability: string;
	limitations: string;
};
type Catalog = {
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
	if (["trace_cross_language", "trace_data_flow"].includes(command))
		base.evidence_trace = {
			start_id: "",
			max_depth: 6,
			max_nodes: 100,
			max_edges: 200,
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
	return (
		<section aria-label="Advanced AI commands" className="space-y-3">
			<h3 className="font-semibold">Advanced AI commands</h3>
			<p className="text-xs">
				Fixed adapters reuse existing engines. Catalog availability is not tool
				readiness. Opening this panel runs no analysis, installs nothing, and
				grants no approvals.
			</p>
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
			<label htmlFor={`${prefix}-request`}>
				Exact command parameters (JSON)
			</label>
			<textarea
				id={`${prefix}-request`}
				className="min-h-48 w-full rounded border bg-background p-2 font-mono text-xs"
				value={request}
				disabled={!local || busy}
				maxLength={150000}
				onChange={(event) => setRequest(event.target.value)}
			/>
			<p className="text-xs">
				run_batch and resume_investigation take a reviewed static notebook
				manifest as target—not a shell command or arbitrary operation list.
				Candidate batches use a confined JSON manifest with up to eight
				independent files. They are not transactional and never replay writes.
				Smali patching publishes one file; assemble it in a separate candidate
				tree before rebuilding.
			</p>
			<Button
				disabled={!local || !entry || busy}
				onClick={() => void prepare()}
			>
				{busy ? "Preparing…" : "Prepare advanced command for review"}
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
