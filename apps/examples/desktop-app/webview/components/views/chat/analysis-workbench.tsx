"use client";

import {
	Activity,
	Binary,
	Bug,
	FileCheck2,
	FileSearch,
	ListChecks,
	Loader2,
	RefreshCw,
	ShieldAlert,
	ShieldCheck,
	Terminal,
	Wrench,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Input } from "@/components/ui/input";
import { toast } from "@/hooks/use-toast";
import { desktopClient } from "@/lib/desktop-client";
import { cn } from "@/lib/utils";
import { AnalysisAuthoring } from "./analysis-authoring";
import { ApkIncidentWorkspace } from "./apk-incident-workspace";
import { InvestigationWorkspace } from "./investigation-workspace";

import { ExecutionWorkspace } from "./execution-workspace";

type WorkbenchMode =
	| "execution"
	| "incidents"
	| "investigation"
	| "tasks"
	| "notebook"
	| "graph"
	| "runtime"
	| "analyze"
	| "debug"
	| "terminal"
	| "approvals"
	| "evidence"
	| "diagnostics";
type TaskKind =
	| "static"
	| "debugger"
	| "gui"
	| "dynamic"
	| "device"
	| "execution";
type TaskPlan = {
	id: string;
	kind: TaskKind;
	operation: string;
	target?: string;
	request: Record<string, unknown>;
	requestHash: string;
	permission: string;
	status: string;
	requirements: string[];
	risk: string;
	budget: Record<string, unknown>;
	createdAt: string;
	expiresAt: string;
	evidence?: {
		resultHash: string;
		requestHash: string;
		tool: string;
		outputPaths: string[];
	};
	error?: string;
};
type Discovery = { reverseEngineering?: unknown; debugger?: unknown };
type AnalysisOperation =
	| "advanced_analysis"
	| "inspect"
	| "scan_strings"
	| "forensic_report"
	| "apk_security_report"
	| "verify_apk_signature"
	| "analyze"
	| "decompile"
	| "disassemble_smali";
type DebugOperation =
	| "inspect_dump"
	| "launch"
	| "attach_snapshot"
	| "backtrace"
	| "registers"
	| "read_memory"
	| "disassemble"
	| "continue"
	| "step";

const modes: Array<{
	id: WorkbenchMode;
	icon: typeof Activity;
	label: string;
}> = [
	{ id: "execution", icon: Terminal, label: "Execution lab" },
	{ id: "incidents", icon: Bug, label: "APK incidents" },
	{ id: "investigation", icon: ListChecks, label: "Investigation" },
	{ id: "tasks", icon: ListChecks, label: "Tasks" },
	{ id: "analyze", icon: Binary, label: "Analyze" },
	{ id: "notebook", icon: ListChecks, label: "Notebook" },
	{ id: "graph", icon: Activity, label: "Graph" },
	{ id: "runtime", icon: ShieldAlert, label: "Isolated runtime" },
	{ id: "debug", icon: Bug, label: "Debug" },
	{ id: "terminal", icon: Terminal, label: "Terminal" },
	{ id: "approvals", icon: ShieldCheck, label: "Approvals" },
	{ id: "evidence", icon: FileCheck2, label: "Evidence" },
	{ id: "diagnostics", icon: Wrench, label: "Diagnostics" },
];

function pretty(value: unknown): string {
	if (typeof value === "string") return value;
	return JSON.stringify(value, null, 2);
}

export function AnalysisWorkbench({
	cwd,
	environmentId,
}: {
	cwd?: string;
	environmentId: string;
}) {
	const [mode, setMode] = useState<WorkbenchMode>("analyze");
	const [discovery, setDiscovery] = useState<Discovery | null>(null);
	const [diagnostics, setDiagnostics] = useState<unknown>(null);
	const [tasks, setTasks] = useState<TaskPlan[]>([]);
	const [pendingPlan, setPendingPlan] = useState<TaskPlan | null>(null);
	const [loadingDiscovery, setLoadingDiscovery] = useState(false);
	const [target, setTarget] = useState("");
	const [decompilerOptions, setDecompilerOptions] = useState("{}");
	const [operation, setOperation] = useState<AnalysisOperation>("inspect");
	const [engine, setEngine] = useState("auto");
	const [advancedAction, setAdvancedAction] = useState("suite");
	const [advancedOptions, setAdvancedOptions] = useState("{}");
	const workspaceKey = `${cwd}\0${environmentId}`;
	const [investigationSelection, setInvestigationSelection] = useState({
		workspaceKey,
		id: "",
	});
	const investigationId =
		investigationSelection.workspaceKey === workspaceKey
			? investigationSelection.id
			: "";
	const setInvestigationId = useCallback(
		(id: string) => setInvestigationSelection({ workspaceKey, id }),
		[workspaceKey],
	);
	const [runtimeOperation, setRuntimeOperation] = useState(
		"trace_native_region",
	);
	const [androidPackage, setAndroidPackage] = useState(
		"com.example.authorized",
	);
	const [captureDex, setCaptureDex] = useState(false);
	const [captureNative, setCaptureNative] = useState(false);
	const [recoveryPlanId, setRecoveryPlanId] = useState("");
	const [runtimeSymbol, setRuntimeSymbol] = useState("main");
	const [architecture, setArchitecture] = useState("x86_64");
	const [uploadConfirmed, setUploadConfirmed] = useState(false);
	const [runtimeConfirmed, setRuntimeConfirmed] = useState(false);
	const [debugOperation, setDebugOperation] =
		useState<DebugOperation>("inspect_dump");
	const [pid, setPid] = useState("");
	const [address, setAddress] = useState("");
	const [authorized, setAuthorized] = useState(false);
	const [executionConfirmed, setExecutionConfirmed] = useState(false);
	const [allowExternalTarget, setAllowExternalTarget] = useState(false);
	const [busy, setBusy] = useState(false);
	const [result, setResult] = useState<unknown>(null);
	const common = useMemo(
		() => ({
			environmentId,
			...(cwd?.trim() ? { cwd } : {}),
			...(investigationId ? { investigationId } : {}),
		}),
		[cwd, environmentId, investigationId],
	);

	const refreshLedger = useCallback(async () => {
		const [nextTasks, nextDiagnostics] = await Promise.all([
			desktopClient.invoke<TaskPlan[]>("list_analysis_tasks", common),
			desktopClient.invoke("get_analysis_diagnostics", common),
		]);
		setTasks(nextTasks);
		setDiagnostics(nextDiagnostics);
	}, [common]);

	const discover = useCallback(
		async (depth: "fast" | "deep" = "fast") => {
			setLoadingDiscovery(true);
			try {
				setDiscovery(
					await desktopClient.invoke<Discovery>("discover_analysis_tools", {
						...common,
						depth,
					}),
				);
				await refreshLedger();
			} catch (error) {
				toast({
					variant: "destructive",
					title: "Diagnostics failed",
					description:
						error instanceof Error
							? error.message
							: "Could not inspect analysis capabilities.",
				});
			} finally {
				setLoadingDiscovery(false);
			}
		},
		[common, refreshLedger],
	);

	useEffect(() => {
		void discover("fast");
	}, [discover]);

	const prepare = async (kind: TaskKind, request: Record<string, unknown>) => {
		setBusy(true);
		setResult(null);
		try {
			const plan = await desktopClient.invoke<TaskPlan>(
				"prepare_analysis_task",
				{
					...common,
					kind,
					request,
					allowExternalTarget,
				},
			);
			setPendingPlan(plan);
			setUploadConfirmed(false);
			setRuntimeConfirmed(false);
			await refreshLedger();
			setMode("approvals");
		} catch (error) {
			toast({
				variant: "destructive",
				title: "Could not prepare task",
				description:
					error instanceof Error ? error.message : "Task planning failed.",
			});
		} finally {
			setBusy(false);
		}
	};

	const approveAndRun = async () => {
		if (!pendingPlan) return;
		if (pendingPlan.kind === "device" || pendingPlan.kind === "execution") {
			toast({
				title:
					"Use the APK incidents or Execution lab tab to approve this plan",
			});
			return;
		}
		if (
			pendingPlan.kind === "dynamic" &&
			(!uploadConfirmed || !runtimeConfirmed)
		)
			return;
		setBusy(true);
		setResult(null);
		try {
			const approved = await desktopClient.invoke<{
				executionToken: string;
			}>("approve_analysis_task", {
				...common,
				planId: pendingPlan.id,
				requirements: pendingPlan.requirements,
				requestHash: pendingPlan.requestHash,
			});
			let response: {
				result: unknown;
				plan?: TaskPlan;
				investigationWarning?: string;
			};
			if (pendingPlan.kind === "debugger") {
				response = await desktopClient.invoke("run_debugger_action", {
					...common,
					planId: pendingPlan.id,
					executionToken: approved.executionToken,
					confirmAuthorized: true,
					input: pendingPlan.request,
				});
			} else if (pendingPlan.kind === "dynamic") {
				response = await desktopClient.invoke("run_dynamic_analysis", {
					...common,
					planId: pendingPlan.id,
					executionToken: approved.executionToken,
					confirmExecution: runtimeConfirmed,
					confirmArtifactUpload: uploadConfirmed,
					input: pendingPlan.request,
				});
			} else {
				response = await desktopClient.invoke(
					pendingPlan.kind === "gui"
						? "open_analysis_gui"
						: "run_static_analysis",
					{
						...common,
						planId: pendingPlan.id,
						executionToken: approved.executionToken,
						...(pendingPlan.kind === "gui" ? { confirmLaunch: true } : {}),
						input: pendingPlan.request,
					},
				);
			}
			if (response.investigationWarning)
				toast({
					variant: "destructive",
					title: "Investigation metadata needs attention",
					description: response.investigationWarning,
				});
			setResult(response.result);
			setPendingPlan(null);
			await refreshLedger();
			setMode("evidence");
		} catch (error) {
			await refreshLedger().catch(() => undefined);
			toast({
				variant: "destructive",
				title: "Supervised task failed",
				description:
					error instanceof Error ? error.message : "The task did not complete.",
			});
		} finally {
			setBusy(false);
		}
	};

	const prepareStatic = (kind: "static" | "gui") => {
		if (kind === "static" && operation === "advanced_analysis")
			try {
				JSON.parse(advancedOptions);
			} catch {
				toast({
					variant: "destructive",
					title: "Invalid advanced options JSON",
				});
				return;
			}
		let selectedOptions: Record<string, unknown> = {};
		if (kind === "static" && operation === "decompile") {
			try {
				selectedOptions = JSON.parse(decompilerOptions);
				if (
					!selectedOptions ||
					Array.isArray(selectedOptions) ||
					typeof selectedOptions !== "object" ||
					Object.keys(selectedOptions).some(
						(key) =>
							![
								"function_selector",
								"jadx_single_class",
								"jadx_mode",
								"managed_worker",
								"confirm_managed_worker",
							].includes(key),
					)
				)
					throw new Error();
			} catch {
				toast({
					variant: "destructive",
					title: "Invalid targeted decompiler options",
				});
				return;
			}
		}
		const request = {
			...selectedOptions,
			engine,
			operation: kind === "gui" ? "open_gui" : operation,
			...(kind === "static" && operation === "advanced_analysis"
				? {
						advanced_action: advancedAction,
						advanced_options: JSON.parse(advancedOptions),
					}
				: {}),
			...(target.trim() ? { target: target.trim() } : {}),
			reuse_analysis: true,
			report_format: "json",
			timeout_ms: 120_000,
		};
		return prepare(kind, request);
	};

	const prepareDebugger = () => {
		const numericPid = Number(pid);
		const request: Record<string, unknown> = {
			operation: debugOperation,
			debugger: "auto",
			target_kind: "local",
			acknowledge_risk: true,
			timeout_ms: 120_000,
		};
		if (target.trim()) request.target = target.trim();
		if (Number.isInteger(numericPid) && numericPid > 0)
			request.pid = numericPid;
		if (address.trim()) request.address = address.trim();
		if (["launch", "continue", "step"].includes(debugOperation)) {
			request.confirm_execution_control = executionConfirmed;
		}
		return prepare("debugger", request);
	};

	const cancelPlan = async (planId: string) => {
		setBusy(true);
		try {
			await desktopClient.invoke("cancel_analysis_task", {
				...common,
				planId,
			});
			if (pendingPlan?.id === planId) setPendingPlan(null);
			await refreshLedger();
			setMode("tasks");
		} finally {
			setBusy(false);
		}
	};

	const openEvidenceArtifact = async (path: string) => {
		await desktopClient.invoke("open_artifact", { ...common, path });
	};

	const exportEvidence = async (planId: string) => {
		const exported = await desktopClient.invoke<{
			outputPath: string;
			bundleHash: string;
		}>("export_analysis_evidence", { ...common, planId });
		setResult(exported);
		toast({
			title: "Evidence bundle exported",
			description: exported.outputPath,
		});
	};

	const formButton = (label: string, action: () => void, disabled = false) => (
		<button
			className="flex w-full items-center justify-center gap-1.5 rounded-md bg-primary px-3 py-2 text-xs font-medium text-primary-foreground disabled:opacity-50"
			disabled={busy || disabled}
			onClick={action}
			type="button"
		>
			{busy ? (
				<Loader2 className="h-3.5 w-3.5 animate-spin" />
			) : (
				<FileSearch className="h-3.5 w-3.5" />
			)}
			{label}
		</button>
	);

	return (
		<div className="flex h-full min-h-0 flex-col">
			<div className="flex shrink-0 flex-wrap items-center gap-1 border-b border-border px-3 py-2">
				{modes.map((item) => (
					<button
						className={cn(
							"flex items-center gap-1.5 rounded-md px-2 py-1.5 text-sm",
							mode === item.id
								? "bg-secondary text-foreground"
								: "text-muted-foreground hover:text-foreground",
						)}
						key={item.id}
						onClick={() => setMode(item.id)}
						type="button"
					>
						<item.icon className="h-3.5 w-3.5" />
						{item.label}
					</button>
				))}
				<button
					aria-label="Refresh diagnostics"
					className="ml-auto rounded-md p-1.5 text-muted-foreground hover:bg-secondary"
					disabled={loadingDiscovery}
					onClick={() => void discover("fast")}
					type="button"
				>
					<RefreshCw
						className={cn("h-3.5 w-3.5", loadingDiscovery && "animate-spin")}
					/>
				</button>
			</div>
			<div className="grid min-h-0 flex-1 grid-cols-1 overflow-hidden lg:grid-cols-[380px_minmax(0,1fr)]">
				<div className="overflow-auto border-b border-border p-4 lg:border-b-0 lg:border-r">
					{(mode === "notebook" || mode === "graph") && (
						<AnalysisAuthoring
							key={mode}
							kind={mode}
							common={common}
							onPrepare={(request) => prepare("static", request)}
						/>
					)}
					{mode === "execution" && (
						<ExecutionWorkspace cwd={cwd} environmentId={environmentId} />
					)}
					{mode === "incidents" && (
						<ApkIncidentWorkspace cwd={cwd} environmentId={environmentId} />
					)}
					{mode === "investigation" && (
						<InvestigationWorkspace
							cwd={cwd}
							environmentId={environmentId}
							onSelect={setInvestigationId}
							selectedId={investigationId}
						/>
					)}
					{mode === "runtime" && (
						<section className="space-y-4">
							<h3 className="text-base font-semibold">
								Isolated native / Android capture
							</h3>
							<p className="text-sm text-muted-foreground">
								Requires an operator-provisioned disposable VM and compatible
								signed worker. The desktop does not execute a native sample.
								Signed operator claims are not hardware attestation.
							</p>
							<label htmlFor="runtime-operation">
								Runtime operation
								<select
									id="runtime-operation"
									value={runtimeOperation}
									onChange={(e) => setRuntimeOperation(e.target.value)}
								>
									<option value="trace_native_region">
										Existing QBDI native trace
									</option>
									<option value="android_capture">
										Authorized Android loader / JNI capture
									</option>
								</select>
							</label>
							{runtimeOperation === "android_capture" && (
								<>
									<label htmlFor="android-package">
										Exact APK package
										<Input
											id="android-package"
											value={androidPackage}
											onChange={(e) => setAndroidPackage(e.target.value)}
										/>
									</label>
									<label>
										<input
											type="checkbox"
											checked={captureDex}
											onChange={(e) => setCaptureDex(e.target.checked)}
										/>{" "}
										Capture sensitive recovered DEX bytes into
										.cline/android-captures (requires explicit approval)
									</label>
									<label>
										<input
											type="checkbox"
											checked={captureNative}
											onChange={(e) => setCaptureNative(e.target.checked)}
										/>{" "}
										Capture authorized app native disk modules (max 4, 2 MiB
										each; not loaded-memory proof)
									</label>
									<p className="text-xs">
										The isolated worker must enforce reset, denied target egress
										and cleanup. Supported loader hooks have limited coverage;
										no key recovery or anti-instrumentation bypass. Native
										hashes may remain unresolved.
									</p>
									<label htmlFor="android-recovery">
										Previously approved Android plan ID
										<Input
											id="android-recovery"
											value={recoveryPlanId}
											onChange={(e) => setRecoveryPlanId(e.target.value)}
										/>
									</label>
									<Button
										disabled={!recoveryPlanId}
										onClick={() =>
											void desktopClient
												.invoke("recover_android_capture", {
													...common,
													planId: recoveryPlanId,
													confirmCaptureWrite: true,
												})
												.then(setResult)
												.catch((e) =>
													toast({
														variant: "destructive",
														title: "Recovery did not complete",
														description: e.message,
													}),
												)
										}
									>
										Retrieve captured plaintext from approved job — no
										re-execution
									</Button>
								</>
							)}
							<label htmlFor="runtime-artifact-path" className="block text-sm">
								Artifact path
								<Input
									id="runtime-artifact-path"
									aria-label="Runtime artifact path"
									value={target}
									onChange={(e) => setTarget(e.target.value)}
								/>
							</label>
							<label htmlFor="runtime-symbol" className="block text-sm">
								Exported function symbol
								<Input
									id="runtime-symbol"
									aria-label="Runtime symbol"
									value={runtimeSymbol}
									onChange={(e) => setRuntimeSymbol(e.target.value)}
								/>
							</label>
							<label className="block text-sm">
								Architecture
								<select
									className="min-h-11 w-full rounded-md border border-input bg-background px-3"
									value={architecture}
									onChange={(e) => setArchitecture(e.target.value)}
								>
									<option value="x86_64">x86-64</option>
									<option value="arm64">ARM64</option>
								</select>
							</label>
							<p className="text-sm text-muted-foreground">
								Worker endpoint, key fingerprint and artifact identity are bound
								to approval. Upload and authorized execution require separate
								acknowledgments. Worker egress stays disabled.
							</p>
							{formButton(
								"Prepare isolated-runtime task",
								() =>
									void prepare("dynamic", {
										...(runtimeOperation === "android_capture"
											? {
													operation: "android_capture",
													package_name: androidPackage,
													capture_dex: captureDex,
													capture_native: captureNative,
													output_directory: ".cline/android-captures",
												}
											: {
													operation: "trace_native_region",
													symbol: runtimeSymbol,
													architecture,
													instruction_limit: 10000,
												}),
										target: target.trim(),
										timeout_ms: 60000,
									}),
								!target.trim(),
							)}
						</section>
					)}
					{mode === "analyze" && (
						<div className="space-y-4">
							<div>
								<h3 className="text-sm font-semibold">
									Static reverse engineering
								</h3>
								<p className="mt-1 text-xs text-muted-foreground">
									Prepare an immutable task plan first. Files are analyzed as
									data and never executed.
								</p>
							</div>
							<label
								className="block text-xs font-medium"
								htmlFor="analysis-artifact-path"
							>
								Artifact path
								<Input
									className="mt-1.5 h-9 font-mono text-xs"
									id="analysis-artifact-path"
									onChange={(event) => setTarget(event.target.value)}
									placeholder="Workspace-relative or absolute path"
									value={target}
								/>
							</label>
							<div className="grid grid-cols-2 gap-2">
								<label className="text-xs font-medium">
									Operation
									<select
										className="mt-1.5 h-9 w-full rounded-md border border-input bg-background px-2 text-xs"
										onChange={(event) =>
											setOperation(event.target.value as AnalysisOperation)
										}
										value={operation}
									>
										<option value="inspect">Inspect</option>
										<option value="advanced_analysis">Advanced suite</option>
										<option value="scan_strings">Scan strings</option>
										<option value="forensic_report">Forensic report</option>
										<option value="apk_security_report">APK security</option>
										<option value="verify_apk_signature">APK signature</option>
										<option value="analyze">Headless analysis</option>
										<option value="decompile">Decompile</option>
										<option value="disassemble_smali">Smali</option>
									</select>
								</label>
								<label className="text-xs font-medium">
									Engine
									<select
										className="mt-1.5 h-9 w-full rounded-md border border-input bg-background px-2 text-xs"
										onChange={(event) => setEngine(event.target.value)}
										value={engine}
									>
										<option value="auto">Auto</option>
										<option value="ghidra">Ghidra</option>
										<option value="ida">IDA</option>
										<option value="jadx">JADX</option>
									</select>
								</label>
							</div>
							{operation === "decompile" && (
								<label className="block text-xs">
									Targeted decompiler options JSON
									<textarea
										aria-label="Targeted decompiler options JSON"
										className="mt-2 min-h-24 w-full rounded-md border border-input bg-background p-3 font-mono text-sm"
										value={decompilerOptions}
										onChange={(event) =>
											setDecompilerOptions(event.target.value)
										}
									/>
									<span className="mt-2 block text-muted-foreground">
										Ghidra/IDA: function_selector with one symbol or hex entry
										address. JADX: jadx_single_class. Requires an installed
										compatible engine; no target execution or license bypass.
										Opt in to a bounded persistent Ghidra/IDA worker with
										managed_worker=true and confirm_managed_worker=true; review
										the separate process/private-project approvals.
									</span>
								</label>
							)}
							{operation === "advanced_analysis" && (
								<label className="block text-xs font-medium">
									Advanced function
									<select
										aria-label="Advanced function"
										className="mt-1.5 h-9 w-full rounded-md border border-input bg-background px-2 text-xs"
										value={advancedAction}
										onChange={(event) => setAdvancedAction(event.target.value)}
									>
										<option value="artifact_discovery">
											Bounded hidden DEX / container discovery
										</option>
										<option value="android_relationships">
											DEX loader references / JNI name candidates
										</option>
										<option value="android_method">
											Exact DEX method metadata
										</option>
										<option value="android_method_code">
											Exact DEX bytecode / operands
										</option>
										<option value="native_function">
											Exact native symbol / entry disassembly
										</option>
										<option value="analysis_readiness">
											Static engine fixture self-tests
										</option>
										<option value="investigation_graph">
											Graph from saved investigation index
										</option>
										<option value="investigation_query">
											Query saved investigation index
										</option>
										<option value="suite">Structural suite</option>
										<option value="toolchain">Optional engine inventory</option>
										<option value="dex_index">
											DEX methods and invoke operands
										</option>
										<option value="apk_inventory">
											APK / multidex inventory
										</option>
										<option value="native_inventory">
											ELF / JNI export candidates
										</option>
										<option value="simplify_expression">
											Z3 expression simplification
										</option>
										<option value="triton_expression">
											Triton expression simplification
										</option>
										<option value="compare_expressions">
											Expression equivalence
										</option>
										<option value="triage">Blob triage</option>
										<option value="cfg_analyze">CFG dominance and loops</option>
										<option value="trace_slice">Imported trace slice</option>
										<option value="trace_taint">
											Imported trace influence
										</option>
										<option value="lift_native_ir">Miasm bounded IR</option>
										<option value="deobfuscation_pass">
											Miasm expression pass
										</option>
										<option value="native_disassemble">
											Native range disassembly
										</option>
										<option value="decrypt_blob">
											Known-key authenticated decryption
										</option>
										<option value="graph_build">
											Build graph from result manifest
										</option>
									</select>
									<span className="mt-3 block">Advanced options JSON</span>
									<textarea
										aria-label="Advanced options JSON"
										className="mt-2 min-h-24 w-full rounded-md border border-input bg-background p-3 font-mono text-sm"
										value={advancedOptions}
										onChange={(e) => setAdvancedOptions(e.target.value)}
									/>
									<p className="mt-2 text-xs font-normal text-muted-foreground">
										Discovery and exact-method lookup use the fixed stdlib
										Python worker (Python must be available). Successful
										investigations save a private index; use its returned file
										as the query target. JNI export matches and loader
										references are static candidates, not verified runtime
										relationships. Exact bytecode/native analysis needs the
										optional Androguard/LIEF/Capstone engines; fixture
										self-tests verify only owned samples. Optional engines are
										installed separately. Missing engines are blocked. Runtime
										and licensed adapters are not enabled here.
									</p>
								</label>
							)}
							<label className="flex items-start gap-2 text-xs">
								<input
									checked={allowExternalTarget}
									className="mt-0.5"
									onChange={(event) =>
										setAllowExternalTarget(event.target.checked)
									}
									type="checkbox"
								/>
								<span>
									Allow this explicitly reviewed path outside workspace.
								</span>
							</label>
							{formButton(
								"Prepare static-analysis task",
								() => void prepareStatic("static"),
								!target.trim() &&
									!(
										operation === "advanced_analysis" &&
										advancedAction === "toolchain"
									),
							)}
							<button
								className="w-full rounded-md border border-border px-3 py-2 text-xs hover:bg-secondary disabled:opacity-50"
								disabled={busy || !target.trim()}
								onClick={() => void prepareStatic("gui")}
								type="button"
							>
								Prepare external GUI launch
							</button>
						</div>
					)}
					{mode === "debug" && (
						<div className="space-y-4">
							<div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
								<div className="flex items-center gap-2 text-xs font-semibold text-amber-600 dark:text-amber-300">
									<ShieldAlert className="h-4 w-4" />
									Authorized targets only
								</div>
								<p className="mt-1 text-sm text-muted-foreground">
									Every action gets an exact, one-time approval token.
								</p>
							</div>
							<label className="block text-xs font-medium">
								Operation
								<select
									className="mt-1.5 h-9 w-full rounded-md border border-input bg-background px-2 text-xs"
									onChange={(event) =>
										setDebugOperation(event.target.value as DebugOperation)
									}
									value={debugOperation}
								>
									<option value="inspect_dump">Inspect crash dump</option>
									<option value="launch">Launch under debugger</option>
									<option value="attach_snapshot">Attach snapshot</option>
									<option value="backtrace">Backtrace</option>
									<option value="registers">Registers</option>
									<option value="read_memory">Read memory</option>
									<option value="disassemble">Disassemble</option>
									<option value="continue">Continue</option>
									<option value="step">Step</option>
								</select>
							</label>
							<Input
								className="h-9 font-mono text-xs"
								onChange={(event) => setTarget(event.target.value)}
								placeholder="Executable or dump path"
								value={target}
							/>
							<div className="grid grid-cols-2 gap-2">
								<Input
									className="h-9 font-mono text-xs"
									inputMode="numeric"
									onChange={(event) => setPid(event.target.value)}
									placeholder="PID"
									value={pid}
								/>
								<Input
									className="h-9 font-mono text-xs"
									onChange={(event) => setAddress(event.target.value)}
									placeholder="Address (0x401000)"
									value={address}
								/>
							</div>
							<label className="flex items-start gap-2 text-xs">
								<input
									checked={authorized}
									className="mt-0.5"
									onChange={(event) => setAuthorized(event.target.checked)}
									type="checkbox"
								/>
								<span>I own or am authorized to inspect this target.</span>
							</label>
							{(["continue", "step", "launch"] as string[]).includes(
								debugOperation,
							) && (
								<label className="flex items-start gap-2 text-xs">
									<input
										checked={executionConfirmed}
										className="mt-0.5"
										onChange={(event) =>
											setExecutionConfirmed(event.target.checked)
										}
										type="checkbox"
									/>
									<span>I approve target execution control.</span>
								</label>
							)}
							{formButton(
								"Prepare debugger task",
								() => void prepareDebugger(),
								!authorized ||
									((["continue", "step", "launch"] as string[]).includes(
										debugOperation,
									) &&
										!executionConfirmed),
							)}
						</div>
					)}
					{mode === "approvals" && (
						<div className="space-y-3">
							<h3 className="text-sm font-semibold">Approval boundary</h3>
							{pendingPlan ? (
								<>
									<pre className="whitespace-pre-wrap rounded-lg border bg-muted/30 p-3 text-sm">
										{pretty(pendingPlan)}
									</pre>
									{pendingPlan.kind === "dynamic" && (
										<div className="space-y-3 text-sm">
											<label className="flex min-h-11 items-start gap-3">
												<input
													type="checkbox"
													checked={uploadConfirmed}
													onChange={(e) => setUploadConfirmed(e.target.checked)}
												/>
												I approve uploading this exact artifact to the reviewed
												worker.
											</label>
											<label className="flex min-h-11 items-start gap-3">
												<input
													type="checkbox"
													checked={runtimeConfirmed}
													onChange={(e) =>
														setRuntimeConfirmed(e.target.checked)
													}
												/>
												I am authorized to execute this exact artifact in that
												isolated worker with egress disabled.
											</label>
										</div>
									)}
									{formButton(
										"Approve exact plan and run",
										() => void approveAndRun(),
										pendingPlan.kind === "dynamic" &&
											(!uploadConfirmed || !runtimeConfirmed),
									)}
									<button
										className="w-full rounded-md border border-border px-3 py-2 text-xs hover:bg-secondary disabled:opacity-50"
										disabled={busy}
										onClick={() => void cancelPlan(pendingPlan.id)}
										type="button"
									>
										Cancel plan
									</button>
								</>
							) : (
								<p className="text-xs text-muted-foreground">
									No plan is waiting for approval.
								</p>
							)}
						</div>
					)}
					{mode === "tasks" && (
						<div className="space-y-2">
							<h3 className="text-sm font-semibold">Task ledger</h3>
							{tasks.length === 0 ? (
								<p className="text-xs text-muted-foreground">No tasks yet.</p>
							) : (
								tasks.map((task) => (
									<div className="rounded-lg border p-2" key={task.id}>
										<button
											className="w-full p-1 text-left hover:bg-secondary"
											onClick={() => setResult(task)}
											type="button"
										>
											<div className="flex justify-between text-xs font-medium">
												<span>{task.operation}</span>
												<span>{task.status}</span>
											</div>
											<div className="mt-1 text-[10px] text-muted-foreground">
												{task.permission} · {task.risk} risk
											</div>
										</button>
										{["awaiting-approval", "approved", "running"].includes(
											task.status,
										) && (
											<button
												className="mt-2 rounded border px-2 py-1 text-[10px] hover:bg-secondary"
												onClick={() => void cancelPlan(task.id)}
												type="button"
											>
												Cancel
											</button>
										)}
									</div>
								))
							)}
						</div>
					)}
					{mode === "terminal" && (
						<div className="space-y-3">
							<h3 className="text-sm font-semibold">Terminal safety</h3>
							<p className="text-xs text-muted-foreground">
								Use the dedicated Workspace Terminal for interactive shell work.
								It negotiates ConPTY/PTY and falls back to bounded pipes when
								the runtime lacks terminal support.
							</p>
							<pre className="whitespace-pre-wrap rounded-lg border bg-muted/30 p-3 text-sm">
								{pretty(diagnostics)}
							</pre>
						</div>
					)}
					{mode === "diagnostics" && (
						<div className="space-y-3">
							<div className="flex items-center justify-between">
								<h3 className="text-sm font-semibold">
									IDA, Ghidra and runtime health
								</h3>
								<button
									className="rounded-md border px-2 py-1 text-sm"
									disabled={loadingDiscovery}
									onClick={() => void discover("deep")}
									type="button"
								>
									Deep check
								</button>
							</div>
							<pre className="whitespace-pre-wrap rounded-lg border bg-muted/30 p-3 text-sm">
								{pretty({ diagnostics, discovery })}
							</pre>
						</div>
					)}
					{mode === "evidence" && (
						<div className="space-y-3">
							<h3 className="text-sm font-semibold">Evidence ledger</h3>
							<p className="text-xs text-muted-foreground">
								Results include a SHA-256 evidence hash and bounded output
								paths.
							</p>
							{tasks
								.filter((task) => task.evidence)
								.map((task) => (
									<div
										className="space-y-2 rounded-lg border bg-muted/30 p-3 text-sm"
										key={task.id}
									>
										<div className="flex items-center justify-between">
											<strong>{task.operation}</strong>
											<span>{task.evidence?.tool}</span>
										</div>
										<div className="break-all font-mono text-[10px] text-muted-foreground">
											Request: {task.requestHash}
											<br />
											Result: {task.evidence?.resultHash}
										</div>
										{task.evidence?.outputPaths.map((path) => (
											<button
												className="block max-w-full truncate text-left text-primary hover:underline"
												key={path}
												onClick={() => void openEvidenceArtifact(path)}
												title={path}
												type="button"
											>
												{path}
											</button>
										))}
										<button
											className="rounded-md border border-border px-2 py-1 text-[10px] hover:bg-secondary"
											onClick={() => void exportEvidence(task.id)}
											type="button"
										>
											Export evidence bundle
										</button>
									</div>
								))}
						</div>
					)}
				</div>
				<div className="min-h-0 overflow-auto bg-muted/10 p-4">
					<div className="mb-2 flex items-center gap-2 text-xs font-medium">
						<Activity className="h-3.5 w-3.5" />
						Supervised output
					</div>
					<pre className="min-h-48 whitespace-pre-wrap break-words rounded-lg border border-border bg-background p-4 font-mono text-xs leading-5">
						{busy
							? "Running bounded operation…"
							: result === null
								? "Task results, evidence hashes, tool versions and generated paths appear here."
								: pretty(result)}
					</pre>
				</div>
			</div>
		</div>
	);
}
