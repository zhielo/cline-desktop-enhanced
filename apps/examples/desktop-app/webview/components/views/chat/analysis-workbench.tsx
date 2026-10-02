"use client";

import {
	Activity,
	Binary,
	Bug,
	ExternalLink,
	FileSearch,
	Loader2,
	RefreshCw,
	ShieldAlert,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Input } from "@/components/ui/input";
import { toast } from "@/hooks/use-toast";
import { desktopClient } from "@/lib/desktop-client";
import { cn } from "@/lib/utils";

type WorkbenchMode = "analyze" | "debug" | "tools";
type Discovery = { reverseEngineering?: unknown; debugger?: unknown };

type AnalysisOperation =
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
	const [loadingDiscovery, setLoadingDiscovery] = useState(false);
	const [target, setTarget] = useState("");
	const [operation, setOperation] = useState<AnalysisOperation>("inspect");
	const [engine, setEngine] = useState("auto");
	const [debugOperation, setDebugOperation] =
		useState<DebugOperation>("inspect_dump");
	const [pid, setPid] = useState("");
	const [address, setAddress] = useState("");
	const [authorized, setAuthorized] = useState(false);
	const [executionConfirmed, setExecutionConfirmed] = useState(false);
	const [busy, setBusy] = useState(false);
	const [result, setResult] = useState<unknown>(null);
	const common = useMemo(
		() => ({ environmentId, ...(cwd?.trim() ? { cwd } : {}) }),
		[cwd, environmentId],
	);

	const discover = useCallback(async () => {
		setLoadingDiscovery(true);
		try {
			setDiscovery(
				await desktopClient.invoke<Discovery>(
					"discover_analysis_tools",
					common,
				),
			);
		} catch (error) {
			toast({
				variant: "destructive",
				title: "Tool discovery failed",
				description:
					error instanceof Error
						? error.message
						: "Could not inspect installed tools.",
			});
		} finally {
			setLoadingDiscovery(false);
		}
	}, [common]);
	useEffect(() => {
		void discover();
	}, [discover]);

	const runAnalysis = async () => {
		if (!target.trim()) return;
		setBusy(true);
		setResult(null);
		try {
			const response = await desktopClient.invoke<{ result: unknown }>(
				"run_static_analysis",
				{
					...common,
					input: {
						engine,
						operation,
						target: target.trim(),
						reuse_analysis: true,
						report_format: "json",
					},
				},
			);
			setResult(response.result);
		} catch (error) {
			toast({
				variant: "destructive",
				title: "Analysis failed",
				description:
					error instanceof Error
						? error.message
						: "The analysis operation failed.",
			});
		} finally {
			setBusy(false);
		}
	};

	const openGui = async () => {
		if (!target.trim()) return;
		setBusy(true);
		try {
			const response = await desktopClient.invoke<{ result: unknown }>(
				"open_analysis_gui",
				{
					...common,
					confirmLaunch: true,
					input: { engine, target: target.trim() },
				},
			);
			setResult(response.result);
		} catch (error) {
			toast({
				variant: "destructive",
				title: "Could not open analysis tool",
				description:
					error instanceof Error ? error.message : "GUI launch failed.",
			});
		} finally {
			setBusy(false);
		}
	};

	const runDebugger = async () => {
		if (!authorized) return;
		setBusy(true);
		setResult(null);
		const numericPid = Number(pid);
		const input: Record<string, unknown> = {
			operation: debugOperation,
			debugger: "auto",
			target_kind: "local",
			acknowledge_risk: true,
		};
		if (target.trim()) input.target = target.trim();
		if (Number.isInteger(numericPid) && numericPid > 0) input.pid = numericPid;
		if (address.trim()) input.address = address.trim();
		if (debugOperation === "continue" || debugOperation === "step")
			input.confirm_execution_control = executionConfirmed;
		try {
			const response = await desktopClient.invoke<{ result: unknown }>(
				"run_debugger_action",
				{ ...common, confirmAuthorized: true, input },
			);
			setResult(response.result);
		} catch (error) {
			toast({
				variant: "destructive",
				title: "Debugger action failed",
				description:
					error instanceof Error
						? error.message
						: "The supervised debugger action failed.",
			});
		} finally {
			setBusy(false);
		}
	};

	return (
		<div className="flex h-full min-h-0 flex-col">
			<div className="flex shrink-0 items-center gap-1 border-b border-border px-3 py-2">
				{(["analyze", "debug", "tools"] as const).map((item) => (
					<button
						className={cn(
							"flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs capitalize",
							mode === item
								? "bg-secondary text-foreground"
								: "text-muted-foreground hover:text-foreground",
						)}
						key={item}
						onClick={() => setMode(item)}
						type="button"
					>
						{item === "analyze" ? (
							<Binary className="h-3.5 w-3.5" />
						) : item === "debug" ? (
							<Bug className="h-3.5 w-3.5" />
						) : (
							<Activity className="h-3.5 w-3.5" />
						)}
						{item}
					</button>
				))}
				<button
					aria-label="Refresh tool discovery"
					className="ml-auto rounded-md p-1.5 text-muted-foreground hover:bg-secondary"
					disabled={loadingDiscovery}
					onClick={() => void discover()}
					type="button"
				>
					<RefreshCw
						className={cn("h-3.5 w-3.5", loadingDiscovery && "animate-spin")}
					/>
				</button>
			</div>
			<div className="grid min-h-0 flex-1 grid-cols-1 overflow-hidden lg:grid-cols-[360px_minmax(0,1fr)]">
				<div className="overflow-auto border-b border-border p-4 lg:border-b-0 lg:border-r">
					{mode === "analyze" && (
						<div className="space-y-4">
							<div>
								<h3 className="text-sm font-semibold">Static analysis</h3>
								<p className="mt-1 text-xs text-muted-foreground">
									Analyze binaries and APKs as data. Targets are never executed
									automatically.
								</p>
							</div>
							<label
								className="block text-xs font-medium"
								htmlFor="analysis-target"
							>
								Artifact path
								<Input
									id="analysis-target"
									className="mt-1.5 h-9 font-mono text-xs"
									onChange={(event) => setTarget(event.target.value)}
									placeholder="C:\\path\\sample.exe or workspace-relative path"
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
										<option value="scan_strings">Scan strings</option>
										<option value="forensic_report">Forensic report</option>
										<option value="apk_security_report">APK security</option>
										<option value="verify_apk_signature">
											Verify APK signature
										</option>
										<option value="analyze">Headless analysis</option>
										<option value="decompile">Decompile</option>
										<option value="disassemble_smali">Disassemble Smali</option>
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
							<div className="flex gap-2">
								<button
									className="flex flex-1 items-center justify-center gap-1.5 rounded-md bg-primary px-3 py-2 text-xs font-medium text-primary-foreground disabled:opacity-50"
									disabled={busy || !target.trim()}
									onClick={() => void runAnalysis()}
									type="button"
								>
									{busy ? (
										<Loader2 className="h-3.5 w-3.5 animate-spin" />
									) : (
										<FileSearch className="h-3.5 w-3.5" />
									)}
									Run analysis
								</button>
								<button
									className="flex items-center gap-1.5 rounded-md border border-border px-3 py-2 text-xs hover:bg-secondary disabled:opacity-50"
									disabled={busy || !target.trim()}
									onClick={() => void openGui()}
									type="button"
								>
									<ExternalLink className="h-3.5 w-3.5" />
									Open GUI
								</button>
							</div>
						</div>
					)}
					{mode === "debug" && (
						<div className="space-y-4">
							<div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
								<div className="flex items-center gap-2 text-xs font-semibold text-amber-600 dark:text-amber-300">
									<ShieldAlert className="h-4 w-4" />
									Authorized targets only
								</div>
								<p className="mt-1 text-[11px] text-muted-foreground">
									Debugger actions are bounded and one-shot. This is not a
									persistent hidden debugger session.
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
							<label
								className="block text-xs font-medium"
								htmlFor="debug-target"
							>
								Executable or dump path
								<Input
									id="debug-target"
									className="mt-1.5 h-9 font-mono text-xs"
									onChange={(event) => setTarget(event.target.value)}
									value={target}
								/>
							</label>
							<div className="grid grid-cols-2 gap-2">
								<label className="text-xs font-medium" htmlFor="debug-pid">
									PID
									<Input
										id="debug-pid"
										className="mt-1.5 h-9 font-mono text-xs"
										inputMode="numeric"
										onChange={(event) => setPid(event.target.value)}
										value={pid}
									/>
								</label>
								<label className="text-xs font-medium" htmlFor="debug-address">
									Address
									<Input
										id="debug-address"
										className="mt-1.5 h-9 font-mono text-xs"
										onChange={(event) => setAddress(event.target.value)}
										placeholder="0x401000"
										value={address}
									/>
								</label>
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
							{(debugOperation === "continue" || debugOperation === "step") && (
								<label className="flex items-start gap-2 text-xs">
									<input
										checked={executionConfirmed}
										className="mt-0.5"
										onChange={(event) =>
											setExecutionConfirmed(event.target.checked)
										}
										type="checkbox"
									/>
									<span>
										I understand this operation resumes target execution.
									</span>
								</label>
							)}
							<button
								className="flex w-full items-center justify-center gap-1.5 rounded-md bg-primary px-3 py-2 text-xs font-medium text-primary-foreground disabled:opacity-50"
								disabled={
									busy ||
									!authorized ||
									((debugOperation === "continue" ||
										debugOperation === "step") &&
										!executionConfirmed)
								}
								onClick={() => void runDebugger()}
								type="button"
							>
								{busy ? (
									<Loader2 className="h-3.5 w-3.5 animate-spin" />
								) : (
									<Bug className="h-3.5 w-3.5" />
								)}
								Run supervised debugger
							</button>
						</div>
					)}
					{mode === "tools" && (
						<div className="space-y-3">
							<div>
								<h3 className="text-sm font-semibold">Tool health</h3>
								<p className="mt-1 text-xs text-muted-foreground">
									Detected versions, executable paths, capabilities and setup
									recommendations.
								</p>
							</div>
							{loadingDiscovery ? (
								<div className="grid place-items-center py-16">
									<Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
								</div>
							) : (
								<pre className="overflow-auto whitespace-pre-wrap break-words rounded-lg border bg-muted/30 p-3 font-mono text-[11px] leading-5">
									{pretty(discovery ?? "No discovery result.")}
								</pre>
							)}
						</div>
					)}
				</div>
				<div className="min-h-0 overflow-auto bg-muted/10 p-4">
					<div className="mb-2 flex items-center gap-2 text-xs font-medium">
						<Activity className="h-3.5 w-3.5" />
						Evidence and output
					</div>
					<pre className="min-h-48 whitespace-pre-wrap break-words rounded-lg border border-border bg-background p-4 font-mono text-xs leading-5">
						{busy
							? "Running supervised operation…"
							: result === null
								? "Analysis results, hashes, tool versions and generated artifact paths appear here."
								: pretty(result)}
					</pre>
				</div>
			</div>
		</div>
	);
}
