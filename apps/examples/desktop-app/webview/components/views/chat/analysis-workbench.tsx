"use client";

import {
	Activity,
	Binary,
	Bug,
  FileCheck2,
	FileSearch,
	Loader2,
  ListChecks,
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

type WorkbenchMode =
  | "tasks"
  | "analyze"
  | "debug"
  | "terminal"
  | "approvals"
  | "evidence"
  | "diagnostics";
type TaskKind = "static" | "debugger" | "gui" | "dynamic";
type TaskPlan = {
  id: string;
  kind: TaskKind;
  operation: string;
  target?: string;
  permission: string;
  status: string;
  requirements: string[];
  risk: string;
  budget: Record<string, unknown>;
  createdAt: string;
  evidence?: Record<string, unknown>;
  error?: string;
};
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

const modes: Array<{
  id: WorkbenchMode;
  icon: typeof Activity;
  label: string;
}> = [
  { id: "tasks", icon: ListChecks, label: "Tasks" },
  { id: "analyze", icon: Binary, label: "Analyze" },
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
	const [operation, setOperation] = useState<AnalysisOperation>("inspect");
	const [engine, setEngine] = useState("auto");
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
		() => ({ environmentId, ...(cwd?.trim() ? { cwd } : {}) }),
		[cwd, environmentId],
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

  const prepare = async (
    kind: TaskKind,
    selectedOperation: string,
    selectedTarget?: string,
  ) => {
		setBusy(true);
		setResult(null);
		try {
      const plan = await desktopClient.invoke<TaskPlan>(
        "prepare_analysis_task",
				{
					...common,
          kind,
          operation: selectedOperation,
          ...(selectedTarget?.trim() ? { target: selectedTarget.trim() } : {}),
          allowExternalTarget,
				},
			);
      setPendingPlan(plan);
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
		setBusy(true);
    setResult(null);
		try {
      const approved = await desktopClient.invoke<{
        executionToken: string;
      }>("approve_analysis_task", {
					...common,
        planId: pendingPlan.id,
        requirements: pendingPlan.requirements,
			});
      let response: { result: unknown; plan?: TaskPlan };
      if (pendingPlan.kind === "debugger") {
		const numericPid = Number(pid);
		const input: Record<string, unknown> = {
			operation: debugOperation,
			debugger: "auto",
			target_kind: "local",
			acknowledge_risk: true,
		};
		if (target.trim()) input.target = target.trim();
        if (Number.isInteger(numericPid) && numericPid > 0)
          input.pid = numericPid;
		if (address.trim()) input.address = address.trim();
		if (debugOperation === "continue" || debugOperation === "step")
			input.confirm_execution_control = executionConfirmed;
        response = await desktopClient.invoke("run_debugger_action", {
          ...common,
          planId: pendingPlan.id,
          executionToken: approved.executionToken,
          confirmAuthorized: true,
          input,
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
            input: {
              engine,
              operation,
              target: target.trim(),
              reuse_analysis: true,
              report_format: "json",
            },
          },
			);
      }
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
              "flex items-center gap-1.5 rounded-md px-2 py-1.5 text-[11px]",
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
              <label className="block text-xs font-medium">
								Artifact path
								<Input
									className="mt-1.5 h-9 font-mono text-xs"
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
                () => void prepare("static", operation, target),
                !target.trim(),
									)}
								<button
                className="w-full rounded-md border border-border px-3 py-2 text-xs hover:bg-secondary disabled:opacity-50"
									disabled={busy || !target.trim()}
                onClick={() => void prepare("gui", "open_gui", target)}
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
								<p className="mt-1 text-[11px] text-muted-foreground">
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
                () => void prepare("debugger", debugOperation, target),
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
                  <pre className="whitespace-pre-wrap rounded-lg border bg-muted/30 p-3 text-[11px]">
                    {pretty(pendingPlan)}
                  </pre>
                  {formButton(
                    "Approve exact plan and run",
                    () => void approveAndRun(),
                  )}
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
                  <button
                    className="w-full rounded-lg border p-3 text-left hover:bg-secondary"
                    key={task.id}
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
              <pre className="whitespace-pre-wrap rounded-lg border bg-muted/30 p-3 text-[11px]">
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
                  className="rounded-md border px-2 py-1 text-[11px]"
                  disabled={loadingDiscovery}
                  onClick={() => void discover("deep")}
                  type="button"
                >
                  Deep check
                </button>
								</div>
              <pre className="whitespace-pre-wrap rounded-lg border bg-muted/30 p-3 text-[11px]">
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
                  <pre
                    className="whitespace-pre-wrap rounded-lg border bg-muted/30 p-3 text-[10px]"
                    key={task.id}
                  >
                    {pretty(task)}
                  </pre>
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
