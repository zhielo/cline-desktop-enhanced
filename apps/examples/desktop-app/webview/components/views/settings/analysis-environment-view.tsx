"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { desktopClient } from "@/lib/desktop-client";
import { OptimizationPanel } from "./optimization-panel";
import { PageFrame, PageHeader } from "../page-layout";
const EXTERNAL_STATUS_LABEL = "Configuration / acceptance required";

type Check = {
	engine: string;
	status: string;
	executionVerified: boolean;
	version?: string;
	reason?: string;
};
type Result = {
  setupCenter?: {
    desktopBuild?: {version:string; sourceCommit:string};
    selectedRuntime?: {runtimeId?:string};
    fullStatus?: string;
    licensedArchitectures?: string[];
  };
	checkedAt: string;
	configured: boolean;
	runtime?: { source: string; runtimeId?: string };
	interpreter: { executable?: string | null; version?: string | null };
	readiness: {
		status: string;
		evidence: { checks?: Check[]; reason?: string };
		diagnostics?: { receiptPath?: string; stderrTail?: string };
	};
	toolchain: {
		status: string;
		evidence: {
			reason?: string;
			engines?: { id: string; installedVersion: string | null }[];
		};
		diagnostics?: {
			receiptPath?: string;
			stderrTail?: string;
			category?: string;
		};
	};
	externalCapabilities: { id: string; status: string; reason: string }[];
	setup: string;
};

export function AnalysisEnvironmentView({onOpenSetup}: {onOpenSetup?: () => void} = {}) {
  const [liveJobs, setLiveJobs] = useState(false);
	const [result, setResult] = useState<Result | null>(null);
	const [busy, setBusy] = useState(false);
	const [repairMessage, setRepairMessage] = useState("");
	const repair = async () => {
		if (
			!window.confirm(
				"Restore the bundled analysis runtime from installed app resources? This does not install IDA, change licenses, or run a target binary. Restart the app afterwards.",
			)
		)
			return;
		setBusy(true);
		setError("");
		try {
			const reply = await desktopClient.invoke<{ message: string }>(
				"repair_analysis_runtime",
				{ environmentId: "local", confirmed: true },
				{ timeoutMs: 180000 },
			);
			setRepairMessage(reply.message);
		} catch (cause) {
			setError(
				cause instanceof Error ? cause.message : "Runtime repair failed",
			);
		} finally {
			setBusy(false);
		}
	};
	const [error, setError] = useState("");
	const [jobs, setJobs] = useState<
		{
			id: string;
			pid: number | null;
			status: string;
			lastPhase: string;
			receiptPath: string;
      elapsedMs?: number; remainingMs?: number | null; deadlineAt?: string | null;
      phaseTimeoutMs?: number; phaseDeadlineAt?: string; lastPhaseAt?: string; timeoutPhase?: string;
      stateMeaning?: string;
		}[]
	>([]);
	const refreshJobs = async () => {
		try {
			const reply = await desktopClient.invoke<{ jobs: typeof jobs }>(
				"get_ida_job_diagnostics",
				{ environmentId: "local" },
			);
			setJobs(reply.jobs);
		} catch (cause) {
			setError(
				cause instanceof Error
					? cause.message
					: "IDA job diagnostics unavailable",
			);
		}
	};
  useEffect(() => {
    if (!liveJobs) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const poll = async () => {
      try {
        const reply = await desktopClient.invoke<{jobs:typeof jobs}>("get_ida_job_diagnostics", {environmentId:"local"});
        if (!cancelled) setJobs(reply.jobs);
      } catch (cause) {
        if (!cancelled) setError(cause instanceof Error ? cause.message : "IDA job diagnostics unavailable");
      } finally { if (!cancelled) timer = setTimeout(poll, 2000); }
    };
    void poll();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [liveJobs]);
	const check = async () => {
		setBusy(true);
		setError("");
		setResult(null);
		try {
			setResult(
				await desktopClient.invoke<Result>(
					"get_analysis_environment",
					{ environmentId: "local" },
					{ timeoutMs: 90_000 },
				),
			);
		} catch (cause) {
			setError(
				cause instanceof Error ? cause.message : "Readiness check failed",
			);
		} finally {
			setBusy(false);
		}
	};
	return (
		<PageFrame>
			<PageHeader title="Analysis environment" />
			<div
				className="space-y-4 overflow-auto p-6"
				data-testid="analysis-environment"
			>
				<p>
					Check the desktop backend’s actual Python interpreter and owned static
					fixtures. No target binary runs and no packages are installed.
				</p>
				<p>Bundled Python health does not validate IDA or its processor-specific Hex-Rays license.
          Core-pack inventory intentionally omits some full-pack engines. Use Setup Center for full-pack installation and ARM64/x86-64 IDA acceptance—no manual pip setup.</p>
        <Button onClick={onOpenSetup} disabled={!onOpenSetup} variant="outline">Open Setup Center</Button>
        <Button onClick={() => void check()} disabled={busy}>
					{busy ? "Checking environment…" : "Check analysis readiness"}
				</Button>
				<Button onClick={() => void repair()} disabled={busy} variant="outline">
					Repair bundled runtime
				</Button>
				{repairMessage && <output aria-live="polite">{repairMessage}</output>}
				<Button onClick={() => void refreshJobs()} variant="outline">
					Refresh IDA jobs
				</Button>
				<label className="block"><input type="checkbox" checked={liveJobs} onChange={event => setLiveJobs(event.target.checked)} /> Live read-only IDA job refresh (every 2 seconds)</label>
        <p>
					IDA progress is based on explicit script phases, not CPU totals or
					output-file existence. No process is killed or restarted by refresh.
				</p>
				<p>
					Job status is the last recorded host state, not a fresh
					process-identity or liveness check. Receipts from the Hub remain
					visible after desktop restart.
				</p>
				<ul>
					{jobs.map((job) => (
						<li key={job.id}>
							Job {job.id}: PID {job.pid ?? "not launched"} — {job.status};{" "}
							{job.lastPhase}. Elapsed {typeof job.elapsedMs === "number" ? `${Math.floor(job.elapsedMs/1000)}s` : "unknown"}; deadline remaining {typeof job.remainingMs === "number" ? `${Math.ceil(job.remainingMs/1000)}s` : "unknown"}.
              {job.timeoutPhase && ` Phase deadline exceeded at ${job.timeoutPhase}; this is a configured limit, not a proven hang.`}
              {job.phaseDeadlineAt && ` Phase deadline: ${job.phaseDeadlineAt}.`}
              {job.lastPhaseAt && ` Last script evidence: ${job.lastPhaseAt}.`}
              {` ${job.stateMeaning ?? "Last recorded host state; not a liveness check"}.`} Receipt: <code>{job.receiptPath}</code>
						</li>
					))}
				</ul>
				{error && <p role="alert">{error}</p>}
				<OptimizationPanel />
				{result && (
					<div aria-live="polite" className="space-y-4">
						<p>Installed desktop: {result.setupCenter?.desktopBuild?.version ?? "Unknown"}; build <code>{result.setupCenter?.desktopBuild?.sourceCommit ?? "Unknown"}</code>.
              Selected runtime: <code>{result.setupCenter?.selectedRuntime?.runtimeId ?? result.runtime?.runtimeId ?? "Unknown"}</code>; full pack: {result.setupCenter?.fullStatus ?? "Open Setup Center"}.
              IDA processors with current executable-bound owned acceptance: {result.setupCenter?.licensedArchitectures?.join(", ") || "None verified"}.</p>
            <p>
							Interpreter:{" "}
							<code>{result.interpreter.executable ?? "Unavailable"}</code>
							<br />
							Version: {result.interpreter.version ?? "Not verified"}
							<br />
							{result.runtime?.source === "bundled"
								? "Bundled isolated runtime — no manual setup"
								: result.configured
									? "External configured interpreter"
									: "Development PATH fallback — installed Windows app includes its runtime"}
						</p>
						<p>
							Package inventory: {result.toolchain.status}. Fixture execution:{" "}
							{result.readiness.status}.
						</p>
						{result.toolchain.evidence.reason && (
							<p role="alert">{result.toolchain.evidence.reason}</p>
						)}
						{result.readiness.evidence.reason && (
							<p role="alert">{result.readiness.evidence.reason}</p>
						)}
						<ul>
							{result.readiness.evidence.checks?.map((item) => (
								<li key={item.engine}>
									<strong>{item.engine}</strong>:{" "}
									{item.executionVerified
										? "Ready — owned fixture passed"
										: item.status === "blocked"
											? "Missing dependency"
											: "Failed"}{" "}
									{item.version && `(${item.version})`}
									{item.reason && <p>{item.reason}</p>}
								</li>
							))}
						</ul>
						<details>
							<summary>
								Package versions (inventory is not execution proof)
							</summary>
							<ul>
								{result.toolchain.evidence.engines?.map((engine) => (
									<li key={engine.id}>
										{engine.id}: {engine.installedVersion ?? "Not installed"}
									</li>
								))}
							</ul>
						</details>
						<ul>
							{result.externalCapabilities.map((item) => (
								<li key={item.id}>
									<strong>{item.id}</strong>: {result.setupCenter?.licensedArchitectures?.length && /IDA|Hex-Rays/i.test(item.id)
                    ? "Owned processor acceptance passed" : EXTERNAL_STATUS_LABEL}.{" "}
                  {result.setupCenter?.licensedArchitectures?.length && /IDA|Hex-Rays/i.test(item.id)
                    ? `Current executable acceptance covers ${result.setupCenter.licensedArchitectures.join(", ")}; other processors and target compatibility remain untested.` : item.reason}
								</li>
							))}
						</ul>
						{[result.toolchain, result.readiness].map(
							(item, index) =>
								item.diagnostics?.receiptPath && (
									<p key={index}>
										Redacted diagnostic receipt:{" "}
										<code>{item.diagnostics.receiptPath}</code>
									</p>
								),
						)}
						<p>{result.setup}</p>
						<p>
							Keystone is not required for the built-in Capstone disassembly
							path. Missing Python packages do not establish an IDA failure.
						</p>
					</div>
				)}
			</div>
		</PageFrame>
	);
}
