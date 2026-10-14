"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { desktopClient } from "@/lib/desktop-client";
import { BackendConnectionStatus } from "@/components/backend-connection-status";
type Status = {
	workspace: string;
	mode: string;
	artifacts: Array<{ id: string; path: string }>;
	scenarios: Array<{ id: string; purpose: string }>;
	browsers: Array<{ browserSessionId: string }>;
};
type Plan = {
	id: string;
	requestHash: string;
	requirements: string[];
	request: Record<string, unknown>;
};
export function InvestigationWorkflow({
	sessionId,
	environmentId,
	mode,
	receiptIds,
}: {
	sessionId: string;
	environmentId: string;
	mode: string;
	receiptIds: string[];
}) {
	const [open, setOpen] = useState(false),
		[status, setStatus] = useState<Status | null>(null),
		[target, setTarget] = useState(""),
		[artifactId, setArtifactId] = useState(""),
		[engine, setEngine] = useState("ghidra"),
		[symbol, setSymbol] = useState(""),
		[plan, setPlan] = useState<Plan | null>(null),
		[busy, setBusy] = useState(false),
		[error, setError] = useState(""),
		[result, setResult] = useState<unknown>(null),
		[browserId, setBrowserId] = useState(""),
		[recording, setRecording] = useState(""),
		[purpose, setPurpose] = useState(""),
		[feature, setFeature] = useState(""),
		[receiptId, setReceiptId] = useState(""),
		[scenarioId, setScenarioId] = useState(""),
		[taskId, setTaskId] = useState("");
	const revision = useRef(0),
		binding = useRef("");
	const current = `${sessionId}:${environmentId}:${mode}`;
	if (binding.current !== current) {
		binding.current = current;
		revision.current++;
	}
	const invoke = useCallback(
		<T,>(command: string, input: Record<string, unknown> = {}) =>
			desktopClient.invoke<T>(
				command,
				{ sessionId, environmentId, input },
				{ timeoutMs: 150000 },
			),
		[sessionId, environmentId],
	);
	useEffect(() => {
		if (binding.current !== current) return;
		setStatus(null);
		setPlan(null);
		setResult(null);
		setArtifactId("");
		setBrowserId("");
		setRecording("");
		setReceiptId("");
		setScenarioId("");
		setTaskId("");
		setBusy(false);
		setError("");
	}, [current]);
	useEffect(() => {
		if (!open || binding.current !== current) return;
		let disposed = false;
		const r = revision.current;
		void invoke<Status>("analysis_workflow_status")
			.then((s) => {
				if (!disposed && r === revision.current) setStatus(s);
			})
			.catch(() => {
				if (!disposed && r === revision.current)
					setError("Investigation status unavailable; no action replayed");
			});
		return () => {
			disposed = true;
		};
	}, [open, invoke, current]);
	const work = async (action: () => Promise<unknown>) => {
		const r = revision.current;
		setBusy(true);
		setError("");
		try {
			const value = await action();
			if (r !== revision.current) return;
			setResult(value);
			const s = await invoke<Status>("analysis_workflow_status");
			if (r === revision.current) setStatus(s);
		} catch (e) {
			if (r === revision.current)
				setError(
					e instanceof Error
						? e.message
						: "Operation failed; inspect state before retrying",
				);
		} finally {
			if (r === revision.current) setBusy(false);
		}
	};
	const invalidate = () => {
		revision.current++;
		setPlan(null);
	};
	const request = () => ({
		artifactId,
		engine,
		selector: symbol.startsWith("0x") ? { address: symbol } : { symbol },
	});
	const run = () => {
		const reviewed = plan;
		if (!reviewed) return;
		const r = revision.current;
		if (
			!window.confirm(
				`Authorize the reviewed exact function analysis? Required approvals: ${reviewed.requirements.join(", ")}. This launches the selected analysis engine, not the target application. No automatic retry.`,
			)
		)
			return;
		void work(async () => {
			setPlan(null);
			const approved = await desktopClient.invoke<{ executionToken: string }>(
				"approve_analysis_task",
				{
					sessionId,
					environmentId,
					cwd: status?.workspace,
					planId: reviewed.id,
					requirements: reviewed.requirements,
					requestHash: reviewed.requestHash,
				},
			);
			if (r !== revision.current)
				throw new Error(
					"Selection changed; approved operation was not launched",
				);
			const value = await invoke("analyze_function", {
				...request(),
				phase: "run",
				planId: reviewed.id,
				executionToken: approved.executionToken,
			});
			if (r === revision.current) setTaskId(reviewed.id);
			return value;
		});
	};
	return (
		<details
			open={open}
			onToggle={(e) => setOpen(e.currentTarget.open)}
			className="space-y-3 rounded border p-3 text-xs"
		>
			<summary className="font-semibold">
				Guided investigation: binary → function → scenario → evidence
			</summary>
			{open && (
				<>
					<BackendConnectionStatus />
					<p>
						Static candidates and browser metadata are not causal feature
						verification. Browser recording is Windows-only, opt-in,
						origin/console-count metadata only, bounded to 120 seconds / 256
						events. Stop explicitly to retain the receipt. New work requires a
						trusted idle local session and Analysis enabled.
					</p>
					<div className="flex flex-wrap gap-2">
						<input
							className="rounded border bg-background p-2"
							aria-label="Investigation binary path"
							value={target}
							disabled={busy}
							onChange={(e) => setTarget(e.target.value)}
							placeholder="Workspace-relative binary"
						/>
						<button
							type="button"
							className="rounded border bg-background px-3 py-2 disabled:opacity-50"
							disabled={busy || mode === "off" || !target.trim()}
							onClick={() => {
								const r = revision.current;
								void work(async () => {
									const v = await invoke<{ id: string }>("open_binary", {
										target,
									});
									if (r === revision.current) {
										setArtifactId(v.id);
										setPlan(null);
									}
									return v;
								});
							}}
						>
							Open immutable binary handle
						</button>
						<select
							className="rounded border bg-background p-2"
							aria-label="Investigation artifact"
							value={artifactId}
							disabled={busy}
							onChange={(e) => {
								setArtifactId(e.target.value);
								invalidate();
							}}
						>
							<option value="">Select opened artifact</option>
							{status?.artifacts.map((a) => (
								<option key={a.id} value={a.id}>
									{a.path}
								</option>
							))}
						</select>
						<select
							className="rounded border bg-background p-2"
							aria-label="Function analysis engine"
							disabled={busy}
							value={engine}
							onChange={(e) => {
								setEngine(e.target.value);
								invalidate();
							}}
						>
							<option value="ghidra">Ghidra</option>
							<option value="ida">Licensed IDA</option>
						</select>
						<input
							className="rounded border bg-background p-2"
							aria-label="Exact function selector"
							value={symbol}
							disabled={busy}
							onChange={(e) => {
								setSymbol(e.target.value);
								invalidate();
							}}
							placeholder="Exact symbol or 0x address"
						/>
						<button
							type="button"
							className="rounded border bg-background px-3 py-2 disabled:opacity-50"
							disabled={busy || mode === "off" || !artifactId || !symbol.trim()}
							onClick={() => {
								const r = revision.current;
								void work(async () => {
									const p = await invoke<Plan>("analyze_function", {
										...request(),
										phase: "prepare",
									});
									if (r === revision.current) setPlan(p);
									return p;
								});
							}}
						>
							Prepare function analysis
						</button>
						{plan && (
							<button
								type="button"
								className="rounded border bg-background px-3 py-2 disabled:opacity-50"
								disabled={busy}
								onClick={run}
							>
								Approve reviewed function analysis
							</button>
						)}
					</div>
					{plan && (
						<pre className="max-h-48 overflow-auto whitespace-pre-wrap">
							{JSON.stringify(
								{
									request: plan.request,
									requirements: plan.requirements,
									requestHash: plan.requestHash,
								},
								null,
								2,
							)}
						</pre>
					)}
					<div className="flex flex-wrap gap-2">
						<select
							className="rounded border bg-background p-2"
							aria-label="Owned browser session"
							value={browserId}
							disabled={busy || !!recording}
							onChange={(e) => setBrowserId(e.target.value)}
						>
							<option value="">Select already-open owned browser</option>
							{status?.browsers.map((b) => (
								<option key={b.browserSessionId}>{b.browserSessionId}</option>
							))}
						</select>
						<input
							className="rounded border bg-background p-2"
							aria-label="Browser scenario purpose"
							disabled={busy || !!recording}
							value={purpose}
							onChange={(e) => setPurpose(e.target.value)}
							placeholder="Scenario purpose (no secrets)"
						/>
						<button
							type="button"
							className="rounded border bg-background px-3 py-2 disabled:opacity-50"
							disabled={
								busy ||
								mode !== "runtime" ||
								!browserId ||
								!purpose.trim() ||
								!!recording
							}
							onClick={() => {
								if (
									!window.confirm(
										"Record this owned browser's action names, network origins/method/status and console level/count for at most two minutes? Values, bodies, cookies, paths and screenshots are excluded. No navigation or replay is performed.",
									)
								)
									return;
								const r = revision.current;
								void work(async () => {
									const v = await invoke("capture_browser_scenario", {
										browserSessionId: browserId,
										action: "start",
										confirmRecord: true,
										purpose,
									});
									if (r === revision.current) setRecording(browserId);
									return v;
								});
							}}
						>
							Start approved metadata recording
						</button>
						<button
							type="button"
							className="rounded border bg-background px-3 py-2 disabled:opacity-50"
							disabled={busy || !(recording || browserId)}
							onClick={() => {
								const r = revision.current;
								void work(async () => {
									const v = await invoke<{ id: string }>(
										"capture_browser_scenario",
										{
											browserSessionId: recording || browserId,
											action: "stop",
											confirmRecord: true,
											purpose: purpose || "Stop owned recording",
										},
									);
									if (r === revision.current) {
										setRecording("");
										setScenarioId(v.id??"");
									}
									return v;
								});
							}}
						>
							Stop and retain scenario
						</button>
						<button
							type="button"
							className="rounded border bg-background px-3 py-2 disabled:opacity-50"
							disabled={busy}
							onClick={() =>
								void work(() => invoke("analysis_workflow_status"))
							}
						>
							Refresh owned evidence
						</button>
					</div>
					<div className="flex flex-wrap gap-2">
						<select
							className="rounded border bg-background p-2"
							aria-label="Selected static receipt"
							value={receiptId}
							onChange={(e) => setReceiptId(e.target.value)}
						>
							<option value="">No static receipt</option>
							{receiptIds.map((id) => (
								<option key={id}>{id}</option>
							))}
						</select>
						<select
							className="rounded border bg-background p-2"
							aria-label="Selected browser scenario"
							value={scenarioId}
							onChange={(e) => setScenarioId(e.target.value)}
						>
							<option value="">No scenario</option>
							{status?.scenarios.map((s) => (
								<option key={s.id} value={s.id}>
									{s.purpose}
								</option>
							))}
						</select>
						<input
							className="rounded border bg-background p-2"
							aria-label="Feature candidate label"
							value={feature}
							onChange={(e) => setFeature(e.target.value)}
							placeholder="Feature label"
						/>
						<button
							type="button"
							className="rounded border bg-background px-3 py-2 disabled:opacity-50"
							disabled={busy || !feature.trim()}
							onClick={() =>
								void work(() =>
									invoke("trace_application_feature", {
										feature,
										receiptId: receiptId || undefined,
										scenarioIds: scenarioId ? [scenarioId] : [],
									}),
								)
							}
						>
							Find feature candidates (not causal proof)
						</button>
						<button
							type="button"
							className="rounded border bg-background px-3 py-2 disabled:opacity-50"
							disabled={busy || !(receiptId || scenarioId || taskId)}
							onClick={() => {
								if (
									!window.confirm(
										"Export only the selected session evidence as JSON? Redaction is best-effort. Review before sharing; this is not a full backup.",
									)
								)
									return;
								void work(async () => {
									const bundle = await invoke("get_evidence_bundle", {
										receiptIds: receiptId ? [receiptId] : [],
										scenarioIds: scenarioId ? [scenarioId] : [],
										taskIds: taskId ? [taskId] : [],
									});
									const url = URL.createObjectURL(
										new Blob([JSON.stringify(bundle, null, 2)], {
											type: "application/json",
										}),
									);
									try {
										const a = document.createElement("a");
										a.href = url;
										a.download = "cline-selected-evidence.json";
										a.click();
									} finally {
										setTimeout(() => URL.revokeObjectURL(url), 1000);
									}
									return { exported: true, coverage: "selected records only" };
								});
							}}
						>
							Export selected evidence JSON
						</button>
					</div>
					{error && <p role="alert">{error}</p>}
					{result !== null && (
						<pre
							
							className="max-h-72 overflow-auto whitespace-pre-wrap"
						>
							{JSON.stringify(result, null, 2)}
						</pre>
					)}
				</>
			)}
		</details>
	);
}
