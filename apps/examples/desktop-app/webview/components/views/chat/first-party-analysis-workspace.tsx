"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { PreviewScrollRegion } from "@/components/ui/preview-scroll-region";
import { desktopClient } from "@/lib/desktop-client";
import { ActiveJavaScriptScenario } from "./active-javascript-scenario";
import type { AnalysisMode } from "./analysis-mode-control";
type Summary = {
	id: string;
	status: string;
	target: string;
	createdAt: string;
	error?: string;
	reservationReleasedAt?: string;
};
type Status = {
	mode: AnalysisMode;
	receipts: Summary[];
	readiness: Record<string, unknown>;
};
type View =
	| "artifacts"
	| "findings"
	| "graph"
	| "comparison"
	| "timeline"
	| "verification"
	| "cross-domain"
	| "dossiers"
	| "disagreements";
type PageResult = {
	items?: unknown[];
	nextOffset?: number | null;
	total?: number;
	[key: string]: unknown;
};
export function FirstPartyAnalysisWorkspace({
	sessionId,
	environmentId,
}: {
	sessionId?: string;
	environmentId: string;
}) {
	const [status, setStatus] = useState<Status | null>(null),
		[target, setTarget] = useState("."),
		[compareTarget, setCompareTarget] = useState("");
	const [inspectorTarget, setInspectorTarget] = useState(""),
		[inspectorPid, setInspectorPid] = useState(""),
		[inspectorEndpoint, setInspectorEndpoint] = useState("");
	const [captureConsole, setCaptureConsole] = useState(false);
	const inspectorRevision = useRef(0);
	const [inspectorPlan, setInspectorPlan] = useState<{
		id: string;
		requestHash: string;
		requirements: string[];
		request: Record<string, unknown>;
	} | null>(null);
	const [inspectorResult, setInspectorResult] = useState<unknown>(null);
	const [error, setError] = useState(""),
		[running, setRunning] = useState(false),
		[selected, setSelected] = useState("");
	const [view, setView] = useState<View>("findings"),
		[filter, setFilter] = useState(""),
		[offset, setOffset] = useState(0),
		[page, setPage] = useState<PageResult | null>(null);
	const refresh = useCallback(async () => {
		if (!sessionId) return;
		const r = await desktopClient.invoke<Status>(
			"first_party_analysis_status",
			{ sessionId, environmentId },
		);
		setStatus(r);
	}, [sessionId, environmentId]);
	useEffect(() => {
		let disposed = false;
		setStatus(null);
		inspectorRevision.current++;
		setCaptureConsole(false);
		setRunning(false);
		setInspectorPlan(null);
		setInspectorResult(null);
		setSelected("");
		setPage(null);
		setError("");
		if (!sessionId || environmentId !== "local") return;
		const update = () =>
			void desktopClient
				.invoke<Status>("first_party_analysis_status", {
					sessionId,
					environmentId,
				})
				.then((r) => {
					if (!disposed) setStatus(r);
				})
				.catch(() => {
					if (!disposed) setError("Analysis status unavailable");
				});
		update();
		const timer = setInterval(update, 2000);
		window.addEventListener("cline-analysis-changed", update);
		return () => {
			disposed = true;
			inspectorRevision.current++;
			clearInterval(timer);
			window.removeEventListener("cline-analysis-changed", update);
		};
	}, [sessionId, environmentId]);
	useEffect(() => {
		setPage(null);
		let disposed = false;
		if (
			(!selected &&
				!["cross-domain", "dossiers", "disagreements"].includes(view)) ||
			!sessionId ||
			view === "timeline"
		)
			return;
		void desktopClient
			.invoke<PageResult>("first_party_analysis_evidence", {
				sessionId,
				environmentId,
				...(["cross-domain", "dossiers", "disagreements"].includes(view)
					? { receiptId: selected, view, offset }
					: {
							query: { receiptId: selected, view, filter, offset, limit: 20 },
						}),
			})
			.then((r) => {
				if (!disposed) setPage(r);
			})
			.catch((e) => {
				if (!disposed)
					setError(e instanceof Error ? e.message : "Evidence unavailable");
			});
		return () => {
			disposed = true;
		};
	}, [selected, sessionId, environmentId, view, filter, offset]);
	if (!sessionId || environmentId !== "local")
		return <p>Open an existing local session to use first-party analysis.</p>;
	const run = async () => {
		setRunning(true);
		setError("");
		try {
			const receipt = await desktopClient.invoke<{
				id: string;
				status: string;
				error?: string;
			}>(
				"first_party_analysis_run",
				{
					sessionId,
					environmentId,
					input: { target, ...(compareTarget ? { compareTarget } : {}) },
				},
				{ timeoutMs: 75000 },
			);
			setSelected(receipt.id);
			setOffset(0);
			if (receipt.error) setError(receipt.error);
			await refresh();
		} catch (e) {
			setError(
				e instanceof Error
					? e.message
					: "Request failed. Inspect receipts; do not replay automatically.",
			);
		} finally {
			setRunning(false);
		}
	};
	const recover = async (id: string) => {
		if (
			!window.confirm(
				"Release this reservation only if both original process instances are proved gone? This does not kill processes, replay work or change the evidence receipt.",
			)
		)
			return;
		try {
			await desktopClient.invoke("first_party_analysis_recover", {
				sessionId,
				environmentId,
				receiptId: id,
				confirmed: true,
			});
			await refresh();
		} catch (e) {
			setError(e instanceof Error ? e.message : "Recovery blocked");
		}
	};
	const prepareInspector = async () => {
		const revision = ++inspectorRevision.current;
		setError("");
		setInspectorPlan(null);
		try {
			const p = await desktopClient.invoke<{
				id: string;
				requestHash: string;
				requirements: string[];
				request: Record<string, unknown>;
			}>("first_party_analysis_inspector_prepare", {
				sessionId,
				environmentId,
				input: {
					operation: "js_inspector_observe",
					target: inspectorTarget,
					pid: Number(inspectorPid),
					endpoint: inspectorEndpoint,
					durationMs: 1000,
					captureConsole,
				},
			});
			if (revision === inspectorRevision.current) setInspectorPlan(p);
		} catch (e) {
			if (revision === inspectorRevision.current)
				setError(e instanceof Error ? e.message : "Inspector plan unavailable");
		}
	};
	const observeInspector = async () => {
		if (
			!inspectorPlan ||
			!window.confirm(
				`Authorize Debug attachment to the reviewed exact target? Attachment can affect the process. Required approvals: ${inspectorPlan.requirements.join(", ")}. No eval, resume or launch will be sent. Console capture: ${inspectorPlan.request.captureConsole === true ? "ON — primitive values may contain secrets and will be stored in private evidence" : "OFF"}.`,
			)
		)
			return;
		const plan = inspectorPlan;
		const revision = inspectorRevision.current;
		setInspectorPlan(null);
		setRunning(true);
		try {
			const approved = await desktopClient.invoke<{ executionToken: string }>(
				"approve_analysis_task",
				{
					sessionId,
					environmentId,
					planId: plan.id,
					requestHash: plan.requestHash,
					requirements: plan.requirements,
				},
			);
			if (revision !== inspectorRevision.current) return;
			const result = await desktopClient.invoke(
				"first_party_analysis_inspector_run",
				{
					sessionId,
					environmentId,
					planId: plan.id,
					executionToken: approved.executionToken,
					input: plan.request,
				},
				{ timeoutMs: 20000 },
			);
			if (revision === inspectorRevision.current) setInspectorResult(result);
		} catch (e) {
			if (revision === inspectorRevision.current)
				setError(
					e instanceof Error
						? e.message
						: "Inspector observation failed; do not replay automatically",
				);
		} finally {
			if (revision === inspectorRevision.current) setRunning(false);
		}
	};
	const cancel = async (id: string) => {
		try {
			await desktopClient.invoke("first_party_analysis_cancel", {
				sessionId,
				environmentId,
				receiptId: id,
			});
			await refresh();
		} catch (e) {
			setError(e instanceof Error ? e.message : "Cancellation unavailable");
		}
	};
	return (
		<section
			className="space-y-3 p-3"
			aria-label="First-party Analysis Workspace"
		>
			<h3 className="font-semibold">First-party Analysis Workspace</h3>
			<p className="text-xs text-muted-foreground">
				Mode: {status?.mode ?? "unavailable"}. Static JS/TS/Electron syntax,
				bounded cross-module/value/call relationships, managed PE metadata and
				IL bytes, declared source-map locations and ASAR inspection. Static
				inspection never executes the target. Active scenarios require a
				separate Execute approval. Mode does not override permissions or disable
				existing tools.
			</p>
			<div className="flex flex-wrap gap-2">
				<input
					aria-label="JavaScript analysis target"
					className="rounded border bg-background p-2 text-xs"
					value={target}
					onChange={(e) => setTarget(e.target.value)}
					placeholder="Workspace-relative artifact or folder"
				/>
				<input
					aria-label="JavaScript comparison target"
					className="rounded border bg-background p-2 text-xs"
					value={compareTarget}
					onChange={(e) => setCompareTarget(e.target.value)}
					placeholder="Optional previous version"
				/>
				<button
					type="button"
					className="rounded bg-primary px-3 py-2 text-xs text-primary-foreground disabled:opacity-50"
					disabled={
						running || !status || status.mode === "off" || !target.trim()
					}
					onClick={() => void run()}
				>
					Inspect static sources
				</button>
			</div>
			<details className="space-y-2 text-xs">
				<summary>
					Separately approved passive Node Inspector observation
				</summary>
				<p>
					Requires Runtime mode, an authorized already-running loopback Node
					Inspector target, exact owning PID and source file. This is a Debug
					attachment, not an OS sandbox. Loaded/parsed scripts are not proof of
					execution. Active eval/resume/launch is unavailable.
				</p>
				<input
					disabled={running}
					aria-label="Inspector source target"
					className="rounded border bg-background p-2"
					value={inspectorTarget}
					onChange={(e) => {
						setInspectorTarget(e.target.value);
						inspectorRevision.current++;
						setInspectorPlan(null);
					}}
					placeholder="Workspace-relative exact source file"
				/>
				<input
					disabled={running}
					aria-label="Inspector owning PID"
					className="rounded border bg-background p-2"
					value={inspectorPid}
					onChange={(e) => {
						setInspectorPid(e.target.value);
						inspectorRevision.current++;
						setInspectorPlan(null);
					}}
					placeholder="Exact running Node PID"
				/>
				<input
					disabled={running}
					aria-label="Inspector loopback endpoint"
					className="rounded border bg-background p-2"
					value={inspectorEndpoint}
					onChange={(e) => {
						setInspectorEndpoint(e.target.value);
						inspectorRevision.current++;
						setInspectorPlan(null);
					}}
					placeholder="ws://127.0.0.1:port/inspector-uuid"
				/>
				<label className="flex items-center gap-2">
					<input
						type="checkbox"
						checked={captureConsole}
						disabled={running}
						aria-label="Capture source-bound console reports"
						onChange={(e) => {
							setCaptureConsole(e.target.checked);
							inspectorRevision.current++;
							setInspectorPlan(null);
						}}
					/>
					Capture source-bound console reports (off by default)
				</label>
				<p>
					Optional console capture stores bounded primitive values in private
					evidence; these may include secrets. Objects remain opaque.
					Target-reported events and coordinates are not authenticated execution
					or scenario proof.
				</p>
				<button
					type="button"
					disabled={running || status?.mode !== "runtime"}
					className="rounded border p-2"
					onClick={() => void prepareInspector()}
				>
					Review Inspector plan
				</button>
				{inspectorPlan ? (
					<>
						<pre className="overflow-auto whitespace-pre-wrap">
							{JSON.stringify(inspectorPlan, null, 2)}
						</pre>
						<button
							type="button"
							className="rounded border p-2"
							onClick={() => void observeInspector()}
						>
							Authorize reviewed observation
						</button>
					</>
				) : null}
				{inspectorResult ? (
					<pre className="max-h-64 overflow-auto whitespace-pre-wrap">
						{JSON.stringify(inspectorResult, null, 2)}
					</pre>
				) : null}
			</details>
			{error ? (
				<p role="alert" className="text-xs text-destructive">
					{error}
				</p>
			) : null}
			<select
				aria-label="Saved analysis receipt"
				className="w-full rounded border bg-background p-2 text-xs"
				value={selected}
				onChange={(e) => {
					setSelected(e.target.value);
					setOffset(0);
				}}
			>
				<option value="">Select saved evidence</option>
				{status?.receipts.map((r) => (
					<option key={r.id} value={r.id}>
						{r.status}
						{r.reservationReleasedAt
							? " (reservation released without replay)"
							: ""}{" "}
						— {r.target} — {r.createdAt}
					</option>
				))}
			</select>
			{status?.receipts
				.filter((r) => r.status === "running" && !r.reservationReleasedAt)
				.map((r) => (
					<button
						key={r.id}
						type="button"
						className="text-xs underline"
						onClick={() => void cancel(r.id)}
					>
						Cancel worker {r.id}
					</button>
				))}
			{status?.receipts
				.filter(
					(r) =>
						["running", "termination-unconfirmed"].includes(r.status) &&
						!r.reservationReleasedAt,
				)
				.map((r) => (
					<button
						key={`recover-${r.id}`}
						type="button"
						className="text-xs underline"
						onClick={() => void recover(r.id)}
					>
						Check and release abandoned reservation {r.id}
					</button>
				))}
			<nav
				aria-label="Analysis evidence views"
				className="flex flex-wrap gap-2"
			>
				{(
					[
						"artifacts",
						"findings",
						"graph",
						"comparison",
						"timeline",
						"verification",
						"cross-domain",
						"dossiers",
						"disagreements",
					] as View[]
				).map((v) => (
					<button
						type="button"
						key={v}
						aria-pressed={view === v}
						className="rounded border px-2 py-1 text-xs"
						onClick={() => {
							setView(v);
							setOffset(0);
						}}
					>
						{v}
					</button>
				))}
			</nav>
			{view === "timeline" ? (
				<ol className="space-y-2 text-xs">
					{status?.receipts.map((r) => (
						<li key={r.id}>
							<button
								type="button"
								className="underline"
								onClick={() => {
									setSelected(r.id);
									setView("verification");
								}}
							>
								{r.createdAt} — {r.status}
								{r.reservationReleasedAt
									? " (reservation released without replay)"
									: ""}{" "}
								— {r.target}
							</button>
							{r.error ? <p>{r.error}</p> : null}
						</li>
					))}
				</ol>
			) : (
				<>
					{view !== "verification" ? (
						<input
							aria-label="Filter analysis evidence"
							className="w-full rounded border bg-background p-2 text-xs"
							value={filter}
							onChange={(e) => {
								setFilter(e.target.value);
								setOffset(0);
							}}
							placeholder="Literal evidence filter"
						/>
					) : null}
					{view === "comparison" && page?.available === false ? (
						<p className="text-xs">
							Comparison was not recorded for this receipt.
						</p>
					) : null}
					{page?.items ? (
						<ul className="space-y-2">
							{page.items.map((item, index) => (
								<li
									key={`${selected}-${offset}-${index}`}
									className="rounded border p-2"
								>
									<PreviewScrollRegion
										aria-label="Scrollable analysis evidence"
										className="max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs"
									>
										<pre className="whitespace-pre-wrap break-all text-xs">
											{JSON.stringify(item, null, 2)}
										</pre>
									</PreviewScrollRegion>
									{view === "graph" && item && typeof item === "object" ? (
										<div className="flex gap-2 text-xs">
											{(["source", "target"] as const).map((side) => {
												const id = (item as Record<string, unknown>)[side];
												return typeof id === "string" ? (
													<button
														key={side}
														type="button"
														className="underline"
														onClick={() => {
															setFilter(id);
															setOffset(0);
															setView("findings");
														}}
													>
														Inspect {side} evidence
													</button>
												) : null;
											})}
										</div>
									) : null}
								</li>
							))}
						</ul>
					) : page ? (
						<PreviewScrollRegion
							aria-label="Scrollable analysis evidence"
							className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded border p-2 text-xs"
						>
							<pre className="whitespace-pre-wrap break-all text-xs">
								{JSON.stringify(page, null, 2)}
							</pre>
						</PreviewScrollRegion>
					) : (
						<p className="text-xs">
							Select a receipt. Evidence remains available when Analysis is Off.
						</p>
					)}
					{view !== "verification" && page ? (
						<div className="flex gap-2 text-xs">
							<button
								type="button"
								disabled={!offset}
								onClick={() => setOffset(Math.max(0, offset - 20))}
							>
								Previous
							</button>
							<span>
								{offset} / {page.total ?? 0}
							</span>
							<button
								type="button"
								disabled={page.nextOffset == null}
								onClick={() => setOffset(Number(page.nextOffset))}
							>
								Next
							</button>
						</div>
					) : null}
				</>
			)}
			<details className="text-xs">
				<summary>Scope and readiness</summary>
				<pre className="overflow-auto whitespace-pre-wrap">
					{JSON.stringify(status?.readiness, null, 2)}
				</pre>
				<p>
					Graph edges are candidate relationships, not execution proof. Native
					analysis, project edits, device work and runtime actions remain in the
					existing approved workbench tabs. Full program recovery and active
					Inspector scenarios are not implemented. Passive observation needs its
					own reviewed Debug approval. Managed inspection retains declarations
					and bounded IL bytes, not high-level decompilation. Native dossiers
					show retained engine output; absent components stay unknown.
				</p>
			</details>
			<ActiveJavaScriptScenario
				sessionId={sessionId}
				environmentId={environmentId}
				enabled={status?.mode === "runtime" && !running}
			/>
		</section>
	);
}
