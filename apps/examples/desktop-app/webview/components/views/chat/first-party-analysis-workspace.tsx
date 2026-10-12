"use client";
import { useCallback, useEffect, useState } from "react";
import { PreviewScrollRegion } from "@/components/ui/preview-scroll-region";
import { desktopClient } from "@/lib/desktop-client";
import type { AnalysisMode } from "./analysis-mode-control";
type Summary = {
	id: string;
	status: string;
	target: string;
	createdAt: string;
	error?: string;
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
	| "verification";
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
			clearInterval(timer);
			window.removeEventListener("cline-analysis-changed", update);
		};
	}, [sessionId, environmentId]);
	useEffect(() => {
		setPage(null);
		let disposed = false;
		if (!selected || !sessionId || view === "timeline") return;
		void desktopClient
			.invoke<PageResult>("first_party_analysis_evidence", {
				sessionId,
				environmentId,
				query: { receiptId: selected, view, filter, offset, limit: 20 },
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
				bounded local value/call relationships, declared source-map locations
				and ASAR inspection. Never executes the target. Mode does not override
				permissions or disable existing tools.
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
						{r.status} — {r.target} — {r.createdAt}
					</option>
				))}
			</select>
			{status?.receipts
				.filter((r) => r.status === "running")
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
								{r.createdAt} — {r.status} — {r.target}
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
					existing approved workbench tabs. General data-flow recovery, .NET
					additions and JavaScript Inspector capture are not implemented by this
					parser.
				</p>
			</details>
		</section>
	);
}
