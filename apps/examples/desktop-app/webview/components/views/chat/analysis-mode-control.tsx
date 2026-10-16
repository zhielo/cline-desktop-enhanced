"use client";
import { useEffect, useId, useState } from "react";
import { desktopClient } from "@/lib/desktop-client";
import type { ChatSessionStatus } from "@/lib/chat-schema";
export type AnalysisMode = "off" | "static" | "runtime" | "hybrid";
export function AnalysisModeControl({
	sessionId,
	environmentId,
	status,
	onOpen,
	draftMode = "off",
	onDraftModeChange,
}: {
	sessionId?: string;
	environmentId?: string;
	status?: ChatSessionStatus;
	onOpen?: () => void;
	draftMode?: AnalysisMode;
	onDraftModeChange?: (mode: AnalysisMode) => void;
}) {
	const controlId = useId();
	const [mode, setMode] = useState<AnalysisMode>("off"),
		[busy, setBusy] = useState(false),
		[error, setError] = useState("");
	const [loaded, setLoaded] = useState(false);
	const idle = !["starting", "running", "stopping"].includes(status ?? "");
	useEffect(() => {
		setLoaded(false);
		setMode("off");
		setError("");
		let disposed = false;
		if (!sessionId || environmentId !== "local") return;
		const refresh = () =>
			void desktopClient
				.invoke<{ mode: AnalysisMode }>("first_party_analysis_status", {
					sessionId,
					environmentId,
				})
				.then((r) => {
					if (!disposed) {
						setMode(r.mode);
						setLoaded(true);
					}
				})
				.catch(() => {
					if (!disposed) setError("Analysis unavailable");
				});
		refresh();
		window.addEventListener("cline-analysis-changed", refresh);
		return () => {
			disposed = true;
			window.removeEventListener("cline-analysis-changed", refresh);
		};
	}, [sessionId, environmentId]);
	if (environmentId !== "local" || (!sessionId && !onDraftModeChange))
		return null;
	const change = async (value: AnalysisMode) => {
		if (!idle || busy || (sessionId && !loaded)) return;
		if (
			(value === "runtime" || value === "hybrid") &&
			!window.confirm(
				"Runtime mode does not grant execution permission. Neither does Hybrid. Hybrid requires prior static evidence and an explicit runtime question.  Existing target selection and per-action approvals remain required. Passive Inspector requires Debug approval; isolated JavaScript execution requires independent Execute approval and verified Windows isolation.",
			)
		)
			return;
		if (!sessionId) {
			onDraftModeChange?.(value);
			return;
		}
		setBusy(true);
		setError("");
		try {
			const r = await desktopClient.invoke<{ mode: AnalysisMode }>(
				"first_party_analysis_mode",
				{ sessionId, environmentId, mode: value },
			);
			setMode(r.mode);
			window.dispatchEvent(new Event("cline-analysis-changed"));
		} catch (e) {
			setError(e instanceof Error ? e.message : "Mode change failed");
		} finally {
			setBusy(false);
		}
	};
	return (
		<div
			className="flex items-center gap-1 text-xs"
			title={
				error ||
				"Session-specific parser mode. Does not override existing permissions or disable other tools."
			}
		>
			<label htmlFor={controlId}>Analysis</label>
			<select
				id={controlId}
				aria-label={sessionId ? "Session Analysis mode" : "Draft Analysis mode"}
				className="rounded border border-border bg-background p-1"
				value={sessionId ? mode : draftMode}
				disabled={!idle || busy || (Boolean(sessionId) && !loaded)}
				onChange={(e) => void change(e.target.value as AnalysisMode)}
			>
				<option value="off">Off</option>
				<option value="static">Static</option>
				<option value="runtime">Runtime</option>
				<option value="hybrid">Hybrid (static first)</option>
			</select>
			<button
				type="button"
				aria-label={
					sessionId
						? "Open Analysis Workspace"
						: "Open draft Analysis workspace"
				}
				className="rounded p-1 hover:bg-secondary"
				onClick={onOpen}
			>
				Open
			</button>
			{error ? (
				<span role="alert" className="max-w-40 truncate text-destructive">
					{error}
				</span>
			) : null}
		</div>
	);
}
