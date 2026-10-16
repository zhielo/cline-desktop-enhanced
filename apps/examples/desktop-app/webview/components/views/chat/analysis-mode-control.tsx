"use client";
import { useEffect, useRef, useState } from "react";
import { desktopClient } from "@/lib/desktop-client";
import type { ChatSessionStatus } from "@/lib/chat-schema";
import {
	clearPendingAnalysisMode,
	readPendingAnalysisMode,
	writePendingAnalysisMode,
	type AnalysisMode,
} from "@/lib/session-preferences";
export type { AnalysisMode } from "@/lib/session-preferences";

export function AnalysisModeControl({
	sessionId,
	environmentId,
	status,
	onOpen,
	onModeChange,
}: {
	sessionId?: string;
	environmentId?: string;
	status?: ChatSessionStatus;
	onOpen?: () => void;
	onModeChange?: (mode: AnalysisMode) => void;
}) {
	const [mode, setMode] = useState<AnalysisMode>("off"),
		[busy, setBusy] = useState(false),
		[error, setError] = useState("");
	const [loaded, setLoaded] = useState(false);
	const pendingModeRef = useRef<AnalysisMode | null>(null);
	const idle = !["starting", "running", "stopping"].includes(status ?? "");
	const controlId = sessionId
		? `session-analysis-mode-${sessionId}`
		: "new-session-analysis-mode";
	useEffect(() => {
		setLoaded(false);
		setMode("off");
		setError("");
		let disposed = false;
		if (environmentId !== "local") return;
		if (!sessionId) {
			const pending = readPendingAnalysisMode();
			setMode(pending);
			onModeChange?.(pending);
			setLoaded(true);
			return;
		}
		const refresh = async () => {
			try {
				const result = await desktopClient.invoke<{ mode: AnalysisMode }>(
					"first_party_analysis_status",
					{ sessionId, environmentId },
				);
				let nextMode = result.mode;
				const pending = pendingModeRef.current ?? readPendingAnalysisMode();
				if (
					onModeChange &&
					(pendingModeRef.current !== null || pending !== "off")
				) {
					if (pending !== result.mode) {
						const applied = await desktopClient.invoke<{ mode: AnalysisMode }>(
							"first_party_analysis_mode",
							{ sessionId, environmentId, mode: pending },
						);
						nextMode = applied.mode;
					}
					pendingModeRef.current = null;
					clearPendingAnalysisMode();
				}
				if (!disposed) {
					setMode(nextMode);
					onModeChange?.(nextMode);
					setLoaded(true);
				}
			} catch {
				if (!disposed) setError("Analysis unavailable");
			}
		};
		refresh();
		window.addEventListener("cline-analysis-changed", refresh);
		return () => {
			disposed = true;
			window.removeEventListener("cline-analysis-changed", refresh);
		};
	}, [environmentId, onModeChange, sessionId]);
	if (environmentId !== "local") return null;
	const change = async (value: AnalysisMode) => {
		if (!idle || busy || !loaded) return;
		if (
			(value === "runtime" || value === "hybrid") &&
			!window.confirm(
				"Runtime mode does not grant execution permission. Neither does Hybrid. Hybrid requires prior static evidence and an explicit runtime question.  Existing target selection and per-action approvals remain required. Passive Inspector requires Debug approval; isolated JavaScript execution requires independent Execute approval and verified Windows isolation.",
			)
		)
			return;
		setBusy(true);
		setError("");
		try {
			if (!sessionId) {
				pendingModeRef.current = value;
				writePendingAnalysisMode(value);
				setMode(value);
				onModeChange?.(value);
				window.dispatchEvent(new Event("cline-analysis-changed"));
				return;
			}
			const r = await desktopClient.invoke<{ mode: AnalysisMode }>(
				"first_party_analysis_mode",
				{ sessionId, environmentId, mode: value },
			);
			setMode(r.mode);
			onModeChange?.(r.mode);
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
				"Choose Analysis before starting a new task. Session mode does not override existing permissions or disable other tools."
			}
		>
			<label htmlFor={controlId}>Analysis</label>
			<select
				id={controlId}
				aria-label="Session Analysis mode"
				className="rounded border border-border bg-background p-1"
				value={mode}
				disabled={!idle || busy || !loaded}
				onChange={(e) => void change(e.target.value as AnalysisMode)}
			>
				<option value="off">Off</option>
				<option value="static">Static</option>
				<option value="runtime">Runtime</option>
				<option value="hybrid">Hybrid (static first)</option>
			</select>
			{onOpen ? (
				<button
					type="button"
					aria-label="Open Analysis Workspace"
					className="rounded p-1 hover:bg-secondary"
					onClick={onOpen}
				>
					Open
				</button>
			) : null}
			{error ? (
				<span role="alert" className="max-w-40 truncate text-destructive">
					{error}
				</span>
			) : null}
		</div>
	);
}
