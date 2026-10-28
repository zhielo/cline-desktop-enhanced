"use client";
import { useId, useRef, useState } from "react";
import { desktopClient } from "@/lib/desktop-client";
import type { SessionToolInventory } from "../../../../sidecar/session-tool-inventory";
/** Explicit local Hub reads only. Never initializes an agent or probes an engine. */
export function SessionToolInventoryPanel() {
	const sessionSelectId = useId();
	const [sessions, setSessions] = useState<
		Array<{ sessionId: string; local: boolean }>
	>([]);
	const [selected, setSelected] = useState("");
	const [inventory, setInventory] = useState<SessionToolInventory>();
	const [busy, setBusy] = useState(false),
		[error, setError] = useState("");
	const requestVersion = useRef(0);
	async function list() {
		const version = ++requestVersion.current;
		setBusy(true);
		setError("");
		setInventory(undefined);
		try {
			const result = await desktopClient.invoke<{
				sessions: Array<{ sessionId: string; local: boolean }>;
			}>("session_tool_inventory_sessions");
			if (version === requestVersion.current) {
				setSessions(result.sessions);
				setSelected("");
			}
		} catch {
			if (version === requestVersion.current)
				setError("Attached sessions could not be read.");
		} finally {
			if (version === requestVersion.current) setBusy(false);
		}
	}
	async function inspect() {
		if (!selected) return;
		const version = ++requestVersion.current,
			id = selected;
		setBusy(true);
		setError("");
		setInventory(undefined);
		try {
			const result = await desktopClient.invoke<SessionToolInventory>(
				"session_tool_inventory",
				{ sessionId: id },
			);
			if (version === requestVersion.current && result.sessionId === id)
				setInventory(result);
		} catch {
			if (version === requestVersion.current)
				setError(
					"Session evidence unavailable. Refresh attached sessions and try again.",
				);
		} finally {
			if (version === requestVersion.current) setBusy(false);
		}
	}
	return (
		<section
			className="rounded border p-4 space-y-3"
			aria-labelledby="session-tools-heading"
		>
			<h2 id="session-tools-heading" className="font-semibold">
				Session model tool evidence
			</h2>
			<p className="text-sm text-muted-foreground">
				Names from the last core model-adapter request after hooks—not the
				registered tool catalog, provider receipt, installed readiness or
				permission. No provider calls, engine tests or installs are triggered by
				inspection. Remote and restarted sessions may have no evidence.
			</p>
			<button
				type="button"
				disabled={busy}
				onClick={list}
				className="rounded border p-2"
			>
				Refresh attached sessions
			</button>
			<div className="text-sm">
				<label htmlFor={sessionSelectId} className="block">
					Owning session
				</label>
				<select
					id={sessionSelectId}
					value={selected}
					onChange={(event) => {
						++requestVersion.current;
						setSelected(event.target.value);
						setInventory(undefined);
						setError("");
						setBusy(false);
					}}
					className="block w-full rounded border bg-background p-2"
				>
					<option value="">Select an attached session</option>
					{sessions.map((s) => (
						<option key={s.sessionId} value={s.sessionId}>
							{s.sessionId}
							{s.local ? "" : " · remote evidence unavailable"}
						</option>
					))}
				</select>
			</div>
			<button
				type="button"
				disabled={busy || !selected}
				onClick={inspect}
				className="rounded border p-2"
			>
				Inspect last request
			</button>
			<output aria-live="polite" className="block text-sm">
				{busy ? "Reading local session evidence…" : error}
			</output>
			{inventory && (
				<div className="text-sm space-y-2">
					<p>
						Evidence:{" "}
						{inventory.status === "last-request"
							? "Last recorded request (historical, not live provider confirmation)"
							: inventory.status === "stale"
								? "Stale — runtime configuration changed since capture"
								: "Unavailable — no usable request evidence"}
					</p>
					{"evidence" in inventory && (
						<>
							<p>
								Captured: {inventory.evidence.capturedAt} · iteration{" "}
								{inventory.evidence.iteration}
							</p>
							<p>
								Captured provider/model: {inventory.providerId} /{" "}
								{inventory.modelId}
							</p>
							<p>
								Local tool definitions: {inventory.evidence.toolCount}.
								Provider-executed tools: {inventory.evidence.modelToolCount}.{" "}
								{inventory.evidence.truncated
									? "Names are partial; counts retain the full totals."
									: "All recorded names shown."}
							</p>
							<ul
								aria-label="Local request tool names"
								className="max-h-64 overflow-auto break-all"
							>
								{inventory.evidence.toolNames.map((name, i) => (
									<li key={`${i}:${name}`}>
										<code>{name}</code>
									</li>
								))}
							</ul>
							<ul aria-label="Provider tool names">
								{inventory.evidence.modelToolNames.map((name, i) => (
									<li key={`${i}:${name}`}>
										<code>{name}</code>
									</li>
								))}
							</ul>
						</>
					)}
					<p>{inventory.authorization}</p>
				</div>
			)}
		</section>
	);
}
