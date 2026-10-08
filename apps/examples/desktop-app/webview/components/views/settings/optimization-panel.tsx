"use client";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { desktopClient } from "@/lib/desktop-client";
type Status = {
	resources: { profile: string; active: number; queued: number; scope: string };
	performance: { reason: string };
	updates: { reason: string };
	limitations: string[];
	restartRequired?: boolean;
};
export function OptimizationPanel() {
	const [status, setStatus] = useState<Status | null>(null);
	const [error, setError] = useState("");
	const [busy, setBusy] = useState(false);
	async function refresh() {
		setBusy(true);
		setError("");
		try {
			setStatus(
				await desktopClient.invoke<Status>("get_optimization_status", {
					environmentId: "local",
				}),
			);
		} catch (e) {
			setError(e instanceof Error ? e.message : "Unavailable");
		} finally {
			setBusy(false);
		}
	}
	async function change(profile: string) {
		if (
			!window.confirm(
				"Change analysis resource admission profile? Active work is not interrupted. Restart to apply it to newly started backend processes.",
			)
		)
			return;
		setBusy(true);
		try {
			setStatus(
				await desktopClient.invoke<Status>("set_resource_profile", {
					environmentId: "local",
					profile,
					confirmed: true,
				}),
			);
		} catch (e) {
			setError(e instanceof Error ? e.message : "Profile change failed");
		} finally {
			setBusy(false);
		}
	}
	return (
		<section
			className="space-y-2 border-t pt-4"
			aria-label="Optimization controls"
		>
			<h3>Optimization and distribution</h3>
			<Button variant="outline" disabled={busy} onClick={() => void refresh()}>
				Inspect optimization status
			</Button>
			{error && <p role="alert">{error}</p>}
			{status && (
				<>
					<label>
						Resource profile{" "}
						<select
							aria-label="Resource profile"
							value={status.resources.profile}
							disabled={busy}
							onChange={(e) => void change(e.target.value)}
						>
							<option value="economy">Economy</option>
							<option value="balanced">Balanced</option>
							<option value="deep">Deep analysis</option>
						</select>
					</label>
					<p>
						{status.resources.active} active; {status.resources.queued} queued.
						Scope: {status.resources.scope}.
					</p>
					{status.restartRequired && (
						<p>Restart required for backend processes.</p>
					)}
					<p>{status.performance.reason}</p>
					<p>{status.updates.reason}</p>
					<ul>
						{status.limitations.map((text) => (
							<li key={text}>{text}</li>
						))}
					</ul>
				</>
			)}
		</section>
	);
}
