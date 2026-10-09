"use client";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { desktopClient } from "@/lib/desktop-client";
type Status = {
	resources: {
		profile: string;
		active: number;
		queued: number;
		scope: string;
		reservedMB?: number;
		estimatedBudgetMB?: number;
		oldestQueuedMs?: number;
	};
	performance: {
		reason: string;
		commandLatency?: {
			status: string;
			reason: string;
			directSamples: number;
			shellSamples: number;
		};
	};
	updates: { reason: string };
	limitations: string[];
	restartRequired?: boolean;
};
export function OptimizationPanel() {
	const [status, setStatus] = useState<Status | null>(null);
	const [error, setError] = useState("");
	const [busy, setBusy] = useState(false);
	const [cleanupMessage, setCleanupMessage] = useState("");
	async function cleanup() {
		if (
			!window.confirm(
				"Remove expired detached command logs? Active commands, session history, projects and runtime packs are preserved.",
			)
		)
			return;
		setBusy(true);
		setError("");
		try {
			const reply = await desktopClient.invoke<{
				removed: number;
				message: string;
			}>("cleanup_completed_command_logs", {
				environmentId: "local",
				confirmed: true,
			});
			setCleanupMessage(
				`${reply.removed} expired log directories removed. ${reply.message}`,
			);
		} catch (e) {
			setError(e instanceof Error ? e.message : "Cleanup failed");
		} finally {
			setBusy(false);
		}
	}
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
			<Button variant="outline" disabled={busy} onClick={() => void cleanup()}>
				Clean expired command logs
			</Button>
			{cleanupMessage && <output>{cleanupMessage}</output>}
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
					{status.resources.reservedMB !== undefined && (
						<p>
							Estimated reservations: {status.resources.reservedMB} MB /{" "}
							{status.resources.estimatedBudgetMB} MB admission budget. Not an
							OS memory limit. Oldest queued request:{" "}
							{Math.round((status.resources.oldestQueuedMs ?? 0) / 1000)}{" "}
							seconds.
						</p>
					)}
					{status.restartRequired && (
						<p>Restart required for backend processes.</p>
					)}
					<p>{status.performance.reason}</p>
					{status.performance.commandLatency && (
						<p>
							Command latency evidence:{" "}
							{status.performance.commandLatency.status};{" "}
							{status.performance.commandLatency.directSamples} direct and{" "}
							{status.performance.commandLatency.shellSamples} shell samples.{" "}
							{status.performance.commandLatency.reason}
						</p>
					)}
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
