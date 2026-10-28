"use client";
import { useRef, useState } from "react";
import { desktopClient } from "@/lib/desktop-client";
import type { ManagedEmulationPreflight } from "../../../../sidecar/managed-emulation-preflight";

export function ManagedEmulationPreflightPanel() {
	const [report, setReport] = useState<ManagedEmulationPreflight>();
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const pending = useRef(false);
	async function inspect() {
		if (
			pending.current ||
			!window.confirm(
				"Run a fixed read-only local Windows prerequisite query? No installation, elevation, Windows feature change, VM/WSL action, network request or engine test is performed.",
			)
		)
			return;
		pending.current = true;
		setBusy(true);
		setError("");
		setReport(undefined);
		try {
			setReport(
				await desktopClient.invoke<ManagedEmulationPreflight>(
					"setup_center_emulation_host_preflight",
					{ environmentId: "local", confirmed: true },
				),
			);
		} catch {
			setError(
				"Local prerequisite query unavailable. No installation or readiness is inferred.",
			);
		} finally {
			pending.current = false;
			setBusy(false);
		}
	}
	return (
		<section
			aria-label="Managed emulation host prerequisites"
			className="space-y-3 rounded border p-4"
		>
			<h3 className="font-semibold">
				Managed emulation pack — host prerequisites
			</h3>
			<p className="text-sm">
				Qiling, unidbg, rnidbg and Speakeasy managed installation is not
				implemented. This explicit check only observes prerequisites for the
				proposed app-owned Hyper-V backend. It does not create or test a VM,
				execute a target, modify Ubuntu/WSL, install engines or authorize
				execution.
			</p>
			<button
				type="button"
				disabled={busy}
				onClick={() => void inspect()}
				className="rounded border p-2"
			>
				{busy
					? "Checking local prerequisites…"
					: "Check local emulation prerequisites"}
			</button>
			{error && <p role="alert">{error}</p>}
			<div aria-live="polite">
				{report && (
					<>
						<p>
							Host prerequisites: <strong>{report.hostPrerequisites}</strong>
						</p>
						<p>
							Query: {report.query} · Windows build:{" "}
							{report.osBuild ?? "unavailable"}
						</p>
						<p>
							Checked:{" "}
							<time dateTime={report.checkedAt}>{report.checkedAt}</time>.
							Historical observation; rerun after host changes.
						</p>
						<ul aria-label="Observed host prerequisite checks">
							{report.checks.map((check) => (
								<li key={check.id}>
									{check.label}: {check.state}
								</li>
							))}
						</ul>
						<p>
							Total memory: {report.capacity.totalMemoryGiB ?? "unknown"} GiB ·
							Available memory: {report.capacity.freeMemoryGiB ?? "unknown"} GiB
							· Free local-app-data volume:{" "}
							{report.capacity.freeStorageGiB ?? "unknown"} GiB
						</p>
						<p>
							Capacity is a point-in-time observation, not reserved resources or
							a validated VM sizing budget.
						</p>
						<p>
							Managed installation: not implemented. Containment: not tested.
							Engine readiness: not tested.
						</p>
					</>
				)}
			</div>
		</section>
	);
}
