"use client";
import { useCallback, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { desktopClient } from "@/lib/desktop-client";

type Capability = {
	id: string;
	state: string;
	reason: string;
	version?: string;
	testedAt?: string;
};
const labels: Record<string, string> = {
	ready: "Ready",
	"needs-setup": "Needs setup",
	"installed-not-tested": "Installed but untested",
	unsupported: "Unsupported",
	"integrity-failed": "Integrity failed",
};
export function BinaryTriageReadiness() {
	const [capabilities, setCapabilities] = useState<Capability[]>([]),
		[busy, setBusy] = useState(false),
		[error, setError] = useState("");
	const refresh = useCallback(async () => {
		const status = await desktopClient.invoke<{ capabilities?: Capability[] }>(
			"binary_triage_status",
			{ environmentId: "local" },
		);
		setCapabilities(status?.capabilities ?? []);
	}, []);
	useEffect(() => {
		let current = true;
		void refresh().catch(() => {
			if (current)
				setError(
					"Binary triage readiness unavailable; no analysis was started.",
				);
		});
		return () => {
			current = false;
		};
	}, [refresh]);
	async function test() {
		if (
			!window.confirm(
				"Run fixed project-owned PE fixtures through radare2, YARA, capa and FLOSS static extraction? No user target will be launched.",
			)
		)
			return;
		setBusy(true);
		setError("");
		try {
			await desktopClient.invoke(
				"binary_triage_test",
				{ environmentId: "local", confirmed: true },
				{ timeoutMs: 420000 },
			);
			await refresh();
		} catch {
			setError(
				"Fixture testing did not establish full readiness. Refresh status; no operation is automatically retried.",
			);
			await refresh().catch(() => {});
		} finally {
			setBusy(false);
		}
	}
	return (
		<section
			aria-label="Binary Triage Pack readiness"
			className="space-y-3 rounded border p-3"
		>
			<h3 className="font-medium">Binary Triage Pack</h3>
			<p className="text-xs text-muted-foreground">
				Pinned radare2/r2pipe, YARA, capa and optional-use FLOSS static
				extraction. Opening this panel never runs tools or downloads packages. A
				receipt verifies owned fixtures for this backend—not arbitrary targets.
			</p>
			{capabilities.map((c) => (
				<div key={c.id} className="rounded border p-2 text-xs">
					<strong>
						{c.id} {c.version} — {labels[c.state] ?? c.state}
					</strong>
					<p>{c.reason}</p>
					{c.testedAt && <p>Last tested: {c.testedAt}</p>}
				</div>
			))}
			<div className="flex flex-wrap gap-2">
				<Button
					variant="outline"
					disabled={busy}
					onClick={() =>
						void refresh().catch(() => setError("Readiness unavailable"))
					}
				>
					Refresh triage status
				</Button>
				<Button
					variant="outline"
					disabled={
						busy ||
						capabilities.length !== 4 ||
						capabilities.some((c) =>
							["needs-setup", "unsupported", "integrity-failed"].includes(
								c.state,
							),
						)
					}
					onClick={() => void test()}
				>
					{busy ? "Testing owned fixtures…" : "Test triage fixtures"}
				</Button>
			</div>
			{error && (
				<p role="alert" className="text-xs text-destructive">
					{error}
				</p>
			)}
		</section>
	);
}
