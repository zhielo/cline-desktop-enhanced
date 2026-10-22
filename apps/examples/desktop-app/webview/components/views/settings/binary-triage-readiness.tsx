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
// Only host-owned diagnostic tokens are exposed; never arbitrary transport text.
export function ownedTriageDiagnostic(error: unknown): string {
 const message = error instanceof Error ? error.message : "";
 const match = message.match(/Owned (radare2|yara|capa|floss) fixture failed; not ready \((completed|failed|timed-out|cancelled|termination-unconfirmed); ((?:request|yara-import|yara-rules|r2-import|r2-open|r2-inspect|native-launch|native-result):(?:ValueError|FileNotFoundError|ModuleNotFoundError|ImportError|OSError|CalledProcessError|PermissionError)|worker-exit|no diagnostic)\)/);
 if (match) return match[0];
 const fixed = [
  "Binary triage requires the trusted desktop connection; no model command bypass",
  "Verified analysis Python runtime required; use Setup Center",
  "Wait for active triage jobs before readiness testing",
  "Explicit owned-fixture confirmation required",
 ];
 return fixed.find(value => message.includes(value)) ?? "No bounded engine diagnostic was returned";
}
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
		} catch (cause) {
			setError(
				`Fixture testing did not establish full readiness. ${ownedTriageDiagnostic(cause)}. Refresh status; no operation is automatically retried.`,
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
                AI route: reverse_engineer → advanced_analysis → binary_triage. Execution requires an owning local Full Access session, Static/Hybrid Analysis, a matching fixture test and separate approval. Ready does not mean currently authorized. YARA coverage is limited to bundled neutral marker/header rules. FLOSS: PE static strings only.
			</p>
			{capabilities.map((c) => (
				<div key={c.id} className="rounded border p-2 text-xs">
					<strong>
						{c.id} {c.version} — {labels[c.state] ?? c.state}
					</strong>
					<p>{c.reason}</p>
                    <p>Installed: {["ready","installed-not-tested"].includes(c.state) ? "verified inventory" : "not verified"}. Fixture tested: {c.state === "ready" ? "yes, matching identity" : "not ready"}.</p>
                    <p>AI route: supported on local Cline Desktop. Permission: checked per request, never granted by this status.</p>
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
