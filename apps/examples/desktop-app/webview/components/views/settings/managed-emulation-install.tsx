"use client";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import type {
	EmulationEngine,
	ManagedPackStatus,
} from "../../../../sidecar/managed-emulation-pack.mjs";

const engines: readonly EmulationEngine[] = [
	"qiling",
	"unidbg",
	"rnidbg",
	"speakeasy",
];
export function ManagedEmulationInstall({
	status,
	busy,
	action,
	job,
	cancel,
}: {
	status?: ManagedPackStatus;
	busy: boolean;
	action: (
		command: string,
		confirmation: string,
		extra?: Record<string, unknown>,
	) => Promise<void>;
	job?: { id: string; command: string; status: string } | null;
	cancel?: (jobId: string) => Promise<void>;
}) {
	const [selection, setSelection] = useState<EmulationEngine[]>([...engines]);
	const [cancelling, setCancelling] = useState(false);
	const available = status?.available === true;
	return (
		<section
			aria-label="Emulation Framework Pack installation"
			className="space-y-3 rounded border p-4"
		>
			<h3 className="font-semibold">Emulation Framework Pack</h3>
			<p>
				Qiling · unidbg · rnidbg · Speakeasy. Install all four, or choose
				individual engines below. Existing Unicorn and Ubuntu/WSL are not
				modified.
			</p>
			{!available && (
				<output className="block">
					This build does not yet contain the reviewed installable images,
					corresponding sources and notices. Installation cannot start from
					development test images.
				</output>
			)}
			<details>
				<summary>Choose individual engines (advanced)</summary>
				<fieldset disabled={busy || !available} className="space-y-2">
					<legend>Engines to install</legend>
					{engines.map((id) => (
						<label key={id} className="flex items-center gap-2">
							<input
								type="checkbox"
								checked={selection.includes(id)}
								onChange={(event) =>
									setSelection((previous) =>
										engines.filter((engine) =>
											engine === id
												? event.target.checked
												: previous.includes(engine),
										),
									)
								}
							/>
							{id}
						</label>
					))}
				</fieldset>
			</details>
			<div className="flex flex-wrap gap-2">
				<Button
					disabled={busy || !available}
					onClick={() =>
						void action(
							"setup_center_emulation_install",
							"Install verified bundled Qiling, unidbg, rnidbg and Speakeasy engine files with their corresponding sources and notices? Existing installations are preserved. This file installation does not start a VM, execute an engine or authorize target analysis.",
							{ engines: [...engines] },
						)
					}
				>
					Install all four
				</Button>
				<Button
					disabled={busy || !available || selection.length === 0}
					onClick={() =>
						void action(
							"setup_center_emulation_install",
							`Install verified bundled files for ${selection.join(", ")}? Unselected engine installations are preserved. No VM or engine is started.`,
							{ engines: selection },
						)
					}
				>
					Install selected engines ({selection.length})
				</Button>
				<Button
					variant="outline"
					disabled={busy || !available || selection.length === 0}
					onClick={() =>
						void action(
							"setup_center_emulation_verify_files",
							"Rehash the selected installed engine files against this build's compiled catalog? This verifies file integrity only, not framework execution or VM containment.",
							{ engines: selection },
						)
					}
				>
					Verify selected files
				</Button>
			</div>
			<ul aria-label="Emulation engine installation states">
				{status?.engines.map((engine) => (
					<li key={engine.id}>
						{engine.id}: {engine.status}
					</li>
				))}
			</ul>
			{job?.status === "running" &&
				job.command === "setup_center_emulation_install" && (
					<Button
						variant="outline"
						disabled={cancelling || !cancel}
						onClick={() => {
							if (!cancel) return;
							setCancelling(true);
							void cancel(job.id).finally(() => setCancelling(false));
						}}
					>
						Request installation cancellation
					</Button>
				)}
			<p className="text-sm text-muted-foreground">
				Installed files are not runtime readiness. Privileged activation and
				Hyper-V execution remain unavailable until their implementation and
				acceptance are complete.
			</p>
		</section>
	);
}
