"use client";
import { useCallback, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { desktopClient } from "@/lib/desktop-client";
import { PageFrame, PageHeader } from "../page-layout";

type Preferences = {
	schemaVersion: 1;
	idaHome: string;
	adbPath: string;
	deviceSerial: string;
	deviceKind: "physical" | "emulator";
	workerEndpoint: string;
	workerPublicKey: string;
	acceptedPlatformToolsLicense: boolean;
};
type Status = {
  desktopBuild?: {version:string; sourceCommit:string; capabilitySchema:string};
  selectedRuntime?: {runtimeId?:string; source?:string; integrity?:string};
  licensedArchitectures?: string[];
	preferences: Preferences;
	fullStatus: string;
	checkedAt?: string;
	lastCheckedAt?: string;
	packs: { id: string; available: boolean; selected: boolean }[];
	features: {
		id: string;
		label: string;
		status: string;
		reason: string;
		version?: string;
	}[];
	limitations: string[];
	licensedStatus: string;
	deviceStatus: string;
	workerStatus: string;
};
export function SetupCenter() {
	const [notice, setNotice] = useState("");
  const [idaArchitecture, setIdaArchitecture] = useState<"x86_64" | "arm64">("x86_64");
  const [operationStarted, setOperationStarted] = useState<number | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);

	const [status, setStatus] = useState<Status | null>(null),
		[form, setForm] = useState<Preferences | null>(null),
		[busy, setBusy] = useState(false),
		[message, setMessage] = useState(""),
		[error, setError] = useState(""),
		[devices, setDevices] = useState<{ serial: string; state: string }[]>([]);
  useEffect(() => {
    if (!busy || operationStarted === null) return;
    const timer = setInterval(() => setElapsedSeconds(Math.floor((Date.now()-operationStarted)/1000)), 1000);
    return () => clearInterval(timer);
  }, [busy, operationStarted]);
	const refresh = useCallback(async () => {
		const reply = await desktopClient.invoke<Status>("setup_center_status", {
			environmentId: "local",
		});
		setStatus(reply);
		setForm(reply.preferences);
	}, []);
	useEffect(() => {
		void refresh().catch((e) =>
			setError(e instanceof Error ? e.message : "Setup status unavailable"),
		);
	}, [refresh]);
	async function action(
		command: string,
		confirmation: string,
		extra: Record<string, unknown> = {},
	) {
		if (confirmation && !window.confirm(confirmation)) return;
		setBusy(true);
    setOperationStarted(Date.now()); setElapsedSeconds(0);
		setError("");
		setMessage("");
		try {
			const reply = await desktopClient.invoke<Record<string, unknown>>(
				command,
				{ environmentId: "local", confirmed: true, ...extra },
				{ timeoutMs: 300000 },
			);
			setMessage(JSON.stringify(reply, null, 2));
			await refresh();
		} catch (e) {
			setError(e instanceof Error ? e.message : "Setup operation failed");
		} finally {
			setBusy(false);
		}
	}
	async function detect() {
		setBusy(true);
		setError("");
		try {
			const reply = await desktopClient.invoke<{ idaCandidates: string[] }>(
				"setup_center_detect",
				{ environmentId: "local" },
			);
			setMessage(
				reply.idaCandidates.length
					? `Detected IDA installations: ${reply.idaCandidates.join("; ")}. Choose your installation before testing.`
					: "No IDA candidate detected. Choose your licensed installation folder.",
			);
			if (reply.idaCandidates[0])
				setForm((f) => (f ? { ...f, idaHome: reply.idaCandidates[0] } : f));
		} catch (e) {
			setError(e instanceof Error ? e.message : "Detection failed");
		} finally {
			setBusy(false);
		}
	}
	async function browseIda() {
		const path = await desktopClient.invoke<string | null>(
			"pick_workspace_directory",
			{ environmentId: "local" },
		);
		if (path) setForm((f) => (f ? { ...f, idaHome: path } : f));
	}
	async function devicesRefresh() {
		setBusy(true);
		setError("");
		try {
			const r = await desktopClient.invoke<{
				devices: typeof devices;
				reason: string;
			}>("setup_center_devices", { environmentId: "local" });
			setDevices(r.devices);
			setMessage(r.reason);
		} catch (e) {
			setError(e instanceof Error ? e.message : "Device discovery failed");
		} finally {
			setBusy(false);
		}
	}
	const change = (key: keyof Preferences, value: string) =>
		setForm((f) => (f ? { ...f, [key]: value } : f));
	return (
		<PageFrame>
			<PageHeader
				title="Setup Center"
				subtitle="Install supported private engine packs, then verify actual capabilities. Licenses and device authorization stay explicit."
			/>
			<div className="space-y-6 p-6">
        <p>Installed desktop: {status?.desktopBuild?.version ?? "Unknown"}; build <code>{status?.desktopBuild?.sourceCommit ?? "Unknown"}</code>.</p>
        <p>Selected runtime: <code>{status?.selectedRuntime?.runtimeId ?? "Unknown"}</code>. Core and full are separate selections; installing an updated .exe alone does not select the full pack.</p>
				<p>
					Full pack:{" "}
					<output aria-label="Full capability pack status">
						{status?.fullStatus ?? "Checking setup"}
					</output>
					.{" "}
					{status?.checkedAt
						? `Last owned-fixture test: ${status.checkedAt}`
						: "Package presence alone is not execution proof."}
					{!status?.checkedAt && status?.lastCheckedAt
						? ` Previous test ${status.lastCheckedAt} is stale; retest the selected runtime.`
						: ""}
				</p>
				<div className="flex flex-wrap gap-2">
					<Button
						disabled={busy}
						onClick={() =>
							void action(
								"setup_center_apply_backend",
								"Apply saved setup to the shared local backend? It restarts only after an accepted drain and confirmed idle state. Busy or unknown work is left running. Other idle clients reconnect; no prompt is replayed.",
							)
						}
					>
						Apply setup to idle backend
					</Button>
					<Button
						disabled={busy}
						onClick={() =>
							void action(
								"setup_center_install_full",
								"Install all supported local engine packs from verified installer resources and run fixed owned fixtures? I have reviewed and accept the bundled Android platform-tools notices. No network download, user pip, target binary, IDA license change or phone modification is performed. Existing shared Hub jobs are not restarted.",
								{ acceptedPlatformToolsLicense: true },
							)
						}
					>
						Install all supported components
					</Button>
					<Button
						disabled={busy}
						onClick={() =>
							void action(
								"setup_center_test_full",
								"Run bounded fixed owned engine fixtures? No target binary is executed.",
							)
						}
					>
						Test every local engine
					</Button>
					<Button
						disabled={busy}
						onClick={() =>
							void action(
								"setup_center_install_full",
								"Repair the full private capability packs from verified installed resources? I have reviewed and accept the bundled Android platform-tools notices. Old versions and project data stay intact.",
								{ acceptedPlatformToolsLicense: true },
							)
						}
					>
						Repair full packs
					</Button>
					<Button
						disabled={busy}
						onClick={() =>
							void action(
								"setup_center_rollback_core",
								"Select the previous core runtime without deleting full packs, history or project data? Existing backend processes need a separate restart.",
							)
						}
					>
						Roll back to core
					</Button>
				</div>
				<Button
					disabled={busy}
					onClick={() =>
						void desktopClient
							.invoke<{ notice: string }>("setup_center_licenses", {
								environmentId: "local",
							})
							.then((r) => setNotice(r.notice))
							.catch((e) => setError(String(e)))
					}
				>
					Read bundled platform-tools notices
				</Button>
				{notice && (
					<label className="block">
						Bundled Android platform-tools notices
						<textarea
							readOnly
							className="block w-full rounded border p-2"
							rows={8}
							value={notice}
						/>
					</label>
				)}
				<p>
					Angr has its own private interpreter to avoid incompatible solver
					dependencies. Packs load on demand. No system Python or
					environment-variable setup is required.
				</p>
				<p>{status?.deviceStatus}</p>
				<p>{status?.workerStatus}</p>
				<ul className="space-y-2">
					{status?.features.map((f) => (
						<li key={f.id}>
							<strong>
								{f.label}: {f.status}
							</strong>
							{f.version ? ` (${f.version})` : ""} — {f.reason}
						</li>
					))}
				</ul>
				{form && (
					<div className="space-y-4">
						<h2 className="text-lg font-semibold">Licensed IDA and Hex-Rays</h2>
						<p>{status?.licensedStatus}</p>
            <label className="block">IDA acceptance processor
              <select aria-label="IDA acceptance processor" value={idaArchitecture} disabled={busy} onChange={e => setIdaArchitecture(e.target.value as "x86_64" | "arm64")}>
                <option value="x86_64">x86-64</option><option value="arm64">ARM64 / AArch64</option>
              </select>
            </label>
            <p>Owned-fixture acceptance for selected processor: {status?.licensedArchitectures?.includes(idaArchitecture) ? "Passed for this executable" : "Not verified; test its licensed decompiler"}.</p>
						<label className="block">
							IDA installation folder
							<input
								className="block w-full rounded border p-2"
								value={form.idaHome}
								onChange={(e) => change("idaHome", e.target.value)}
							/>
						</label>
						<div className="flex flex-wrap gap-2">
							<Button disabled={busy} onClick={() => void detect()}>
								Detect installed IDA
							</Button>
							<Button
								disabled={busy}
								onClick={() =>
									void browseIda().catch((e) => setError(String(e)))
								}
							>
								Choose IDA folder
							</Button>
							<Button
								disabled={busy}
								onClick={() =>
									void action(
										"setup_center_test_ida",
										`I own an authorized IDA/Hex-Rays license. Save this IDA folder and run one fixed owned ${idaArchitecture} selected-function decompilation? This does not install a license or execute the ELF.`,
										{ authorizedLicense: true, architecture: idaArchitecture, idaHome: form.idaHome },
									)
								}
							>
								Test licensed IDA
							</Button>
						</div>
						<p>
							This test saves only the selected IDA folder. An owned processor test does
              not validate every license or arbitrary target compatibility.
						</p>
						<h2 className="text-lg font-semibold">
							Android device or emulator
						</h2>
						<label className="block">
							Installed ADB executable
							<input
								className="block w-full rounded border p-2"
								value={form.adbPath}
								onChange={(e) => change("adbPath", e.target.value)}
							/>
						</label>
						<label className="block">
							Exact device serial
							<input
								className="block w-full rounded border p-2"
								value={form.deviceSerial}
								onChange={(e) => change("deviceSerial", e.target.value)}
							/>
						</label>
						<label className="block">
							Device kind
							<select
								className="block rounded border p-2"
								value={form.deviceKind}
								onChange={(e) => change("deviceKind", e.target.value)}
							>
								<option value="physical">Physical device</option>
								<option value="emulator">Emulator</option>
							</select>
						</label>
						<div className="flex flex-wrap gap-2">
							<Button disabled={busy} onClick={() => void devicesRefresh()}>
								Discover connected devices
							</Button>
							<Button
								disabled={busy}
								onClick={() =>
									void action(
										"setup_center_test_device",
										"Check exact device connectivity and emulator identity using read-only ADB commands? No rooting, flashing, application installation or capture is performed.",
									)
								}
							>
								Test selected device
							</Button>
						</div>
						<ul>
							{devices.map((d) => (
								<li key={d.serial}>
									<button
										type="button"
										className="underline"
										onClick={() => change("deviceSerial", d.serial)}
									>
										{d.serial} — {d.state}
									</button>
								</li>
							))}
						</ul>
						<h2 className="text-lg font-semibold">
							Isolated dynamic-analysis worker
						</h2>
						<label className="block">
							Worker HTTPS URL
							<input
								className="block w-full rounded border p-2"
								value={form.workerEndpoint}
								onChange={(e) => change("workerEndpoint", e.target.value)}
							/>
						</label>
						<label className="block">
							Pinned Ed25519 public key
							<textarea
								className="block w-full rounded border p-2"
								rows={3}
								value={form.workerPublicKey}
								onChange={(e) => change("workerPublicKey", e.target.value)}
							/>
						</label>
						<p>
							Public key only—never paste a private key or credential.
							Installing QBDI does not provision VM isolation. Target tracing
							and Android capture retain independent exact
							worker/upload/execution approvals.
						</p>
						<Button
							disabled={busy}
							onClick={() =>
								void action(
									"setup_center_test_worker",
									"Probe the exact configured HTTPS worker and verify its signed capability manifest? No artifact is uploaded or executed.",
								)
							}
						>
							Test signed worker connection
						</Button>
						<div>
							<Button
								disabled={busy}
								onClick={() =>
									void action(
										"setup_center_save",
										"Save these exact local tool/device/worker settings? Worker identity changes require fresh analysis approval. Existing shared backend processes need a restart.",
										{ preferences: form },
									)
								}
							>
								Save setup settings
							</Button>
						</div>
					</div>
				)}
				{busy && (
					<p aria-live="polite">
						Setup operation running{operationStarted === null ? "" : ` — ${elapsedSeconds}s elapsed; response deadline 300s`}; elapsed time is not engine progress. Existing project jobs
						are not restarted.
					</p>
				)}
				{error && <p role="alert">{error}</p>}
				{message && (
					<output
						aria-live="polite"
						className="block whitespace-pre-wrap break-words"
					>
						{message}
					</output>
				)}
				<h2 className="text-lg font-semibold">Acceptance boundaries</h2>
				<ul>
					{status?.limitations.map((t) => (
						<li key={t}>{t}</li>
					))}
				</ul>
				<p>
					Automatic installer updates remain disabled until owner signing and
					staged installer/data rollback are configured. Capability-pack
					rollback above is not an installer or database-schema downgrade.
				</p>
			</div>
		</PageFrame>
	);
}
