"use client";
import {
	SetupCapabilityDirectoryView,
	type SetupCapabilityDirectory,
	type OptionalFramework,
} from "./setup-capability-directory";
import { BinaryTriageReadiness } from "./binary-triage-readiness";
import { useCallback, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { desktopClient } from "@/lib/desktop-client";
import { BackendConnectionStatus } from "@/components/backend-connection-status";
import { PageFrame, PageHeader } from "../page-layout";

type Preferences = {
	schemaVersion: 1;
	idaHome: string;
	ghidraHome?: string;
	adbPath: string;
	deviceSerial: string;
	deviceKind: "physical" | "emulator";
	workerEndpoint: string;
	workerPublicKey: string;
	acceptedPlatformToolsLicense: boolean;
};
type SetupJob = {
	id: string;
	command: string;
	status: "running" | "completed" | "failed" | "interrupted";
	phase: string;
	startedAt: string;
	error?: string;
};
type Status = {
	aiCapabilities?: SetupCapabilityDirectory;
	optionalFrameworks?: OptionalFramework[];
	specialistProfiles?: {
		id: string;
		status: string;
		checkedAt?: string;
		scope: string;
	}[];
	ghidra?: { status: string; javaVersion?: string; reason: string };
	firstPartyAnalysis?: {
		installed: boolean;
		parser: string;
		staticFixture: { status: string; checkedAt?: string };
		targetSupported: string;
		nativeProvider: string;
		runtimeCapture: string;
		behaviorVerification: string;
	};
	setupJob?: SetupJob | null;
	desktopBuild?: {
		version: string;
		sourceCommit: string;
		capabilitySchema: string;
	};
	selectedRuntime?: { runtimeId?: string; source?: string; integrity?: string };
	licensedArchitectures?: string[];
	preferences: Preferences;
	fullStatus: string;
	checkedAt?: string;
	lastCheckedAt?: string;
	packs: { id: string; available: boolean; selected: boolean }[];
	features: {
		id: string;
		label: string;
		aiRoute?: string;
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
	const [capabilityFilter, setCapabilityFilter] = useState(""),
		[attentionOnly, setAttentionOnly] = useState(false);
	const [notice, setNotice] = useState("");
	const [setupJob, setSetupJob] = useState<SetupJob | null>(null);
	const [awaitingReceipt, setAwaitingReceipt] = useState(false);
	const [idaArchitecture, setIdaArchitecture] = useState<"x86_64" | "arm64">(
		"x86_64",
	);
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
		const timer = setInterval(
			() =>
				setElapsedSeconds(Math.floor((Date.now() - operationStarted) / 1000)),
			1000,
		);
		return () => clearInterval(timer);
	}, [busy, operationStarted]);
	const refresh = useCallback(async () => {
		const reply = await desktopClient.invoke<Status>("setup_center_status", {
			environmentId: "local",
		});
		setStatus(reply);
		setForm(reply.preferences);
		if (reply.setupJob) {
			setSetupJob(reply.setupJob);
			if (
				reply.setupJob.status === "running" ||
				reply.setupJob.status === "interrupted"
			) {
				setBusy(true);
				setOperationStarted(Date.parse(reply.setupJob.startedAt));
			}
		}
	}, []);
	useEffect(() => {
		const saved = localStorage.getItem("cline.setup.ida-processor");
		if (saved === "arm64" || saved === "x86_64") setIdaArchitecture(saved);
		if (localStorage.getItem("cline.setup.pending-admission")) {
			setAwaitingReceipt(true);
			setBusy(true);
		}
		void refresh().catch((e) =>
			setError(e instanceof Error ? e.message : "Setup status unavailable"),
		);
	}, [refresh]);
	useEffect(() => {
		if (!awaitingReceipt && setupJob?.status !== "running") return;
		let disposed = false;
		let timer: ReturnType<typeof setTimeout>;
		const poll = async () => {
			try {
				const reply = await desktopClient.invoke<{ job: SetupJob | null }>(
					"setup_center_job_status",
					{
						environmentId: "local",
						...(setupJob?.id ? { jobId: setupJob.id } : {}),
					},
					{ timeoutMs: 15000 },
				);
				if (disposed) return;
				if (reply.job) {
					setSetupJob(reply.job);
					setAwaitingReceipt(false);
					localStorage.removeItem("cline.setup.pending-admission");
					setOperationStarted(Date.parse(reply.job.startedAt));
					if (reply.job.status !== "running") {
						setBusy(reply.job.status === "interrupted");
						setError(
							reply.job.status === "failed"
								? (reply.job.error ?? "Setup job failed")
								: reply.job.status === "interrupted"
									? reply.job.phase
									: "",
						);
						await refresh();
						return;
					}
					setError("");
				}
			} catch {
				if (!disposed)
					setError(
						"Setup status connection unavailable; this does not prove installation failed. Read-only reconnection continues; no operation is replayed.",
					);
			}
			if (!disposed) timer = setTimeout(poll, 1500);
		};
		timer = setTimeout(poll, 500);
		return () => {
			disposed = true;
			clearTimeout(timer);
		};
	}, [awaitingReceipt, setupJob?.id, setupJob?.status, refresh]);
	async function action(
		command: string,
		confirmation: string,
		extra: Record<string, unknown> = {},
	) {
		if (confirmation && !window.confirm(confirmation)) return;
		const tracked = [
			"setup_center_install_full",
			"setup_center_test_full",
			"setup_center_test_specialist",
			"setup_center_rollback_core",
			"setup_center_test_ida",
			"setup_center_test_ghidra",
			"setup_center_test_worker",
			"setup_center_test_device",
		].includes(command);
		if (tracked) {
			localStorage.setItem("cline.setup.pending-admission", command);
			setSetupJob(null);
		}
		let accepted = false;
		setBusy(true);
		setOperationStarted(Date.now());
		setElapsedSeconds(0);
		setError("");
		setMessage("");
		try {
			const reply = await desktopClient.invoke<Record<string, unknown>>(
				command,
				{
					environmentId: "local",
					confirmed: true,
					...extra,
					...(tracked ? { background: true } : {}),
				},
				{ timeoutMs: tracked ? 15000 : 300000 },
			);
			if (tracked && reply.setupJob) {
				const job = reply.setupJob as SetupJob;
				setSetupJob(job);
				accepted = true;
				localStorage.removeItem("cline.setup.pending-admission");
				setAwaitingReceipt(false);
				setOperationStarted(Date.parse(job.startedAt));
			} else {
				setMessage(JSON.stringify(reply, null, 2));
				await refresh();
				if (tracked) localStorage.removeItem("cline.setup.pending-admission");
			}
		} catch (e) {
			if (
				tracked &&
				/timed? ?out|timeout|WebSocket|transport|connection|closed/i.test(
					e instanceof Error ? e.message : String(e),
				)
			) {
				// RPC timeout is not worker failure; never replay an uncertain mutation.
				setAwaitingReceipt(true);
				accepted = true;
				setError(
					"Setup request response unavailable. Checking the persisted job; installation may still be running. No operation is replayed.",
				);
			} else {
				if (tracked) {
					localStorage.removeItem("cline.setup.pending-admission");
					setAwaitingReceipt(false);
				}
				setError(e instanceof Error ? e.message : "Setup operation failed");
			}
		} finally {
			if (!accepted) setBusy(false);
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
					: "No IDA candidate detected. Choose your installed IDA folder.",
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
				description="Install supported private engine packs, then verify actual capabilities. Licenses and device authorization stay explicit."
			/>
			<div className="space-y-6 p-6">
				<BackendConnectionStatus />
				<section
					className="space-y-3 rounded-md border p-4"
					aria-label="Optional specialist engines"
				>
					<h3 className="font-semibold">Optional specialist engines</h3>
					<p className="text-sm text-muted-foreground">
						Independent from the full pack. Joern uses a pinned Linux runtime;
						angr symbolic uses the separate interpreter. A passed owned fixture
						is not target-wide readiness.
					</p>
					{(["angr", "joern"] as const).map((engine) => {
						const profile = status?.specialistProfiles?.find(
							(p) => p.id === engine,
						);
						return (
							<div key={engine}>
								<p>
									{engine}: {profile?.status ?? "not-tested"}
									{profile?.checkedAt ? ` — ${profile.checkedAt}` : ""}
								</p>
								<Button
									disabled={busy}
									onClick={() =>
										void action(
											"setup_center_test_specialist",
											`Run the fixed ${engine} owned fixture? No selected target is analyzed.`,
											{ engine },
										)
									}
								>
									Test {engine} specialist fixture
								</Button>
							</div>
						);
					})}
					<p className="text-sm text-muted-foreground">
						Speakeasy: prepare an emulate_windows task in Runtime Analysis;
						signed worker and upload/execution approval required. Qiling:
						optional static ELF profile. unidbg: optional ARM32/64 JNI. rnidbg:
						experimental ARM64 JNI. Each needs its own isolated worker; use
						Runtime workbench readiness. Nothing is auto-installed.
					</p>
				</section>
				<SetupCapabilityDirectoryView
					catalog={status?.aiCapabilities}
					frameworks={status?.optionalFrameworks}
				/>
				<BinaryTriageReadiness />
				<p className="text-xs">
					Installed does not mean verified. Ready requires an owned-fixture
					execution receipt; stale or not-tested components need an explicit
					test. Optional licensed engines and devices remain optional.
				</p>
				<section
					aria-label="First-party analysis readiness"
					className="space-y-2 rounded border p-3"
				>
					<h3>First-party JavaScript / Electron analysis</h3>
					<Button
						variant="outline"
						onClick={() =>
							void desktopClient
								.invoke<{ notices: string }>("first_party_analysis_notices", {
									environmentId: "local",
								})
								.then((r) => setNotice(r.notices))
								.catch(() => setError("Parser notices unavailable"))
						}
					>
						Read bundled parser notices
					</Button>
					<p>
						Parser bundled:{" "}
						{status?.firstPartyAnalysis?.installed
							? status.firstPartyAnalysis.parser
							: "Checking installed backend"}
						. No REA, separate Node installation or Python pack required.
					</p>
					<p>
						Owned static fixture:{" "}
						{status?.firstPartyAnalysis?.staticFixture.status ?? "not-tested"}.
						This is not target behavior verification.
					</p>
					<p className="text-xs">
						{status?.firstPartyAnalysis?.targetSupported}
					</p>
					<p className="text-xs">
						{status?.firstPartyAnalysis?.nativeProvider}
					</p>
					<p className="text-xs">
						{status?.firstPartyAnalysis?.runtimeCapture}
					</p>
					<Button
						disabled={busy}
						onClick={() =>
							void action(
								"first_party_analysis_selftest",
								"Run the bundled parser against fixed owned JavaScript fixtures? Target source is parsed, never executed; this does not certify native engines or runtime capture.",
							)
						}
					>
						Test first-party static analysis
					</Button>
				</section>
				<p>
					Installed desktop: {status?.desktopBuild?.version ?? "Unknown"}; build{" "}
					<code>{status?.desktopBuild?.sourceCommit ?? "Unknown"}</code>.
				</p>
				<p>
					Selected runtime:{" "}
					<code>{status?.selectedRuntime?.runtimeId ?? "Unknown"}</code>. Core
					and full are separate selections; installing an updated .exe alone
					does not select the full pack.
				</p>
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
						Test Python pack engines
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
				<output
					className="block"
					aria-live="polite"
					aria-label="Setup operation status"
				>
					{setupJob && (
						<span className="block">
							Job {setupJob.id}: {setupJob.status} — {setupJob.phase}.
						</span>
					)}
					{busy && (
						<span className="block">
							Setup operation running — {elapsedSeconds}s elapsed. Elapsed time
							is not engine progress. Request timeouts do not stop background
							setup; existing project jobs are not restarted.
						</span>
					)}
					{awaitingReceipt && (
						<span className="block">
							Awaiting persisted admission receipt; read-only reconnection only.
						</span>
					)}
				</output>
				{error && <p role="alert">{error}</p>}
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
				<div className="flex gap-3">
					<input
						aria-label="Filter capabilities"
						value={capabilityFilter}
						onChange={(e) => setCapabilityFilter(e.target.value)}
						placeholder="Find an engine or capability"
					/>
					<label>
						<input
							type="checkbox"
							checked={attentionOnly}
							onChange={(e) => setAttentionOnly(e.target.checked)}
						/>{" "}
						Needs attention only
					</label>
				</div>
				<p>
					AI discovery: reverse_engineer → analysis_command_catalog lists every
					registered Setup Center engine and its real operation. Use
					advanced_analysis → toolchain for inventory; full_readiness and
					angr_readiness run owned self-tests only. Listed does not mean ready;
					no separate REA runtime is needed.
				</p>
				<ul aria-label="Capability readiness" className="space-y-2">
					{status?.features
						.filter(
							(f) =>
								(!attentionOnly || f.status.toLowerCase() !== "ready") &&
								`${f.label} ${f.status} ${f.reason}`
									.toLowerCase()
									.includes(capabilityFilter.toLowerCase()),
						)
						.map((f) => (
							<li key={f.id}>
								<strong>
									{f.label}: {f.status}
								</strong>
								{f.version ? ` (${f.version})` : ""} — {f.reason}
								{f.aiRoute && (
									<p className="text-sm">
										AI route: reverse_engineer → advanced_analysis → {f.aiRoute}
									</p>
								)}
							</li>
						))}
				</ul>
				{form && (
					<div className="space-y-4">
						<h2 className="text-lg font-semibold">Ghidra and Java</h2>
						<output className="block">
							Ghidra: {status?.ghidra?.status ?? "Not tested"}
							{status?.ghidra?.javaVersion
								? ` — Java ${status.ghidra.javaVersion}`
								: ""}
						</output>
						<p>
							{status?.ghidra?.reason ??
								"Ghidra has a separate explicit owned-fixture test; Python pack readiness does not cover it."}
						</p>
						<label className="block">
							Ghidra installation folder
							<input
								className="block w-full rounded border p-2"
								value={form.ghidraHome ?? ""}
								onChange={(e) => change("ghidraHome", e.target.value)}
							/>
						</label>
						<div className="flex flex-wrap gap-2">
							<Button
								disabled={busy}
								onClick={() =>
									void desktopClient
										.invoke<string | null>("pick_workspace_directory", {
											environmentId: "local",
										})
										.then((path) => {
											if (path) change("ghidraHome", path);
										})
										.catch((e) => setError(String(e)))
								}
							>
								Choose Ghidra folder
							</Button>
							<Button
								disabled={busy}
								onClick={() =>
									void action(
										"setup_center_save_ghidra",
										"Save this Ghidra installation? No analysis is executed. Apply saved setup to an idle backend separately.",
										{ ghidraHome: form.ghidraHome ?? "" },
									)
								}
							>
								Save Ghidra installation
							</Button>
							<Button
								disabled={busy}
								onClick={() =>
									void action(
										"setup_center_test_ghidra",
										"Save this Ghidra folder and run bounded headless analysis and selected decompilation on one owned x86-64 ELF? This launches Java and Ghidra, not target code. No packages are installed.",
										{ ghidraHome: form.ghidraHome ?? "" },
									)
								}
							>
								Test Ghidra and Java
							</Button>
						</div>
						<p>
							Use a JDK supported by your Ghidra version. Configure Java with
							Ghidra's supported launcher settings if the test reports no
							compatible JDK. This test is separate from the Python pack and
							does not establish every processor or target's compatibility.
						</p>
						<h2 className="text-lg font-semibold">
							IDA and Hex-Rays integration
						</h2>
						<p>{status?.licensedStatus}</p>
						<label className="block">
							IDA acceptance processor
							<select
								aria-label="IDA acceptance processor"
								value={idaArchitecture}
								disabled={busy}
								onChange={(e) => {
									const value = e.target.value as "x86_64" | "arm64";
									setIdaArchitecture(value);
									localStorage.setItem("cline.setup.ida-processor", value);
								}}
							>
								<option value="x86_64">x86-64</option>
								<option value="arm64">ARM64 / AArch64</option>
							</select>
						</label>
						<p>
							Owned-fixture acceptance for selected processor:{" "}
							{status?.licensedArchitectures?.includes(idaArchitecture)
								? "Passed for this executable"
								: "Not tested or stale — optional; direct IDA analysis remains available"}
							.
						</p>
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
										"setup_center_save_ida",
										"Save this IDA installation for direct analysis? No integration test or license change is performed. Existing Hub processes require the separate idle-only setup application.",
										{ idaHome: form.idaHome },
									)
								}
							>
								Save IDA installation
							</Button>
							<Button
								disabled={busy}
								onClick={() =>
									void action(
										"setup_center_test_ida",
										`Save this IDA folder and run one fixed owned ${idaArchitecture} selected-function decompilation? IDA reports actual plugin/runtime errors. This does not alter licensing or execute the ELF.`,
										{
											architecture: idaArchitecture,
											idaHome: form.idaHome,
										},
									)
								}
							>
								Test IDA integration (optional)
							</Button>
						</div>
						<p>
							The test is optional and is not a gate for direct IDA analysis.
							Detection or folder selection alone does not prove IDAPython or
							the selected Hex-Rays processor works. Actual execution reports
							plugin, license and runtime errors. An owned processor test does
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
