"use client";
import { useCallback, useEffect, useId, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { desktopClient } from "@/lib/desktop-client";
const steps = [
	["inspect", "Inspect APK / DEX structure"],
	["validate_android_container", "Validate AAB / inspect split container"],
	["disassemble_smali", "Decode ordinary APK / disassemble DEX"],
	["search_smali", "Search decoded Smali"],
	["read_smali_method", "Read an exact Smali method"],
	["decompile", "View one class with JADX"],
	["assemble_smali", "Assemble Smali to a new DEX"],
	["rebuild_apk", "Rebuild a new unsigned APK"],
	["compare_apks", "Compare original and candidate APK"],
	["align_apk", "Align a new APK (16 KiB pages)"],
	["sign_apk", "Sign a new APK with host test key"],
	["verify_apk_signature", "Verify certificate and signature schemes"],
];
const writes = new Set([
	"assemble_smali",
	"rebuild_apk",
	"align_apk",
	"sign_apk",
]);
export function AndroidToolchainWorkspace({
	environmentId = "local",
	onPrepare,
}: {
	environmentId?: string;
	onPrepare: (request: Record<string, unknown>) => unknown;
}) {
	const prefix = useId(),
		[operation, setOperation] = useState("inspect"),
		[target, setTarget] = useState(""),
		[output, setOutput] = useState(""),
		[selector, setSelector] = useState(""),
		[secondary, setSecondary] = useState(""),
		[ack, setAck] = useState(false),
		[signing, setSigning] = useState(false),
		[status, setStatus] = useState("unavailable"),
		[busy, setBusy] = useState(false),
		[error, setError] = useState("");
	const local = environmentId === "local";
	const refresh = useCallback(async () => {
		const result = await desktopClient.invoke<{ state: string }>(
			"setup_center_android_status",
			{ environmentId },
		);
		setStatus(result.state);
	}, [environmentId]);
	useEffect(() => {
		if (local) void refresh().catch(() => setStatus("unavailable"));
	}, [local, refresh]);
	async function test() {
		if (
			!window.confirm(
				"Run fixed owned Android assemble/decode/rebuild/signature fixtures? A disposable fixture key is deleted afterwards. No user app is installed or launched.",
			)
		)
			return;
		setBusy(true);
		setError("");
		try {
			await desktopClient.invoke(
				"setup_center_android_test",
				{ environmentId, confirmed: true },
				{ timeoutMs: 600000 },
			);
			await refresh();
		} catch {
			setError(
				"Owned fixtures did not establish readiness. No automatic retry; inspect build/diagnostics before continuing.",
			);
		} finally {
			setBusy(false);
		}
	}
	const needsSelector = [
		"search_smali",
		"read_smali_method",
		"decompile",
	].includes(operation);
	function prepare() {
		const request: Record<string, unknown> = {
			engine: operation === "decompile" ? "jadx" : "auto",
			operation,
			target: target.trim(),
			timeout_ms: 120000,
			reuse_analysis: true,
		};
		if (writes.has(operation)) {
			request.output_file = output.trim();
			request.acknowledge_external_output = ack;
		}
		if (operation === "compare_apks") request.compare_target = secondary.trim();
		if (operation === "search_smali") request.smali_query = selector;
		if (operation === "read_smali_method") request.smali_method = selector;
		if (operation === "decompile") request.jadx_single_class = selector;
		if (operation === "sign_apk") request.confirm_test_signing = signing;
		void onPrepare(request);
	}
	return (
		<section
			aria-label="Android Analysis and Rebuild Pack"
			className="space-y-3"
		>
			<h3 className="font-semibold">Android Analysis &amp; Rebuild Pack</h3>
			<p className="text-xs">
				Pinned Java, Apktool, Smali/Baksmali, JADX, Bundletool and Android Build
				Tools. Inspect → decode → review/edit in Files → rebuild a new unsigned
				artifact → compare → align → separately sign → verify. Each step
				requires a fresh exact-request approval; opening this page runs no
				tools.
			</p>
			<output className="block">
				Pack status: {local ? status : "unsupported remote environment"}
			</output>
			<Button
				variant="outline"
				disabled={!local || busy}
				onClick={() => void test()}
			>
				{busy ? "Testing owned fixtures…" : "Test owned Android fixtures"}
			</Button>
			<p className="text-xs">
				A fixture pass does not certify arbitrary inputs, complete Dalvik/ART
				validity, AAB/split compatibility or device behavior. Static parsing is
				not an OS sandbox.
			</p>
			<label htmlFor={`${prefix}-operation`}>Android step</label>
			<select
				id={`${prefix}-operation`}
				className="w-full rounded border bg-background p-2 text-sm"
				value={operation}
				onChange={(e) => {
					setOperation(e.target.value);
					setAck(false);
					setSigning(false);
				}}
			>
				{steps.map(([id, label]) => (
					<option key={id} value={id}>
						{label}
					</option>
				))}
			</select>
			<label htmlFor={`${prefix}-target`}>
				Target file or decoded project directory
			</label>
			<Input
				id={`${prefix}-target`}
				value={target}
				onChange={(e) => setTarget(e.target.value)}
				placeholder="app.apk, classes.dex, or decoded-project"
			/>
			{needsSelector && (
				<>
					<label htmlFor={`${prefix}-selector`}>
						{operation === "search_smali"
							? "Literal search"
							: operation === "decompile"
								? "Exact Java class"
								: "Exact method name/signature (select a .smali file)"}
					</label>
					<Input
						id={`${prefix}-selector`}
						value={selector}
						onChange={(e) => setSelector(e.target.value)}
					/>
				</>
			)}
			{operation === "compare_apks" && (
				<>
					<label htmlFor={`${prefix}-compare`}>Candidate APK</label>
					<Input
						id={`${prefix}-compare`}
						value={secondary}
						onChange={(e) => setSecondary(e.target.value)}
					/>
				</>
			)}
			{writes.has(operation) && (
				<>
					<label htmlFor={`${prefix}-output`}>
						New output file — existing paths are rejected
					</label>
					<Input
						id={`${prefix}-output`}
						value={output}
						onChange={(e) => setOutput(e.target.value)}
						placeholder="C:\\Cline-Outputs\\owned-app\\deliverables\\candidate.apk"
					/>
					<label className="flex gap-2">
						<input
							type="checkbox"
							checked={ack}
							onChange={(e) => setAck(e.target.checked)}
						/>
						I authorize writing this new artifact outside the managed analysis
						cache.
					</label>
				</>
			)}
			{operation === "sign_apk" && (
				<>
					<p className="text-xs">
						Requires a host-configured authorized test keystore. Never enter
						passwords, private keys or keystore contents here. Original app
						signatures cannot be preserved by rebuilding. No automatic install,
						launch or key generation.
					</p>
					<label className="flex gap-2">
						<input
							type="checkbox"
							checked={signing}
							onChange={(e) => setSigning(e.target.checked)}
						/>
						I separately authorize signing this candidate with my configured
						test identity.
					</label>
				</>
			)}
			<p className="text-xs">
				AAB/APKS/APKM/XAPK are not ordinary APKs. Validate/inventory first;
				explicitly select base/split artifacts. Bundletool does not
				automatically merge, sign or install them. Frida, Objection and ADB
				runtime work remain separate authorized device workflows.
			</p>
			<Button
				disabled={
					!local ||
					busy ||
					!target.trim() ||
					(needsSelector && !selector.trim()) ||
					(operation === "compare_apks" && !secondary.trim()) ||
					(writes.has(operation) && (!output.trim() || !ack)) ||
					(operation === "sign_apk" && !signing)
				}
				onClick={prepare}
			>
				Prepare exact Android step for review
			</Button>
			{error && <p role="alert">{error}</p>}
		</section>
	);
}
