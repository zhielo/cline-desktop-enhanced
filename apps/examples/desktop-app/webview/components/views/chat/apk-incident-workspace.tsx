"use client";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { desktopClient } from "@/lib/desktop-client";
import { ownedFixtureRows } from "../../../../shared/incident-readiness";

type Plan = {
	id: string;
	requestHash: string;
	requirements: string[];
	request: Record<string, unknown>;
	kind: string;
};
type Case = {
	id: string;
	revision: number;
	status: string;
	stage: string;
	planId: string;
	controlUnavailable?: boolean;
	request: Record<string, unknown>;
	result?: string;
	error?: string;
};
export function ApkIncidentWorkspace({
	cwd,
	environmentId,
}: {
	cwd?: string;
	environmentId?: string;
}) {
	const scope = useMemo(() => ({ cwd, environmentId }), [cwd, environmentId]);
	const epoch = useRef(0);
	const [operation, setOperation] = useState("observe_apk"),
		[target, setTarget] = useState(""),
		[candidate, setCandidate] = useState(""),
		[pkg, setPkg] = useState(""),
		[serial, setSerial] = useState(""),
		[reproduction, setReproduction] = useState(""),
		[expected, setExpected] = useState(""),
		[seconds, setSeconds] = useState(30);
	const [plan, setPlan] = useState<Plan | null>(null),
		[confirmed, setConfirmed] = useState<string[]>([]),
		[current, setCurrent] = useState<Case | null>(null),
		[cases, setCases] = useState<
			{ id: string; status: string; stage: string }[]
		>([]),
		[busy, setBusy] = useState(false),
		[error, setError] = useState(""),
		[readiness, setReadiness] = useState<unknown>(),
		[notes, setNotes] = useState(""),
		[reproduced, setReproduced] = useState(false),
		[regressed, setRegressed] = useState(false),
		[correlation, setCorrelation] = useState("");
	const call = useCallback(
		<T,>(command: string, args: Record<string, unknown> = {}) =>
			desktopClient.invoke<T>(command, { ...scope, ...args }),
		[scope],
	);
	const refresh = useCallback(async () => {
		const at = epoch.current;
		try {
			const rows = await call<typeof cases>("list_apk_incidents");
			if (at === epoch.current) setCases(rows);
		} catch (e) {
			if (at === epoch.current) setError(String(e));
		}
	}, [call]);
	useEffect(() => {
		epoch.current++;
		setPlan(null);
		setConfirmed([]);
		setCurrent(null);
		setCases([]);
		setReadiness(undefined);
		setBusy(false);
		setError("");
		setTarget("");
		setCandidate("");
		setSerial("");
		setPkg("");
		setReproduction("");
		setExpected("");
		setNotes("");
		setReproduced(false);
		setRegressed(false);
		setCorrelation("");
		void refresh();
		return () => {
			epoch.current++;
		};
	}, [refresh]);
	useEffect(() => {
		if (
			!current ||
			!["accepted", "running"].includes(current.status) ||
			current.controlUnavailable
		)
			return;
		const at = epoch.current,
			id = current.id;
		const timer = setInterval(() => {
			void call<Case>("get_apk_incident", { id })
				.then((value) => {
					if (at === epoch.current) setCurrent(value);
				})
				.catch((e) => {
					if (at === epoch.current) setError(String(e));
				});
		}, 2000);
		return () => clearInterval(timer);
	}, [
		call,
		current?.id,
		current?.status,
		current?.controlUnavailable,
		current,
	]);
	async function action(run: () => Promise<void>) {
		const at = epoch.current;
		setBusy(true);
		setError("");
		try {
			await run();
		} catch (e) {
			if (at === epoch.current)
				setError(e instanceof Error ? e.message : String(e));
		} finally {
			if (at === epoch.current) {
				setBusy(false);
				void refresh();
			}
		}
	}
	async function prepare(rollback = false) {
		const at = epoch.current;
		const input =
			rollback && current
				? {
						...current.request,
						operation: "rollback_apk",
						rollback_case_id: current.id,
					}
				: {
						operation,
						target,
						...(candidate ? { compare_target: candidate } : {}),
						package: pkg,
						device_serial: serial,
						reproduction,
						expected,
						duration_seconds: seconds,
					};
		const value = await call<Plan>("prepare_apk_incident", { input });
		if (at === epoch.current) {
			setPlan(value);
			setConfirmed([]);
		}
	}
	async function start() {
		if (!plan || !plan.requirements.every((r) => confirmed.includes(r))) return;
		const selected = plan,
			at = epoch.current;
		setPlan(null);
		setConfirmed([]);
		const approved = await call<{ executionToken: string }>(
			"approve_analysis_task",
			{
				planId: selected.id,
				requestHash: selected.requestHash,
				requirements: selected.requirements,
			},
		);
		if (at !== epoch.current) return;
		// One-shot submission only. A response loss must be reconciled from saved cases, never automatically retried.
		if (selected.kind === "static") {
			const result = await call("run_static_analysis", {
				planId: selected.id,
				executionToken: approved.executionToken,
				input: selected.request,
			});
			if (at === epoch.current) {
				const discovered = await call<Record<string, unknown>>(
					"get_incident_readiness",
				);
				if (at === epoch.current)
					setReadiness({
						...discovered,
						rows: [
							...(Array.isArray(discovered.rows) ? discovered.rows : []),
							...ownedFixtureRows(result),
						],
						ownedFixtureHealth: result,
					});
			}
			return;
		}
		const receipt = await call<{ id: string }>("start_apk_incident", {
			planId: selected.id,
			executionToken: approved.executionToken,
		});
		const value = await call<Case>("get_apk_incident", { id: receipt.id });
		if (at === epoch.current) setCurrent(value);
	}
	const field = (label: string, value: string, set: (v: string) => void) => (
		<label className="block text-xs">
			{label}
			<input
				aria-label={label}
				className="mt-1 w-full rounded border bg-background p-2"
				value={value}
				onChange={(e) => set(e.target.value)}
			/>
		</label>
	);
	return (
		<section className="space-y-3 text-sm">
			<h3 className="font-semibold">APK incident debugger</h3>
			<p className="text-xs text-muted-foreground">
				Local, explicitly selected device. No automatic root, Frida, uninstall,
				log clearing, unknown sample replay, or claimed fix from a successful
				build. Use a dedicated authorized test device for patch installation.
			</p>
			<label className="block text-xs">
				Operation
				<select
					aria-label="Incident operation"
					className="w-full rounded border bg-background p-2"
					value={operation}
					onChange={(e) => setOperation(e.target.value)}
				>
					<option value="observe_apk">Observe already-running app</option>
					<option value="launch_apk">Explicitly launch and observe</option>
					<option value="validate_apk_patch">
						Verify, install candidate, launch, observe
					</option>
				</select>
			</label>
			{field("Original APK (workspace path)", target, setTarget)}
			{field("Candidate APK (patch validation only)", candidate, setCandidate)}
			{field("Exact package", pkg, setPkg)}
			{field("ADB device serial", serial, setSerial)}
			{field(
				"Manual reproduction steps (never executed as shell)",
				reproduction,
				setReproduction,
			)}
			{field("Expected behavior / regression checklist", expected, setExpected)}
			<label className="block text-xs">
				Observation seconds (2–120)
				<input
					aria-label="Observation seconds"
					type="number"
					min={2}
					max={120}
					value={seconds}
					onChange={(e) => setSeconds(Number(e.target.value))}
					className="w-full rounded border bg-background p-2"
				/>
			</label>
			<button
				disabled={busy || !!plan}
				type="button"
				onClick={() => void action(() => prepare())}
				className="rounded border px-3 py-2"
			>
				Prepare hash-bound plan
			</button>
			{plan && (
				<div className="space-y-2 rounded border p-3">
					<p>Review exact request and required approvals:</p>
					<pre className="max-h-48 overflow-auto text-xs whitespace-pre-wrap">
						{JSON.stringify(plan.request, null, 2)}
					</pre>
					{plan.requirements.map((requirement) => (
						<label key={requirement} className="flex gap-2 text-xs">
							<input
								type="checkbox"
								checked={confirmed.includes(requirement)}
								onChange={(e) =>
									setConfirmed((old) =>
										e.target.checked
											? [...old, requirement]
											: old.filter((r) => r !== requirement),
									)
								}
							/>
							{requirement}
						</label>
					))}
					<button
						type="button"
						disabled={
							busy || !plan.requirements.every((r) => confirmed.includes(r))
						}
						onClick={() => void action(start)}
						className="rounded border px-3 py-2"
					>
						Approve and start once
					</button>
					<button
						type="button"
						disabled={busy}
						onClick={() =>
							void action(async () => {
								await call("cancel_analysis_task", { planId: plan.id });
								setPlan(null);
							})
						}
						className="ml-2 underline"
					>
						Cancel plan
					</button>
				</div>
			)}
			<div className="flex flex-wrap gap-2">
				<button
					type="button"
					disabled={busy}
					onClick={() => void refresh()}
					className="rounded border p-2"
				>
					Refresh saved cases
				</button>
				<button
					type="button"
					disabled={busy}
					onClick={() =>
						void action(async () => {
							const at = epoch.current,
								value = await call("get_incident_readiness");
							if (at === epoch.current) setReadiness(value);
						})
					}
					className="rounded border p-2"
				>
					Tool readiness
				</button>
				<button
					type="button"
					disabled={busy}
					onClick={() =>
						void action(async () => {
							const at = epoch.current,
								p = await call<Plan>("prepare_analysis_task", {
									kind: "static",
									request: {
										engine: "auto",
										operation: "advanced_analysis",
										advanced_action: "analysis_readiness",
									},
								});
							if (at === epoch.current) {
								setPlan(p);
								setConfirmed([]);
							}
						})
					}
					className="rounded border p-2"
				>
					Prepare owned-fixture health test
				</button>
			</div>
			{plan?.kind === "static" && (
				<p className="text-xs">
					This approved plan executes only owned static DEX/ELF health fixtures;
					it never launches an APK or changes a device.
				</p>
			)}
			<select
				aria-label="Saved incident"
				value={current?.id ?? ""}
				className="w-full rounded border bg-background p-2"
				onChange={(e) => {
					if (e.target.value)
						void action(async () => {
							const at = epoch.current,
								c = await call<Case>("get_apk_incident", {
									id: e.target.value,
								});
							if (at === epoch.current) {
								setCurrent(c);
								setNotes("");
								setReproduced(false);
								setRegressed(false);
							}
						});
				}}
			>
				<option value="">Select saved incident</option>
				{cases.map((c) => (
					<option key={c.id} value={c.id}>
						{c.status} · {c.stage} · {c.id.slice(0, 8)}
					</option>
				))}
			</select>
			{current && (
				<div className="space-y-2 rounded border p-3">
					<p>
						{current.status} · {current.stage}
					</p>
					{current.controlUnavailable && (
						<p>
							Owner process unavailable to this view. Inspect saved evidence and
							device manually; status refresh will not replay work.
						</p>
					)}
					<p className="text-xs">
						{current.result ??
							"Accepted is not completed. Perform the approved manual reproduction during the observation window."}
					</p>
					{["accepted", "running"].includes(current.status) &&
						!current.controlUnavailable && (
							<button
								type="button"
								onClick={() =>
									void action(async () => {
										await call("cancel_analysis_task", {
											planId: current.planId,
										});
									})
								}
								className="underline"
							>
								Cancel capture (does not undo installation)
							</button>
						)}
					{current.status === "completed" && (
						<>
							<label className="flex gap-2 text-xs">
								<input
									type="checkbox"
									checked={reproduced}
									onChange={(e) => setReproduced(e.target.checked)}
								/>
								I completed the same reproduction
							</label>
							<label className="flex gap-2 text-xs">
								<input
									type="checkbox"
									checked={regressed}
									onChange={(e) => setRegressed(e.target.checked)}
								/>
								I checked the stated regressions
							</label>
							{field("Review notes", notes, setNotes)}
							<button
								type="button"
								disabled={busy || !notes}
								onClick={() =>
									void action(async () => {
										const at = epoch.current,
											c = await call<Case>("review_apk_incident", {
												input: {
													id: current.id,
													revision: current.revision,
													reproductionCompleted: reproduced,
													regressionPassed: regressed,
													notes,
												},
											});
										if (at === epoch.current) setCurrent(c);
									})
								}
								className="rounded border p-2"
							>
								Save operator review (not automatic proof)
							</button>
							<label className="block text-xs">
								Exact-build correlation JSON
								<textarea
									aria-label="Exact-build correlation JSON"
									className="w-full h-32 rounded border bg-background p-2 font-mono"
									value={correlation}
									onChange={(e) => setCorrelation(e.target.value)}
									placeholder={
										'{"kind":"java","apkSha256":"…","mapping":"mapping.txt","mappingSha256":"…","className":"a.b","method":"c"}'
									}
								/>
							</label>
							<p className="text-xs">
								Native: kind, apkSha256, module, moduleSha256, buildId, abi, pc
								(hex), loadBias (hex). No guessed symbols or universal
								deobfuscation.
							</p>
							<button
								type="button"
								disabled={busy || !correlation}
								onClick={() =>
									void action(async () => {
										const at = epoch.current,
											c = await call<Case>("correlate_apk_incident", {
												id: current.id,
												revision: current.revision,
												input: JSON.parse(correlation),
											});
										if (at === epoch.current) setCurrent(c);
									})
								}
								className="rounded border p-2"
							>
								Correlate evidence
							</button>
						</>
					)}
					{current.request.operation === "validate_apk_patch" &&
						!["accepted", "running"].includes(current.status) && (
							<button
								type="button"
								disabled={busy || !!plan}
								onClick={() => void action(() => prepare(true))}
								className="rounded border p-2"
							>
								Prepare separately approved rollback
							</button>
						)}
					<pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs">
						{JSON.stringify(current, null, 2)}
					</pre>
				</div>
			)}
			{readiness !== undefined && (
				<pre className="max-h-80 overflow-auto whitespace-pre-wrap text-xs">
					{JSON.stringify(readiness, null, 2)}
				</pre>
			)}
			{error && (
				<p role="alert" className="text-destructive">
					{error}
				</p>
			)}
			{busy && <output>Working…</output>}
		</section>
	);
}
