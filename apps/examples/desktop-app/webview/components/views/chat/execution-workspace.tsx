"use client";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { desktopClient } from "@/lib/desktop-client";

type Plan = {
	id: string;
	requestHash: string;
	requirements: string[];
	request: Record<string, unknown>;
};
type Receipt = {
	id: string;
	status: string;
	controlUnavailable?: boolean;
	jobs?: { id: string; status: string }[];
};
const initial = () =>
	JSON.stringify(
		{
			operation: "execution_pipeline",
			operation_id: crypto.randomUUID(),
			title: "Reviewed host task",
			trusted_host_work: true,
			parallel: 1,
			archive_logs: false,
			stages: [
				{
					id: "inspect",
					backend: "shell",
					depends_on: [],
					timeout_ms: 30000,
					request: {
						executable: "git",
						args: ["status", "--short"],
						interactive: false,
						replay_safety: "inspection-declared",
						native_job: false,
					},
				},
			],
		},
		null,
		2,
	);
export function ExecutionWorkspace({
	cwd,
	environmentId,
}: {
	cwd?: string;
	environmentId?: string;
}) {
	const scope = useMemo(() => ({ cwd, environmentId }), [cwd, environmentId]),
		epoch = useRef(0);
	const [draft, setDraft] = useState(initial),
		[plan, setPlan] = useState<Plan | null>(null),
		[accepted, setAccepted] = useState<string[]>([]),
		[receipt, setReceipt] = useState<Receipt | null>(null),
		[rows, setRows] = useState<{ id: string; title: string; status: string }[]>(
			[],
		),
		[output, setOutput] = useState<unknown>(),
		[error, setError] = useState(""),
		[busy, setBusy] = useState(false),
		[target, setTarget] = useState(""),
		[pkg, setPkg] = useState(""),
		[candidate, setCandidate] = useState(""),
		[reproduction, setReproduction] = useState(""),
		[stdin, setStdin] = useState("");
	const call = useCallback(
		<T,>(command: string, args: Record<string, unknown> = {}) =>
			desktopClient.invoke<T>(command, { ...scope, ...args }),
		[scope],
	);
	const refresh = useCallback(async () => {
		const at = epoch.current;
		try {
			const items = await call<typeof rows>("list_execution_receipts");
			if (at === epoch.current) setRows(items);
		} catch (e) {
			if (at === epoch.current) setError(String(e));
		}
	}, [call]);
	useEffect(() => {
		epoch.current++;
		setDraft(initial());
		setPlan(null);
		setAccepted([]);
		setReceipt(null);
		setOutput(undefined);
		setRows([]);
		setError("");
		setBusy(false);
		setTarget("");
		setPkg("");
		setCandidate("");
		setReproduction("");
		setStdin("");
		void refresh();
		return () => {
			epoch.current++;
		};
	}, [refresh]);
	useEffect(() => {
		if (
			!receipt ||
			receipt.controlUnavailable ||
			!["accepted", "starting", "running"].includes(receipt.status)
		)
			return;
		const at = epoch.current,
			id = receipt.id;
		const timer = setInterval(() => {
			void call<Receipt>("get_execution_receipt", { id })
				.then((r) => {
					if (at === epoch.current) {
						setReceipt(r);
						setOutput(r);
					}
				})
				.catch((e) => {
					if (at === epoch.current) setError(String(e));
				});
		}, 1500);
		return () => clearInterval(timer);
	}, [call, receipt]);
	const action = async (run: (at: number) => Promise<void>) => {
		const at = epoch.current;
		setBusy(true);
		setError("");
		try {
			await run(at);
		} catch (e) {
			if (at === epoch.current) setError(String(e));
		} finally {
			if (at === epoch.current) {
				setBusy(false);
				void refresh();
			}
		}
	};
	const edit = (text: string) => {
		epoch.current++;
		setDraft(text);
		setPlan(null);
		setAccepted([]);
		setBusy(false);
	};
	const button = (
		label: string,
		run: (at: number) => Promise<void>,
		disabled = false,
	) => (
		<button
			type="button"
			className="rounded border px-2 py-1"
			disabled={busy || disabled}
			onClick={() => void action(run)}
		>
			{label}
		</button>
	);
	return (
		<section className="space-y-3 p-3 text-sm">
			<h2 className="font-semibold">Execution and evidence lab</h2>
			<p>
				Reviewed host commands only—not an OS sandbox. Never run unknown
				APK/native samples here. Approvals bind the exact staged request;
				refreshing or timing out never replays it.
			</p>
			{environmentId && (
				<output>
					This lab rejects SSH workspaces. Select a local workspace.
				</output>
			)}
			<label className="block">
				Staged task JSON
				<textarea
					aria-label="Staged task JSON"
					className="block w-full h-60 rounded border bg-transparent p-2 font-mono text-xs"
					value={draft}
					disabled={busy}
					onChange={(e) => edit(e.target.value)}
				/>
			</label>
			{button("Prepare exact task", async (at) => {
				const p = await call<Plan>("prepare_execution_pipeline", {
					input: JSON.parse(draft),
				});
				if (at === epoch.current) {
					setPlan(p);
					setAccepted([]);
					setOutput(p);
				}
			})}
			{plan && (
				<div className="space-y-2">
					<p>
						Review normalized request and each requirement before approving:
					</p>
					<pre className="max-h-52 overflow-auto whitespace-pre-wrap text-xs">
						{JSON.stringify(plan.request, null, 2)}
					</pre>
					{plan.requirements.map((item) => (
						<label className="block" key={item}>
							<input
								type="checkbox"
								checked={accepted.includes(item)}
								onChange={(e) =>
									setAccepted((v) =>
										e.target.checked
											? [...v, item]
											: v.filter((x) => x !== item),
									)
								}
							/>
							{item}
						</label>
					))}
					{button(
						"Approve and start once",
						async (at) => {
							const approval = await call<{ executionToken: string }>(
								"approve_analysis_task",
								{
									planId: plan.id,
									requestHash: plan.requestHash,
									requirements: accepted,
								},
							);
							if (at !== epoch.current) return;
							const result = await call<{ id: string }>(
								"start_execution_pipeline",
								{ planId: plan.id, executionToken: approval.executionToken },
							);
							if (at !== epoch.current) return;
							setPlan(null);
							const r = await call<Receipt>("get_execution_receipt", {
								id: result.id,
							});
							if (at === epoch.current) {
								setReceipt(r);
								setOutput(r);
							}
						},
						plan.requirements.some((x) => !accepted.includes(x)),
					)}
				</div>
			)}
			<h3 className="font-semibold">Persistent receipts</h3>
			{button("Refresh receipts", async () => refresh())}
			{rows.map((row) => (
				<div key={row.id}>
					{button(`${row.title}: ${row.status}`, async (at) => {
						const r = await call<Receipt>("get_execution_receipt", {
							id: row.id,
						});
						if (at === epoch.current) {
							setReceipt(r);
							setOutput(r);
						}
					})}
				</div>
			))}
			{receipt && (
				<div>
					<p>
						{receipt.status}
						{receipt.controlUnavailable
							? " — owner lost, exit unproven; no replay"
							: ""}
					</p>
					{button("Reconcile without replay", async (at) => {
						const result = await call("reconcile_execution_receipt", {
							id: receipt.id,
						});
						if (at === epoch.current) setOutput(result);
					})}
					{button(
						"Request cancellation",
						async (at) => {
							const result = await call("cancel_execution_receipt", {
								id: receipt.id,
							});
							if (at === epoch.current) setOutput(result);
						},
						receipt.controlUnavailable ||
							!["accepted", "starting", "running"].includes(receipt.status),
					)}
					{receipt.jobs
						?.filter((j) => j.status === "running")
						.map((j) => (
							<div key={j.id}>
								<label>
									Input for {j.id}
									<input
										aria-label={`Input for ${j.id}`}
										className="border bg-transparent"
										value={stdin}
										onChange={(e) => setStdin(e.target.value)}
									/>
								</label>
								{button(
									"Send stdin (not retained)",
									async (at) => {
										await call("execution_stdin", {
											id: receipt.id,
											stageId: j.id,
											text: `${stdin}\n`,
										});
										if (at === epoch.current) setStdin("");
									},
									receipt.controlUnavailable,
								)}
							</div>
						))}
				</div>
			)}
			<h3 className="font-semibold">
				Evidence planner / APK debug import / patch review
			</h3>
			<label className="block">
				Target or debug report path
				<input
					aria-label="Target or debug report path"
					className="block w-full border bg-transparent"
					value={target}
					onChange={(e) => setTarget(e.target.value)}
				/>
			</label>
			{button("Plan evidence analysis (no execution)", async (at) => {
				const result = await call<{ stages: { reason?: string }[] }>(
					"plan_evidence_analysis",
					{ input: { target, engine: "auto" } },
				);
				if (at === epoch.current) {
					const stages = result.stages.map(({ reason, ...s }) => s);
					edit(
						JSON.stringify(
							{
								operation: "execution_pipeline",
								operation_id: crypto.randomUUID(),
								title: "Evidence-first analysis",
								trusted_host_work: true,
								parallel: 1,
								archive_logs: false,
								stages,
							},
							null,
							2,
						),
					);
					setOutput(result);
				}
			})}
			<label className="block">
				Package ID
				<input
					aria-label="Package ID"
					className="block w-full border bg-transparent"
					value={pkg}
					onChange={(e) => setPkg(e.target.value)}
				/>
			</label>
			{button("Import ANR / tombstone / process death report", async (at) => {
				const result = await call("import_android_debug_evidence", {
					input: { file: target, package: pkg },
				});
				if (at === epoch.current) setOutput(result);
			})}
			<label className="block">
				Candidate artifact
				<input
					aria-label="Candidate artifact"
					className="block w-full border bg-transparent"
					value={candidate}
					onChange={(e) => setCandidate(e.target.value)}
				/>
			</label>
			<label className="block">
				Reproduction and regression criterion
				<input
					aria-label="Reproduction and regression criterion"
					className="block w-full border bg-transparent"
					value={reproduction}
					onChange={(e) => setReproduction(e.target.value)}
				/>
			</label>
			{button("Review hash-bound patch (no install)", async (at) => {
				const result = await call("review_patch_artifacts", {
					input: {
						original: target,
						candidate,
						reproduction,
						regressionChecklist: [reproduction],
					},
				});
				if (at === epoch.current) setOutput(result);
			})}
			<p>
				Installation, reproduction and rollback remain separate approvals in APK
				incidents. Imported reports are unverified observations—not proof of a
				deadlock or symbol match. IDA/Ghidra licenses and device readiness are
				never inferred from installation.
			</p>
			{error && (
				<p role="alert" className="text-red-400">
					{error}
				</p>
			)}
			{output !== undefined && (
				<pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs">
					{JSON.stringify(output, null, 2)}
				</pre>
			)}
		</section>
	);
}
