"use client";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { desktopClient } from "@/lib/desktop-client";
export function RuntimeJniWorkspace({
	cwd,
	environmentId,
}: {
	cwd?: string;
	environmentId?: string;
}) {
	const scope = useMemo(() => ({ cwd, environmentId }), [cwd, environmentId]),
		epoch = useRef(0),
		[draft, setDraft] = useState(
			'{"planId":"","classDescriptor":"","name":"","descriptor":"","confirmRelativeAddressIsElfVA":false}',
		),
		[output, setOutput] = useState<unknown>(),
		[error, setError] = useState(""),
		[busy, setBusy] = useState(false),
		[plans, setPlans] = useState<
			{ id: string; kind: string; operation: string; status: string }[]
		>([]);
	const call = useCallback(
		<T,>(command: string, args: Record<string, unknown> = {}) =>
			desktopClient.invoke<T>(command, { ...scope, ...args }),
		[scope],
	);
	const refresh = useCallback(async () => {
		const at = epoch.current;
		try {
			const rows = await call<typeof plans>("list_analysis_tasks");
			if (at === epoch.current)
				setPlans(
					rows.filter(
						(p) =>
							p.kind === "dynamic" &&
							p.operation === "android_capture" &&
							p.status === "completed",
					),
				);
		} catch (e) {
			if (at === epoch.current) setError(String(e));
		}
	}, [call]);
	useEffect(() => {
		epoch.current++;
		setOutput(undefined);
		setError("");
		setBusy(false);
		setPlans([]);
		setDraft(
			'{"planId":"","classDescriptor":"","name":"","descriptor":"","confirmRelativeAddressIsElfVA":false}',
		);
		void refresh();
		return () => {
			epoch.current++;
		};
	}, [refresh]);
	return (
		<section className="space-y-2 rounded border p-3">
			<h3 className="font-semibold">Signed live JNI evidence</h3>
			<p>
				Query an already completed approved Android capture. This does not
				attach, execute, install or replay anything. Imported JSON is rejected.
			</p>
			<button
				type="button"
				className="rounded border p-1"
				onClick={() => void refresh()}
			>
				Refresh completed JNI captures
			</button>
			<label className="block">
				Completed capture
				<select
					aria-label="Completed JNI capture"
					className="w-full border bg-transparent"
					defaultValue=""
					onChange={(e) => {
						epoch.current++;
						setBusy(false);
						let value: Record<string, unknown> = {};
						try {
							const parsed = JSON.parse(draft);
							if (
								parsed &&
								typeof parsed === "object" &&
								!Array.isArray(parsed)
							)
								value = parsed;
						} catch {
							/* Selecting a plan restores an editable object; never execute malformed JSON. */
						}
						value.planId = e.target.value;
						setDraft(JSON.stringify(value, null, 2));
						setOutput(undefined);
					}}
				>
					<option value="">Select capture</option>
					{plans.map((p) => (
						<option key={p.id} value={p.id}>
							{p.id}
						</option>
					))}
				</select>
			</label>
			<label className="block">
				Exact JNI query JSON
				<textarea
					aria-label="Exact JNI query JSON"
					className="h-36 w-full rounded border bg-transparent p-2 font-mono text-xs"
					value={draft}
					disabled={busy}
					onChange={(e) => {
						epoch.current++;
						setDraft(e.target.value);
						setOutput(undefined);
					}}
				/>
			</label>
			<button
				type="button"
				className="rounded border p-1"
				disabled={busy}
				onClick={() => {
					const at = epoch.current;
					setBusy(true);
					setError("");
					void Promise.resolve()
						.then(() => call("query_runtime_jni", { input: JSON.parse(draft) }))
						.then((r) => {
							if (at === epoch.current) setOutput(r);
						})
						.catch((e) => {
							if (at === epoch.current) setError(String(e));
						})
						.finally(() => {
							if (at === epoch.current) setBusy(false);
						});
				}}
			>
				Verify and query signed registrations
			</button>
			<p>
				Multiple process/loader observations remain ambiguous. Disk hashes do
				not attest loaded memory. Relative offsets are not automatically ELF
				addresses; any exact-symbol candidate requires your explicit coordinate
				review.
			</p>
			{error && <p role="alert">{error}</p>}
			{output !== undefined && (
				<pre className="max-h-96 overflow-auto whitespace-pre-wrap text-xs">
					{JSON.stringify(output, null, 2)}
				</pre>
			)}
		</section>
	);
}
