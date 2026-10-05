"use client";
import { useCallback, useEffect, useId, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { desktopClient } from "@/lib/desktop-client";
type Case = {
	jobCurrentStatuses?: Record<string, string>;
	id: string;
	title: string;
	revision: number;
	state: string;
	summary: string;
	questions: string[];
	evidence: Array<{
		id: string;
		engine?: string;
		provenance: string;
		sourceArtifactSha256?: string;
		methods?: Array<Record<string, unknown>>;
		functions?: Array<Record<string, unknown>>;
		outputPaths?: string[];
		metadataCoverage?: unknown;
		relationships?: Array<Record<string, unknown>>;
		registrations?: Array<Record<string, unknown>>;
		checks?: unknown;
		engineExecution?: string;
	}>;
	transformations: Array<Record<string, unknown>>;
	jobs: Array<{ id: string; status: string }>;
	parentId?: string;
};
export function InvestigationWorkspace({
	cwd,
	environmentId,
	onSelect,
	selectedId,
}: {
	cwd: string;
	environmentId: string;
	onSelect: (id: string) => void;
	selectedId: string;
}) {
	const prefix = useId(),
		[cases, setCases] = useState<Case[]>([]),
		[selected, setSelected] = useState<Case | null>(null),
		[title, setTitle] = useState("Android investigation"),
		[summary, setSummary] = useState(""),
		[questions, setQuestions] = useState(""),
		[state, setState] = useState("active"),
		[error, setError] = useState(""),
		[busy, setBusy] = useState(false);
	const context = useMemo(() => ({ cwd, environmentId }), [cwd, environmentId]);
	const refresh = useCallback(async () => {
		setCases(await desktopClient.invoke("list_investigations", context));
	}, [context]);
	async function action(run: () => Promise<void>) {
		setBusy(true);
		setError("");
		try {
			await run();
		} catch (e) {
			setError(
				e instanceof Error ? e.message : "Investigation operation failed",
			);
		} finally {
			setBusy(false);
		}
	}
	const pick = useCallback(
		(c: Case) => {
			setSelected(c);
			setSummary(c.summary);
			setQuestions(c.questions.join("\n"));
			setState(c.state);
			onSelect(c.id);
		},
		[onSelect],
	);
	useEffect(() => {
		setSelected(null);
		if (selectedId)
			void desktopClient
				.invoke<Case>("get_investigation", { ...context, id: selectedId })
				.then(pick)
				.catch(() => setError("Selected case unavailable in this workspace."));
		void refresh().catch(() =>
			setError("Investigation store unavailable; no tasks were executed."),
		);
	}, [context, refresh, pick, selectedId]);
	return (
		<section className="space-y-4">
			<h3 className="text-base font-semibold">
				Durable investigation workspace
			</h3>
			<p className="text-sm text-muted-foreground">
				Device-local metadata, checkpoints and evidence references are separate
				from chat. Forks preserve previous evidence; reopening a case never
				replays tools. Captured plaintext needs protected local storage.
			</p>
			{error && (
				<p role="alert" className="text-destructive">
					{error}
				</p>
			)}
			<label htmlFor={`${prefix}-title`}>
				New case or fork title
				<Input
					id={`${prefix}-title`}
					value={title}
					onChange={(e) => setTitle(e.target.value)}
				/>
			</label>
			<Button
				disabled={busy || !title.trim()}
				onClick={() =>
					void action(async () => {
						const c = await desktopClient.invoke<Case>("mutate_investigation", {
							...context,
							input: {
								action: "create",
								title: title.trim(),
								confirmWrite: true,
							},
						});
						pick(c);
						await refresh();
					})
				}
			>
				Create local investigation
			</Button>
			<div className="flex flex-wrap gap-2">
				{cases.map((c) => (
					<Button
						key={c.id}
						variant={c.id === selected?.id ? "default" : "outline"}
						disabled={busy}
						onClick={() =>
							void action(async () =>
								pick(
									await desktopClient.invoke<Case>("get_investigation", {
										...context,
										id: c.id,
									}),
								),
							)
						}
					>
						{c.title} · {c.state}
					</Button>
				))}
			</div>
			{selected && (
				<>
					<p className="text-xs">
						Case {selected.id} · revision {selected.revision}
						{selected.parentId ? ` · fork of ${selected.parentId}` : ""}
					</p>
					<label htmlFor={`${prefix}-summary`}>
						Checkpoint summary
						<Textarea
							id={`${prefix}-summary`}
							value={summary}
							onChange={(e) => setSummary(e.target.value)}
						/>
					</label>
					<label htmlFor={`${prefix}-questions`}>
						Unresolved questions, one per line
						<Textarea
							id={`${prefix}-questions`}
							value={questions}
							onChange={(e) => setQuestions(e.target.value)}
						/>
					</label>
					<label htmlFor={`${prefix}-state`}>
						Investigation state
						<select
							id={`${prefix}-state`}
							value={state}
							onChange={(e) => setState(e.target.value)}
						>
							{[
								"active",
								"paused",
								"authentication-required",
								"worker-disconnected",
								"closed",
							].map((s) => (
								<option key={s} value={s}>
									{s}
								</option>
							))}
						</select>
					</label>
					<div className="flex gap-2">
						<Button
							disabled={busy}
							onClick={() =>
								void action(async () => {
									pick(
										await desktopClient.invoke<Case>("mutate_investigation", {
											...context,
											input: {
												action: "checkpoint",
												id: selected.id,
												revision: selected.revision,
												summary,
												questions: questions.split("\n").filter(Boolean),
												state,
												confirmWrite: true,
											},
										}),
									);
									await refresh();
								})
							}
						>
							Save checkpoint
						</Button>
						<Button
							variant="outline"
							disabled={busy}
							onClick={() =>
								void action(async () => {
									pick(
										await desktopClient.invoke<Case>("mutate_investigation", {
											...context,
											input: {
												action: "fork",
												id: selected.id,
												revision: selected.revision,
												title: title.trim(),
												confirmWrite: true,
											},
										}),
									);
									await refresh();
								})
							}
						>
							Fork without replay
						</Button>
						<Button
							variant="outline"
							disabled={busy}
							onClick={() =>
								void action(async () => {
									pick(
										await desktopClient.invoke<Case>("get_investigation", {
											...context,
											id: selected.id,
										}),
									);
									await refresh();
								})
							}
						>
							Reload evidence
						</Button>
					</div>
					<h4 className="font-semibold">Cross-language evidence</h4>
					<pre className="overflow-auto rounded border p-3 text-xs">
						{JSON.stringify(correlateEvidence(selected.evidence), null, 2)}
					</pre>
					<p className="text-xs text-muted-foreground">
						Static JNI name matches remain candidates. Signed worker
						registrations report observations, not hardware-attested truth.
						Missing native module hashes remain unresolved; absolute addresses
						are not stable identities.
					</p>
					{selected.evidence.map((e) => (
						<article
							key={e.id}
							className="rounded border border-border p-3 text-xs"
						>
							<p>
								{e.engine ?? "engine unspecified"} · {e.provenance} ·{" "}
								{e.engineExecution ?? "execution validation not established"}
							</p>
							<p className="break-all">
								Original artifact SHA256:{" "}
								{e.sourceArtifactSha256 ?? "not applicable"}
							</p>
							{e.outputPaths?.map((path) => (
								<p key={path} className="break-all">
									Evidence file: {path}
								</p>
							))}
							{e.metadataCoverage !== undefined && (
								<pre className="overflow-auto">
									{JSON.stringify(e.metadataCoverage, null, 2)}
								</pre>
							)}
							{e.checks !== undefined && (
								<pre className="overflow-auto">
									{JSON.stringify(e.checks, null, 2)}
								</pre>
							)}
							{[
								...(e.methods ?? []),
								...(e.functions ?? []),
								...(e.relationships ?? []),
								...(e.registrations ?? []),
							].map((row, i) => (
								<pre key={`${e.id}-${i}`} className="overflow-auto">
									{JSON.stringify(row, null, 2)}
								</pre>
							))}
						</article>
					))}
					<h4 className="font-semibold">
						Targeted transformations and proof boundaries
					</h4>
					<p className="text-xs text-muted-foreground">
						Run expression comparison, bounded IR passes or CFG analysis through
						Analyze after selecting this case. Approved results are linked here.
						No binary is rewritten; originals remain intact. Expression
						equivalence does not prove a whole method or binary equivalent.
					</p>
					{selected.transformations.map((t, i) => (
						<pre
							key={String(t.id ?? i)}
							className="overflow-auto rounded border p-3 text-xs"
						>
							{JSON.stringify(t, null, 2)}
						</pre>
					))}
					<h4 className="font-semibold">
						Bound jobs — never automatically replayed
					</h4>
					{selected.jobs.map((j) => (
						<p key={j.id} className="text-xs">
							{j.id} ·{" "}
							{selected.jobCurrentStatuses?.[j.id] ??
								`${j.status} (last recorded; refresh task ledger)`}
						</p>
					))}
				</>
			)}
		</section>
	);
}

export function correlateEvidence(evidence: Case["evidence"]) {
	const methods = evidence.flatMap((e) =>
		(e.methods ?? []).map((method) => ({
			method,
			sourceArtifactSha256: e.sourceArtifactSha256,
		})),
	);
	return evidence.flatMap((e) =>
		(e.registrations ?? []).map((registration) => {
			const matches = methods.filter(
				({ method }) =>
					method.classDescriptor === registration.classDescriptor &&
					method.name === registration.name &&
					method.descriptor === registration.descriptor,
			);
			return {
				registration,
				observation: e.provenance,
				staticMatches: matches,
				correlation:
					matches.length === 1
						? "descriptor-match-not-proven-runtime-class-identity"
						: matches.length
							? "ambiguous-static-descriptor-matches"
							: "no-static-descriptor-match",
				nativeIdentity:
					registration.moduleSha256 && registration.relativeAddress
						? "disk-hash-and-module-relative-address-not-loaded-image-proof"
						: "unresolved-module-hash",
			};
		}),
	);
}
