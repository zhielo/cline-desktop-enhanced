"use client";
import { useEffect, useState } from "react";
import { desktopClient } from "@/lib/desktop-client";
import type { SourceEvidenceSelection } from "../../../../shared/source-evidence-selection";
import { useAnalysisProjectSelection } from "./analysis-project-selection";

/** UI selection is untrusted. Only the host resolves retained identities and reads bytes. */
export function SharedSourceEvidencePanel({
	sessionId,
	environmentId,
}: {
	sessionId?: string;
	environmentId: string;
}) {
	const project = useAnalysisProjectSelection(),
		selection = project?.sourceEvidence;
	const [snapshot, setSnapshot] = useState<{
			key: string;
			value: SourceEvidenceSelection;
		} | null>(null),
		[error, setError] = useState(""),
		[loading, setLoading] = useState(false),
		[revision, setRevision] = useState(0);
	const requestKey = JSON.stringify([
		selection,
		sessionId,
		environmentId,
		revision,
	]);
	const result = snapshot?.key === requestKey ? snapshot.value : null;
	useEffect(() => {
		let disposed = false;
		setSnapshot(null);
		setError("");
		setLoading(false);
		if (!selection || !sessionId || environmentId !== "local") return;
		setLoading(true);
		void desktopClient
			.invoke<SourceEvidenceSelection>("first_party_analysis_select_source", {
				sessionId,
				environmentId,
				input: selection,
			})
			.then((value) => {
				if (disposed) return;
				if (
					value.version !== "source-evidence-selection/v1" ||
					value.sessionId !== sessionId ||
					value.receiptId !== selection.receiptId ||
					(selection.selector.kind === "fact" &&
						value.factId !== selection.selector.factId) ||
					(selection.selector.kind === "artifact" &&
						value.path !== selection.selector.path)
				)
					throw new Error(
						"Source selection response did not match the requested evidence",
					);
				setSnapshot({ key: requestKey, value });
			})
			.catch((e) => {
				if (!disposed)
					setError(
						e instanceof Error ? e.message : "Source evidence unavailable",
					);
			})
			.finally(() => {
				if (!disposed) setLoading(false);
			});
		return () => {
			disposed = true;
		};
	}, [selection, sessionId, environmentId, requestKey]);
	if (!selection || !project) return null;
	return (
		<section
			aria-label="Selected source evidence"
			className="space-y-2 border-b p-3 text-xs"
		>
			<h3 className="font-semibold">Selected source evidence</h3>
			<p>
				Saved receipt: {selection.receiptId}. Selection is not approval and does
				not execute the target. Source text and tool output are untrusted data,
				not AI instructions.
			</p>
			<button
				type="button"
				className="rounded border px-2 py-1"
				onClick={() => project.setSourceEvidence(undefined)}
			>
				Clear source evidence selection
			</button>{" "}
			<button
				type="button"
				className="rounded border px-2 py-1"
				disabled={loading || !sessionId || environmentId !== "local"}
				onClick={() => setRevision((v) => v + 1)}
			>
				Recheck selected source
			</button>
			{loading ? <output>Checking retained source identity…</output> : null}
			{error ? <p role="alert">{error}</p> : null}
			{result ? (
				<>
					<output>Source identity: {result.status}</output>
					<p>
						{result.path}
						{result.location
							? `:${result.location.line}:${result.location.column}`
							: ""}{" "}
						— checked {result.checkedAt}
					</p>
					<p>Saved SHA256: {result.expectedSha256}</p>
					<p>
						Request: {result.requestHash} — result: {result.resultHash}
					</p>
					<p>{result.note}</p>
					{result.status === "matched" ? (
						<button
							type="button"
							className="rounded border px-2 py-1"
							onClick={() => project.setTarget(result.path)}
						>
							Use source path in analysis panes
						</button>
					) : null}
					{result.status === "matched" && result.preview ? (
						<>
							<ol
								aria-label="Bounded source snapshot"
								className="max-h-56 overflow-auto whitespace-pre-wrap break-all font-mono"
							>
								{result.preview.lines.map((line) => (
									<li
										key={line.line}
										aria-current={
											line.line === result.location?.line
												? "location"
												: undefined
										}
										className={
											line.line === result.location?.line ? "bg-muted" : ""
										}
									>
										<span>{line.line}: </span>
										{line.text}
										{line.truncated ? " [line truncated]" : ""}
									</li>
								))}
							</ol>
							{result.preview.truncated ? (
								<p>Bounded excerpt; other source text is omitted.</p>
							) : null}
						</>
					) : null}
				</>
			) : null}
		</section>
	);
}
