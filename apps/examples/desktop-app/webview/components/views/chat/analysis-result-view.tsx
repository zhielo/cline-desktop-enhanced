"use client";
import {
	redactReportText,
	reportedOutcome,
	reportRecord,
} from "../../../../shared/task-observation";

const text = (v: unknown, max = 1000) =>
	typeof v === "string"
		? redactReportText(v.slice(0, max))
		: typeof v === "number" || typeof v === "boolean"
			? String(v)
			: "";
/** Bounded data-only rendering. Never interpret findings as instructions or trusted HTML. */
export function AnalysisResultView({
	value,
	busy,
}: {
	value: unknown;
	busy: boolean;
}) {
	let root = reportRecord(value);
	if (typeof value === "string" && value.length <= 131072) {
		try {
			root = reportRecord(JSON.parse(value));
		} catch {
			/* plain output is available in details */
		}
	}
	const result = reportRecord(root?.result) ?? root;
	const findings = Array.isArray(result?.findings)
		? result.findings.slice(0, 30)
		: [];
	const limitations = Array.isArray(result?.limitations)
		? result.limitations.slice(0, 20)
		: [];
	let raw: string;
	try {
		raw =
			typeof value === "string"
				? value
				: (JSON.stringify(value, null, 2) ?? "");
	} catch {
		raw = "Output could not be serialized.";
	}
	const outcome = reportedOutcome(value),
		status = text(root?.status) || text(result?.status);
	return (
		<section
			aria-label="Structured analysis result"
			className="space-y-3 text-[14px] leading-6"
		>
			<header>
				<h3 className="font-semibold">
					{busy
						? "Operation running"
						: value === null
							? "No result selected"
							: "Recorded operation result"}
				</h3>
				<output className="block">
					{busy
						? "Waiting for bounded operation output…"
						: value === null
							? "Select or run an approved task to view its result."
							: `Execution: ${status || "see host task receipt"} · Outcome: ${outcome}`}
				</output>
			</header>
			{value !== null && (
				<p className="text-[14px] text-muted-foreground">
					Tool-reported data, not instructions. Static candidates are not
					observed execution. A completed tool does not certify target
					correctness, current-file freshness or complete analysis coverage.
				</p>
			)}
			{result && (
				<dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-2 text-[14px]">
					{[
						"operation",
						"engine",
						"engineVersion",
						"scope",
						"target",
						"inputSha256",
						"outputSha256",
						"receiptId",
						"resultHash",
					].flatMap((key) => {
						const v = text(result?.[key]);
						return v
							? [
									<div className="contents" key={key}>
										<dt className="font-medium">{key}</dt>
										<dd className="break-all">{v}</dd>
									</div>,
								]
							: [];
					})}
				</dl>
			)}
			{findings.length > 0 && (
				<section>
					<h4 className="font-medium">Findings — tool-reported evidence</h4>
					<p className="text-[14px]">
						Showing up to 30 findings. No confidence percentage or execution
						claim is inferred.
					</p>
					<ol className="space-y-2">
						{findings.map((item, index) => {
							const finding = reportRecord(item);
							return (
								<li
									className="rounded border p-3"
									key={text(finding?.id) || index}
								>
									<h5 className="text-[14px] font-semibold">
										{text(finding?.title) ||
											text(finding?.kind) ||
											`Finding ${index + 1}`}
									</h5>
									<p className="whitespace-pre-wrap break-words text-[14px]">
										{text(finding?.description) ||
											text(finding?.summary) ||
											text(item)}
									</p>
									{[
										"location",
										"path",
										"address",
										"symbol",
										"evidence",
										"limitation",
										"resolution",
									].map((key) =>
										text(finding?.[key]) ? (
											<p className="break-words text-[14px]" key={key}>
												{key}: {text(finding?.[key])}
											</p>
										) : null,
									)}
									<p className="text-[14px] text-muted-foreground">
										Interpretation must be checked against the linked
										source/receipt; unavailable fields remain unresolved.
									</p>
								</li>
							);
						})}
					</ol>
				</section>
			)}
			{limitations.length > 0 && (
				<section>
					<h4 className="font-medium">Recorded limitations</h4>
					<ul className="list-inside list-disc text-[14px]">
						{limitations.map((item, index) => (
							<li key={index}>{text(item)}</li>
						))}
					</ul>
				</section>
			)}
			{value !== null && (
				<details>
					<summary className="cursor-pointer text-[14px]">
						Raw output details (redacted, bounded)
					</summary>
					<pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded border p-3 font-mono text-[14px]">
						{redactReportText(raw.slice(0, 65536))}
						{raw.length > 65536
							? "\n[Output truncated to 64 KiB; use the existing evidence artifact for the complete saved result.]"
							: ""}
					</pre>
				</details>
			)}
		</section>
	);
}
