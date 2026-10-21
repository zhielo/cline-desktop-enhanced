"use client";
import { useState } from "react";
import { PreviewScrollRegion } from "@/components/ui/preview-scroll-region";
import { desktopClient } from "@/lib/desktop-client";

type Page = { nextOffset?: number | null; [key: string]: unknown };
/** Explicit, read-only workflows over previously retained evidence. No target/provider launch. */
export function ApplicationEvidenceWorkflows({
	sessionId,
	environmentId,
	receiptId,
	receipts,
}: {
	sessionId: string;
	environmentId: string;
	receiptId: string;
	receipts: { id: string; target: string }[];
}) {
	const [kind, setKind] = useState("application-trace");
	const [seedKind, setSeedKind] = useState("channel"),
		[seed, setSeed] = useState("");
	const [direction, setDirection] = useState("both");
	const [other, setOther] = useState("");
	const [leftModule, setLeftModule] = useState(""),
		[rightModule, setRightModule] = useState("");
	const [leftExport, setLeftExport] = useState(""),
		[rightExport, setRightExport] = useState("");
	const [page, setPage] = useState<Page | null>(null),
		[error, setError] = useState("");
	const [busy, setBusy] = useState(false),
		[lastQuery, setLastQuery] = useState<Record<string, unknown> | null>(null);
	async function query(input: Record<string, unknown>) {
		setBusy(true);
		setError("");
		try {
			const result = await desktopClient.invoke<Page>(
				"first_party_analysis_evidence",
				{ sessionId, environmentId, query: input },
			);
			setPage(result);
			setLastQuery(input);
		} catch (e) {
			setError(
				e instanceof Error ? e.message : "Application evidence query failed",
			);
			setPage(null);
		} finally {
			setBusy(false);
		}
	}
	function run() {
		const q: Record<string, unknown> = {
			receiptId,
			view: kind,
			offset: 0,
			limit: 20,
		};
		if (kind === "application-trace")
			q.applicationTrace = {
				seed: {
					kind: seedKind,
					value: seed,
					match: "exact",
					case_sensitive: false,
				},
				direction,
			};
		else q.compareReceiptId = other;
		if (kind === "application-exports")
			q.exportSelectors = {
				left: { modulePath: leftModule, exportName: leftExport },
				right: { modulePath: rightModule, exportName: rightExport },
			};
		void query(q);
	}
	return (
		<details
			aria-label="Saved application workflows"
			className="space-y-2 rounded border p-2 text-xs"
		>
			<summary>Saved application feature tracing and comparisons</summary>
			<p>
				Reads retained, session-owned graphs only. No target execution or
				provider launch. Admitted-source coverage remains partial.
			</p>
			<label>
				Application workflow
				<select
					aria-label="Application workflow"
					disabled={busy}
					value={kind}
					onChange={(e) => {
						setKind(e.target.value);
						setPage(null);
						setLastQuery(null);
					}}
				>
					<option value="application-trace">Feature trace</option>
					<option value="application-comparison">Application versions</option>
					<option value="application-exports">Export return shapes</option>
					<option value="application-source-bundle">
						Reference sources to bundle
					</option>
				</select>
			</label>
			{kind === "application-trace" ? (
				<div className="flex flex-wrap gap-2">
					<label>
						Seed kind
						<select
							aria-label="Application seed kind"
							disabled={busy}
							value={seedKind}
							onChange={(e) => setSeedKind(e.target.value)}
						>
							{[
								"channel",
								"module",
								"string",
								"api",
								"route",
								"native-export",
								"node-id",
							].map((k) => (
								<option key={k}>{k}</option>
							))}
						</select>
					</label>
					<input
						aria-label="Application feature seed"
						disabled={busy}
						value={seed}
						onChange={(e) => setSeed(e.target.value)}
						placeholder="Exact retained literal"
					/>
					<label>
						Direction
						<select
							aria-label="Application trace direction"
							disabled={busy}
							value={direction}
							onChange={(e) => setDirection(e.target.value)}
						>
							{["both", "incoming", "outgoing"].map((k) => (
								<option key={k}>{k}</option>
							))}
						</select>
					</label>
				</div>
			) : (
				<label>
					Comparison receipt
					<select
						aria-label="Application comparison receipt"
						disabled={busy}
						value={other}
						onChange={(e) => setOther(e.target.value)}
					>
						<option value="">Select retained receipt</option>
						{receipts
							.filter(
								(r) =>
									kind === "application-source-bundle" || r.id !== receiptId,
							)
							.map((r) => (
								<option key={r.id} value={r.id}>
									{r.target} — {r.id}
								</option>
							))}
					</select>
				</label>
			)}
			{kind === "application-exports" && (
				<div className="grid grid-cols-2 gap-2">
					<input
						aria-label="Left export module"
						disabled={busy}
						value={leftModule}
						onChange={(e) => setLeftModule(e.target.value)}
						placeholder="Left exact module path"
					/>
					<input
						aria-label="Right export module"
						disabled={busy}
						value={rightModule}
						onChange={(e) => setRightModule(e.target.value)}
						placeholder="Right exact module path"
					/>
					<input
						aria-label="Left export name"
						disabled={busy}
						value={leftExport}
						onChange={(e) => setLeftExport(e.target.value)}
						placeholder="Left export name"
					/>
					<input
						aria-label="Right export name"
						disabled={busy}
						value={rightExport}
						onChange={(e) => setRightExport(e.target.value)}
						placeholder="Right export name"
					/>
				</div>
			)}
			<button
				type="button"
				disabled={
					busy ||
					!receiptId ||
					(kind !== "application-trace" && !other) ||
					(kind === "application-trace" && !seed) ||
					(kind === "application-exports" && (!leftModule || !rightModule))
				}
				onClick={run}
			>
				{busy
					? "Reading saved application evidence…"
					: "Run saved application query"}
			</button>
			{error && <p role="alert">{error}</p>}
			{page && (
				<PreviewScrollRegion className="max-h-80">
					<section aria-label="Saved application workflow result">
						<pre className="whitespace-pre-wrap break-all">
							{JSON.stringify(page, null, 2)}
						</pre>
					</section>
				</PreviewScrollRegion>
			)}
			{page?.nextOffset !== null &&
				typeof page?.nextOffset === "number" &&
				lastQuery && (
					<button
						type="button"
						disabled={busy}
						onClick={() =>
							void query({ ...lastQuery, offset: page.nextOffset })
						}
					>
						Next saved application page
					</button>
				)}
		</details>
	);
}
