"use client";
import { useCallback, useEffect, useId, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PreviewScrollRegion } from "@/components/ui/preview-scroll-region";
import { desktopClient } from "@/lib/desktop-client";
import { BinaryTriageReadiness } from "../settings/binary-triage-readiness";

type Receipt = {
	id: string;
	operation: string;
	status: string;
	target: string;
	targetSha256?: string;
	question: string;
	evidence?: { category?: string; coverage?: string };
	startedAt?: string;
};
const operations = [
	["inspect_binary", "Inspect binary structure"],
	["list_functions", "Find candidate functions"],
	["get_function_disassembly", "Inspect instructions at an address"],
	["find_references", "Find candidate references to an address"],
	["scan_yara", "Match reviewed YARA patterns"],
	["identify_capabilities", "Identify capa capabilities"],
	["extract_strings", "Extract FLOSS static strings (PE)"],
];
export function GuidedInvestigation({
	sessionId,
	environmentId,
	onNavigate,
}: {
	sessionId?: string;
	environmentId: string;
	onNavigate: (
		mode: "android" | "first-party" | "incidents" | "investigation" | "evidence",
	) => void;
}) {
	const prefix = useId(),
		[target, setTarget] = useState(""),
		[question, setQuestion] = useState(""),
		[operation, setOperation] = useState("inspect_binary"),
		[address, setAddress] = useState(""),
		[busy, setBusy] = useState(false),
		[requestId, setRequestId] = useState(""),
		[error, setError] = useState(""),
		[receipt, setReceipt] = useState<Receipt | null>(null),
		[history, setHistory] = useState<Receipt[]>([]);
	const local = environmentId === "local";
	const refresh = useCallback(async () => {
		if (!sessionId || !local) return;
		setHistory(
			await desktopClient.invoke<Receipt[]>("binary_triage_history", {
				sessionId,
				environmentId,
			}),
		);
	}, [sessionId, environmentId, local]);
	useEffect(() => {
		setReceipt(null);
		setHistory([]);
		setError("");
		void refresh().catch(() => {});
	}, [refresh]); // Reads only; never replays a prior run.
	async function run() {
		if (
			!window.confirm(
				`Run the selected bounded static analysis on ${target}? Full Access, an idle local session and enabled Analysis are required. No target execution is authorized.`,
			)
		)
			return;
		const id = crypto.randomUUID();
		setRequestId(id);
		setBusy(true);
		setError("");
		setReceipt(null);
		try {
			setReceipt(
				await desktopClient.invoke<Receipt>(
					"binary_triage_run",
					{
						sessionId,
						environmentId,
						requestId: id,
						confirmed: true,
						input: {
							target,
							question,
							operation,
							...(["get_function_disassembly", "find_references"].includes(
								operation,
							)
								? { address }
								: {}),
						},
					},
					{ timeoutMs: 120000 },
				),
			);
		} catch (e) {
			setError(
				e instanceof Error
					? e.message
					: "Analysis unavailable. Inspect history; do not automatically retry an ambiguous request.",
			);
		} finally {
			setBusy(false);
			await refresh().catch(() => {});
		}
	}
	async function exportReport(id: string) {
		try {
			const report = await desktopClient.invoke("binary_triage_report", {
				sessionId,
				environmentId,
				id,
			});
			const url = URL.createObjectURL(
				new Blob([JSON.stringify(report, null, 2)], {
					type: "application/json",
				}),
			);
			const link = document.createElement("a");
			link.href = url;
			link.download = `cline-triage-${id}.json`;
			link.click();
			setTimeout(() => URL.revokeObjectURL(url), 1000);
		} catch {
			setError(
				"Report unavailable in this owning session. No export was claimed.",
			);
		}
	}
	return (
		<section aria-label="Guided investigation" className="space-y-4">
			<h3 className="font-semibold">
				Start with a question, finish with evidence
			</h3>
			<p className="text-xs text-muted-foreground">
				Select target → ask a question → inspect → choose deeper analysis →
				review evidence → export. Existing coding, worktrees, providers and
				advanced tabs are unchanged.
			</p>
			<div className="grid gap-2">
				<Button variant="outline" onClick={() => onNavigate("first-party")}>
					Understand a JS / Electron application
				</Button>
				<Button variant="outline" onClick={() => onNavigate("android")}>
 Analyze / rebuild an owned Android app
 </Button>
 <Button variant="outline" onClick={() => onNavigate("incidents")}>
					Investigate an APK / native issue
				</Button>
				<Button variant="outline" onClick={() => onNavigate("investigation")}>
					Organize investigation questions
				</Button>
				<Button variant="outline" onClick={() => onNavigate("evidence")}>
					Review existing analysis evidence
				</Button>
			</div>
			<p className="text-xs">
				For coding, use normal chat and Changes / Files / Terminal. This guide
				does not change your provider, permission profile or Analysis mode.
			</p>
			{local ? (
				<BinaryTriageReadiness />
			) : (
				<p>Binary Triage Pack: Unsupported for remote/cloud environments.</p>
			)}
			<h4 className="font-medium">Bounded binary triage</h4>
			<label htmlFor={`${prefix}-question`}>
				What do you want to understand?
			</label>
			<Input
				id={`${prefix}-question`}
				maxLength={500}
				value={question}
				onChange={(e) => setQuestion(e.target.value)}
				placeholder="Which functions may perform network communication?"
			/>
			<label htmlFor={`${prefix}-target`}>
				Target inside this session’s workspace
			</label>
			<Input
				id={`${prefix}-target`}
				value={target}
				onChange={(e) => setTarget(e.target.value)}
				placeholder="bin/application.exe or lib/arm64-v8a/library.so"
			/>
			<label htmlFor={`${prefix}-operation`}>Next analysis step</label>
			<select
				id={`${prefix}-operation`}
				className="w-full rounded border bg-background p-2 text-sm"
				value={operation}
				onChange={(e) => setOperation(e.target.value)}
			>
				{operations.map(([value, label]) => (
					<option key={value} value={value}>
						{label}
					</option>
				))}
			</select>
			{["get_function_disassembly", "find_references"].includes(operation) && (
				<>
					<label htmlFor={`${prefix}-address`}>Exact hexadecimal address</label>
					<Input
						id={`${prefix}-address`}
						value={address}
						onChange={(e) => setAddress(e.target.value)}
						placeholder="0x140001000"
					/>
				</>
			)}
			<p className="text-xs text-muted-foreground">
				Suggested order: inspect structure → list functions → inspect selected
				addresses. YARA/capa add pattern and capability evidence; they do not
				prove behavior or maliciousness. FLOSS decoding is disabled. No match
				does not mean safe.
			</p>
			<Button
				disabled={
					busy || !local || !sessionId || !target.trim() || !question.trim()
				}
				onClick={() => void run()}
			>
				{busy
					? "Analyzing; no automatic replay…"
					: "Review and run static triage"}
			</Button>
			{busy && (
				<Button
					variant="outline"
					onClick={() =>
						void desktopClient
							.invoke("binary_triage_cancel", {
								sessionId,
								environmentId,
								requestId,
							})
							.catch(() =>
								setError(
									"Cancellation could not be confirmed. Inspect history before new work.",
								),
							)
					}
				>
					Request cancellation
				</Button>
			)}
			{!sessionId && (
				<p className="text-xs">
					Open an idle local session to bind evidence to its workspace.
				</p>
			)}
			{error && (
				<p role="alert" className="text-xs text-destructive">
					{error}
				</p>
			)}
			{receipt && (
				<div className="space-y-2 rounded border p-3">
					<strong>Result: {receipt.status}</strong>
					<p className="break-all text-xs">
						Observed input SHA-256: {receipt.targetSha256}
					</p>
					<p className="text-xs">
						Evidence category:{" "}
						{receipt.evidence?.category ?? "No completed findings"}
					</p>
					<p className="text-xs">{receipt.evidence?.coverage}</p>
					<p className="text-xs">
						Unknown: complete behavior and whether the investigation question is
						fully answered. Review findings before drawing conclusions.
					</p>
					<PreviewScrollRegion
						aria-label="Bounded triage evidence preview"
						className="max-h-80"
					>
						<pre className="whitespace-pre-wrap break-all text-xs">
							{JSON.stringify(receipt, null, 2).slice(0, 30000)}
						</pre>
					</PreviewScrollRegion>
					<p className="text-xs">
						Preview capped at 30,000 characters; export contains the bounded
						full receipt.
					</p>
					<Button
						variant="outline"
						onClick={() => void exportReport(receipt.id)}
					>
						Export selected evidence report
					</Button>
				</div>
			)}
			<h4>Saved receipts — status reads never rerun analysis</h4>
			<Button
				variant="outline"
				disabled={busy || !sessionId || !local}
				onClick={() =>
					void refresh().catch(() => setError("History unavailable"))
				}
			>
				Refresh saved receipts
			</Button>
			{history.map((r) => (
				<div key={r.id} className="rounded border p-2 text-xs">
					<p>
						{r.operation} — {r.status} — {r.target}
					</p>
					<Button variant="outline" onClick={() => void exportReport(r.id)}>
						Export receipt
					</Button>
				</div>
			))}
		</section>
	);
}
