"use client";
import { useEffect, useRef, useState } from "react";
import { desktopClient } from "@/lib/desktop-client";
type Plan = {
	id: string;
	requestHash: string;
	requirements: string[];
	request: Record<string, unknown>;
};
export function ActiveJavaScriptScenario({
	sessionId,
	environmentId,
	enabled,
}: {
	sessionId: string;
	environmentId: string;
	enabled: boolean;
}) {
	const [allowExternal, setAllowExternal] = useState(false);
	const [kind, setKind] = useState("execute"),
		[pid, setPid] = useState(""),
		[address, setAddress] = useState("");
	const [target, setTarget] = useState(""),
		[purpose, setPurpose] = useState("Owned standalone scenario"),
		[expected, setExpected] = useState(""),
		[exit, setExit] = useState("0");
	const [plan, setPlan] = useState<Plan | null>(null),
		[result, setResult] = useState<unknown>(null),
		[error, setError] = useState(""),
		[busy, setBusy] = useState(false);
	const revision = useRef(0);
	const invalidate = () => {
		revision.current++;
		setPlan(null);
		setResult(null);
	};
	// biome-ignore lint/correctness/useExhaustiveDependencies: Session/environment/mode changes must invalidate pending authorizations even though only revision is accessed.
	useEffect(() => {
		revision.current++;
		setPlan(null);
		setResult(null);
		setError("");
		setBusy(false);
		return () => {
			revision.current++;
		};
	}, [sessionId, environmentId, enabled]);
	async function prepare() {
		const r = ++revision.current;
		setPlan(null);
		setError("");
		try {
			if (kind === "native") {
				const p = await desktopClient.invoke<Plan>(
					"first_party_analysis_native_prepare",
					{
						sessionId,
						environmentId,
						allowExternalTarget: allowExternal,
						input: {
							operation: "native_module_observe",
							target,
							pid: Number(pid),
							runtimeAddress: address,
						},
					},
				);
				if (r === revision.current) setPlan(p);
				return;
			}
			const hash = await crypto.subtle.digest(
				"SHA-256",
				new TextEncoder().encode(expected),
			);
			const stdoutSha256 = Array.from(new Uint8Array(hash), (b) =>
				b.toString(16).padStart(2, "0"),
			).join("");
			const p = await desktopClient.invoke<Plan>(
				"first_party_analysis_execute_prepare",
				{
					sessionId,
					environmentId,
					allowExternalTarget: allowExternal,
					input: {
						operation: "js_isolated_execute",
						target,
						timeoutMs: 5000,
						scenario: {
							id: "standalone-interface",
							purpose,
							exitCode: Number(exit),
							stdoutSha256,
						},
					},
				},
			);
			if (r === revision.current) setPlan(p);
		} catch (e) {
			if (r === revision.current)
				setError(e instanceof Error ? e.message : "Execute preparation failed");
		}
	}
	async function execute() {
		if (
			!plan ||
			!window.confirm(
				plan.request.operation === "native_module_observe"
					? `Authorize DEBUG/read of 32 bytes at this exact process birth, reviewed module and runtime address? Raw memory is not retained. Required approvals: ${plan.requirements.join(", ")}`
					: `Authorize EXECUTE of this exact standalone file in Windows x64 AppContainer? This runs target code, separately from Debug/Inspector. No dependencies, Electron GUI or unsandboxed fallback. AppContainer is not a VM and OS/application-readable files may remain accessible. Required approvals: ${plan.requirements.join(", ")}`,
			)
		)
			return;
		const approvedPlan = plan,
			r = revision.current;
		setPlan(null);
		setBusy(true);
		setError("");
		try {
			const approval = await desktopClient.invoke<{ executionToken: string }>(
				"approve_analysis_task",
				{
					sessionId,
					environmentId,
					planId: approvedPlan.id,
					requirements: approvedPlan.requirements,
					requestHash: approvedPlan.requestHash,
				},
			);
			if (r !== revision.current) return;
			const response = await desktopClient.invoke(
				approvedPlan.request.operation === "native_module_observe"
					? "first_party_analysis_native_run"
					: "first_party_analysis_execute_run",
				{
					sessionId,
					environmentId,
					planId: approvedPlan.id,
					executionToken: approval.executionToken,
					input: approvedPlan.request,
					confirmExecution: true,
					confirmDebug: true,
				},
				{ timeoutMs: 60000 },
			);
			if (r === revision.current) setResult(response);
		} catch (e) {
			if (r === revision.current)
				setError(
					e instanceof Error
						? e.message
						: "Execution failed; inspect tasks, do not automatically retry",
				);
		} finally {
			if (r === revision.current) setBusy(false);
		}
	}
	return (
		<section aria-label="Isolated JavaScript scenario">
			<h3>Isolated execution and native module observation</h3>
			<label>
				Operation
				<select
					aria-label="Scenario operation"
					value={kind}
					disabled={busy}
					onChange={(e) => {
						invalidate();
						setKind(e.target.value);
					}}
				>
					<option value="execute">JavaScript — Execute</option>
					<option value="native">Native module/address — Debug</option>
				</select>
			</label>
			{kind === "native" && (
				<>
					<label>
						Exact PID
						<input
							aria-label="Native observation PID"
							value={pid}
							disabled={busy}
							onChange={(e) => {
								invalidate();
								setPid(e.target.value);
							}}
						/>
					</label>
					<label>
						Runtime address
						<input
							aria-label="Native runtime address"
							value={address}
							disabled={busy}
							onChange={(e) => {
								invalidate();
								setAddress(e.target.value);
							}}
							placeholder="0x…"
						/>
					</label>
					<p>
						Windows x64 host reads an exact 32-byte PE range and observes the
						module base. PID birth and backing artifact hash are rechecked. This
						does not certify whole-image identity.
					</p>
				</>
			)}
			<p>
				Windows x64 only. One staged CommonJS file, no dependencies or host
				network capabilities. Tests exit status and exact stdout against your
				reviewed expectation—not internal semantic equivalence.
			</p>
			<label>
				Standalone target
				<input
					aria-label="Isolated JavaScript target"
					value={target}
					disabled={busy}
					onChange={(e) => {
						invalidate();
						setTarget(e.target.value);
					}}
				/>
			</label>
			<label>
				<input
					type="checkbox"
					aria-label="Allow reviewed external analysis target"
					checked={allowExternal}
					disabled={busy}
					onChange={(e) => {
						invalidate();
						setAllowExternal(e.target.checked);
					}}
				/>
				Allow this reviewed target outside the session workspace
			</label>
			<label>
				Scenario purpose
				<input
					aria-label="Isolated scenario purpose"
					value={purpose}
					disabled={busy}
					onChange={(e) => {
						invalidate();
						setPurpose(e.target.value);
					}}
				/>
			</label>
			<label>
				Expected stdout (exact, including newline)
				<textarea
					aria-label="Expected scenario stdout"
					value={expected}
					disabled={busy}
					onChange={(e) => {
						invalidate();
						setExpected(e.target.value);
					}}
				/>
			</label>
			<label>
				Expected exit code
				<input
					aria-label="Expected scenario exit"
					type="number"
					min={0}
					max={255}
					value={exit}
					disabled={busy}
					onChange={(e) => {
						invalidate();
						setExit(e.target.value);
					}}
				/>
			</label>
			<button
				type="button"
				disabled={!enabled || busy || !target}
				onClick={() => void prepare()}
			>
				Prepare independently reviewed plan
			</button>
			{plan && (
				<>
					<pre>
						{JSON.stringify(
							{
								request: plan.request,
								requestHash: plan.requestHash,
								requirements: plan.requirements,
							},
							null,
							2,
						)}
					</pre>
					<button
						type="button"
						disabled={!enabled || busy}
						onClick={() => void execute()}
					>
						{plan.request.operation === "native_module_observe"
							? "Approve Debug and observe once"
							: "Approve Execute and run once"}
					</button>
				</>
			)}
			{busy && <p>Running one isolated scenario…</p>}
			{error && <p role="alert">{error}</p>}
			{result != null && <pre>{JSON.stringify(result, null, 2)}</pre>}
		</section>
	);
}
