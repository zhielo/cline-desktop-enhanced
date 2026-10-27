"use client";
import { useId, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { desktopClient } from "@/lib/desktop-client";
export function EmulationProfileControls({
	target,
	common,
	onPrepare,
	onDraftChange,
}: {
	target: string;
	common: Record<string, unknown>;
	onPrepare: (request: Record<string, unknown>) => Promise<void>;
	onDraftChange?: () => void;
}) {
	const id = useId();
	const [engine, setEngine] = useState("qiling"),
		[architecture, setArchitecture] = useState("x86_64"),
		[scenario, setScenario] = useState("initialize"),
		[cls, setCls] = useState(""),
		[method, setMethod] = useState(""),
		[argument, setArgument] = useState("0"),
		[expected, setExpected] = useState(""),
		[instructions, setInstructions] = useState("10000"),
		[timeout, setTimeoutMs] = useState("60000"),
		[baseline, setBaseline] = useState(""),
		[baselineKind, setBaselineKind] = useState("receipt"),
		[question, setQuestion] = useState(""),
		[status, setStatus] = useState(
			"Workers are optional and not bundled. Check readiness before preparing.",
		),
		[busy, setBusy] = useState(false);
	const choose = (value: string) => {
		setEngine(value);
		setArchitecture(value === "qiling" ? "x86_64" : "arm64");
		setExpected("");
		setStatus(
			"Engine changed. A fresh worker-bound plan and approval are required.",
		);
	};
	const int = (s: string, min: number, max: number) => {
		if (!/^-?\d+$/.test(s))
			throw new Error(
				"Use whole numbers for typed scenario values and budgets",
			);
		const n = Number(s);
		if (!Number.isSafeInteger(n) || n < min || n > max)
			throw new Error("Scenario value or budget is out of range");
		return n;
	};
	const prepare = async () => {
		setBusy(true);
		try {
			const typed =
				engine === "qiling"
					? {
							kind: "entry",
							...(expected !== ""
								? { expectedExit: int(expected, 0, 255) }
								: {}),
						}
					: scenario === "initialize"
						? { kind: "initialize" }
						: {
								kind: "jni-int32",
								className: cls,
								methodName: method,
								argument: int(argument, -2147483648, 2147483647),
								...(expected !== ""
									? { expectedReturn: int(expected, -2147483648, 2147483647) }
									: {}),
							};
			await onPrepare({
				operation: "emulate_profile",
				target: target.trim(),
				engine,
				architecture,
				scenario: typed,
				instruction_limit: int(instructions, 1, 100000),
				timeout_ms: int(timeout, 1000, 120000),
				...(baseline
					? { hybridProposal: { baselineKind, baselineId: baseline, question } }
					: {}),
			});
		} catch (e) {
			setStatus(e instanceof Error ? e.message : String(e));
		} finally {
			setBusy(false);
		}
	};
	return (
		<section
			className="space-y-3"
			aria-label="Optional emulation profile"
			onChange={onDraftChange}
		>
			<h4 className="font-semibold">Fixed emulation profile</h4>
			<p className="text-xs text-muted-foreground">
				Requires an attached Full Access local session in Runtime or Hybrid
				mode. Static planning never executes targets. No automatic fallback,
				download or engine switching. Existing Unicorn and Speakeasy are
				preserved.
			</p>
			<label className="block">
				Emulation engine
				<select
					aria-label="Emulation engine"
					className="min-h-11 w-full rounded-md border bg-background"
					value={engine}
					onChange={(e) => choose(e.target.value)}
				>
					<option value="qiling">
						Qiling · static Linux ELF x86-64 / ARM32 / ARM64
					</option>
					<option value="unidbg">unidbg · Android JNI ARM32 / ARM64</option>
					<option value="rnidbg">
						rnidbg · experimental Android JNI ARM64
					</option>
				</select>
			</label>
			<label className="block">
				Emulation architecture
				<select
					aria-label="Emulation architecture"
					className="min-h-11 w-full rounded-md border bg-background"
					value={architecture}
					onChange={(e) => setArchitecture(e.target.value)}
				>
					{engine === "qiling" ? (
						<>
							<option value="x86_64">x86-64</option>
							<option value="arm32">ARM32</option>
							<option value="arm64">ARM64</option>
						</>
					) : (
						<>
							<option value="arm64">ARM64</option>
							{engine === "unidbg" && <option value="arm32">ARM32</option>}
						</>
					)}
				</select>
			</label>
			{engine !== "qiling" && (
				<label className="block">
					JNI scenario
					<select
						aria-label="JNI scenario"
						className="min-h-11 w-full rounded-md border bg-background"
						value={scenario}
						onChange={(e) => {
							setScenario(e.target.value);
							setExpected("");
						}}
					>
						<option value="initialize">Constructors + JNI_OnLoad only</option>
						<option value="jni-int32">Exact static JNI method (I)I</option>
					</select>
				</label>
			)}
			{engine !== "qiling" && scenario === "jni-int32" && (
				<>
					<label htmlFor={`${id}-jni-class`} className="block">
						JNI class
						<Input
							id={`${id}-jni-class`}
							aria-label="JNI class"
							placeholder="com/example/Owned"
							value={cls}
							onChange={(e) => setCls(e.target.value)}
						/>
					</label>
					<label htmlFor={`${id}-jni-method`} className="block">
						JNI method
						<Input
							id={`${id}-jni-method`}
							aria-label="JNI method"
							placeholder="transform"
							value={method}
							onChange={(e) => setMethod(e.target.value)}
						/>
					</label>
					<label htmlFor={`${id}-int32-argument`} className="block">
						Int32 argument
						<Input
							id={`${id}-int32-argument`}
							aria-label="Int32 argument"
							value={argument}
							onChange={(e) => setArgument(e.target.value)}
						/>
					</label>
				</>
			)}
			{(engine === "qiling" || scenario === "jni-int32") && (
				<label htmlFor={`${id}-expected-emulation-result`} className="block">
					{engine === "qiling"
						? "Expected exit (optional)"
						: "Expected Int32 return (optional)"}
					<Input
						id={`${id}-expected-emulation-result`}
						aria-label="Expected emulation result"
						value={expected}
						onChange={(e) => setExpected(e.target.value)}
					/>
				</label>
			)}
			<div className="grid grid-cols-2 gap-2">
				<label htmlFor={`${id}-emulation-instruction-limit`}>
					Instruction limit
					<Input
						id={`${id}-emulation-instruction-limit`}
						aria-label="Emulation instruction limit"
						value={instructions}
						onChange={(e) => setInstructions(e.target.value)}
					/>
				</label>
				<label htmlFor={`${id}-emulation-timeout`}>
					Timeout (ms)
					<Input
						id={`${id}-emulation-timeout`}
						aria-label="Emulation timeout"
						value={timeout}
						onChange={(e) => setTimeoutMs(e.target.value)}
					/>
				</label>
			</div>
			<details>
				<summary>Hybrid static-evidence basis (required in Hybrid)</summary>
				<p className="text-xs">
					Use intact evidence from this session for this exact artifact hash.
					Runtime mode must leave this empty.
				</p>
				<label className="block">
					Baseline kind
					<select
						aria-label="Emulation baseline kind"
						value={baselineKind}
						onChange={(e) => setBaselineKind(e.target.value)}
					>
						<option value="receipt">Static receipt</option>
						<option value="static-task">Static task</option>
					</select>
				</label>
				<label htmlFor={`${id}-emulation-baseline-id`}>
					Baseline ID
					<Input
						id={`${id}-emulation-baseline-id`}
						aria-label="Emulation baseline ID"
						value={baseline}
						onChange={(e) => setBaseline(e.target.value)}
					/>
				</label>
				<label htmlFor={`${id}-emulation-question`}>
					Question
					<Input
						id={`${id}-emulation-question`}
						aria-label="Emulation question"
						value={question}
						onChange={(e) => setQuestion(e.target.value)}
					/>
				</label>
			</details>
			<p className="text-xs text-muted-foreground">
				{engine === "qiling"
					? "Static ET_EXEC only, empty rootfs, stdout/stderr write and exit only; no libc or OS filesystem."
					: "ELF shared library without DT_NEEDED dependencies. No APK, external libraries, custom Java stubs or target syscalls. Unsupported targets fail closed."}{" "}
				Results are modeled partial evidence, never native behavior or whole-app
				verification.
			</p>
			<div className="flex flex-wrap gap-2">
				<Button
					variant="outline"
					disabled={busy}
					onClick={async () => {
						setBusy(true);
						try {
							const h = await desktopClient.invoke<{
								ready: boolean;
								error?: string;
							}>("get_emulation_readiness", { ...common, engine });
							setStatus(
								h.ready
									? "Signed worker passed its owned startup fixtures. Operator VM isolation is not hardware-attested."
									: (h.error ?? "Worker unavailable"),
							);
						} catch (e) {
							setStatus(e instanceof Error ? e.message : String(e));
						} finally {
							setBusy(false);
						}
					}}
				>
					Check engine readiness
				</Button>
				<Button
					disabled={busy || !target.trim() || !common.sessionId}
					onClick={() => void prepare()}
				>
					Prepare emulation task
				</Button>
			</div>
			<output className="block break-words text-xs">{status}</output>
		</section>
	);
}
