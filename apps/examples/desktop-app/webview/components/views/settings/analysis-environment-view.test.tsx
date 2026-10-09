// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
const calls = vi.hoisted(() => vi.fn());
vi.mock("@/lib/desktop-client", () => ({ desktopClient: { invoke: calls } }));
import { AnalysisEnvironmentView } from "./analysis-environment-view";
it("requires explicit readiness action and renders missing engines without claiming IDA failure", async () => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	calls.mockResolvedValue({
		configured: true,
		interpreter: { executable: "C:\\owned\\python.exe", version: "3.13" },
		toolchain: { status: "completed", evidence: { engines: [] } },
		readiness: {
			status: "partial",
			evidence: {
				checks: [
					{
						engine: "lief",
						status: "blocked",
						executionVerified: false,
						reason: "Required static engine missing",
					},
				],
			},
		},
		externalCapabilities: [
			{ id: "IDA / IDAPython", reason: "Separate acceptance required" },
		],
		setup: "Explicit opt-in setup",
	});
	const element = document.createElement("div");
	document.body.append(element);
	const root = createRoot(element);
	try {
		await act(async () => root.render(<AnalysisEnvironmentView />));
		expect(calls).not.toHaveBeenCalled();
		const button = [...element.querySelectorAll("button")].find(
			(node) => node.textContent === "Check analysis readiness",
		)!;
		await act(async () => {
			button.click();
		});
		expect(calls).toHaveBeenCalledWith(
			"get_analysis_environment",
			{ environmentId: "local" },
			{ timeoutMs: 90_000 },
		);
		expect(element.textContent).toContain("Missing dependency");
		expect(element.textContent).toContain(
			"Configuration / acceptance required",
		);
		expect(element.textContent).toContain("C:\\owned\\python.exe");
	} finally {
		await act(async () => root.unmount());
		element.remove();
    calls.mockReset();
	}
});

it("opens Setup Center without running readiness or installation commands", async () => {
  Object.assign(globalThis,{IS_REACT_ACT_ENVIRONMENT:true});calls.mockReset();
  const open=vi.fn();const element=document.createElement("div");document.body.append(element);const root=createRoot(element);
  try {
    await act(async()=>root.render(<AnalysisEnvironmentView onOpenSetup={open}/>));
    const button=[...element.querySelectorAll("button")].find(b=>b.textContent==="Open Setup Center")!;
    await act(async()=>button.click());expect(open).toHaveBeenCalledOnce();expect(calls).not.toHaveBeenCalled();
    expect(element.textContent).toContain("processor-specific Hex-Rays license");
  } finally {await act(async()=>root.unmount());element.remove();calls.mockReset();}
});
it("live diagnostics refresh serially and stop on unmount without restarting a job", async () => {
  Object.assign(globalThis,{IS_REACT_ACT_ENVIRONMENT:true});calls.mockReset();vi.useFakeTimers();
  calls.mockResolvedValue({jobs:[{id:"owned",pid:42,status:"running",lastPhase:"auto-analysis-waiting",receiptPath:"owned.jsonl",elapsedMs:10000,remainingMs:120000}]});
  const element=document.createElement("div");document.body.append(element);const root=createRoot(element);
  try {
    await act(async()=>root.render(<AnalysisEnvironmentView/>));
    await act(async()=>element.querySelector<HTMLInputElement>('input[type="checkbox"]')!.click());
    expect(calls).toHaveBeenCalledTimes(1);
    expect(calls.mock.calls[0][0]).toBe("get_ida_job_diagnostics");
    expect(element.textContent).toContain("Elapsed 10s");
    await act(async()=>vi.advanceTimersByTimeAsync(2000));expect(calls).toHaveBeenCalledTimes(2);
    await act(async()=>root.unmount());
    await vi.advanceTimersByTimeAsync(4000);expect(calls).toHaveBeenCalledTimes(2);
  } finally {await act(async()=>root.unmount());element.remove();calls.mockReset();vi.useRealTimers();}
});
