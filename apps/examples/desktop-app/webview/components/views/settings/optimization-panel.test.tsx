// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
const calls = vi.hoisted(() => vi.fn());
vi.mock("@/lib/desktop-client", () => ({desktopClient:{invoke:calls}}));
import { OptimizationPanel } from "./optimization-panel";

it("cleans expired logs only after confirmation and displays bounded resource/evidence status", async () => {
	Object.assign(globalThis, {IS_REACT_ACT_ENVIRONMENT:true});
	const element = document.createElement("div");
	document.body.append(element);
	const root = createRoot(element);
	const confirm = vi.spyOn(window,"confirm").mockReturnValue(false);
	calls.mockImplementation(async (command:string) => command === "cleanup_completed_command_logs"
		? {removed:2,message:"Active commands and history preserved"}
		: {resources:{profile:"balanced",active:1,queued:2,scope:"owning-process",reservedMB:128,estimatedBudgetMB:1024,oldestQueuedMs:5000},
			performance:{reason:"Baseline required",commandLatency:{status:"collecting",reason:"Insufficient evidence",directSamples:2,shellSamples:3}},
			updates:{reason:"Private unsigned"},limitations:[]});
	try {
		await act(async()=>root.render(<OptimizationPanel/>));
		expect(calls).not.toHaveBeenCalled();
		const find = (text:string) => [...element.querySelectorAll("button")].find(b=>b.textContent===text)!;
		await act(async()=>find("Clean expired command logs").click());
		expect(calls).not.toHaveBeenCalled();
		confirm.mockReturnValue(true);
		await act(async()=>find("Clean expired command logs").click());
		expect(calls).toHaveBeenCalledWith("cleanup_completed_command_logs",{environmentId:"local",confirmed:true});
		expect(element.textContent).toContain("2 expired log directories removed");
		await act(async()=>find("Inspect optimization status").click());
		expect(element.textContent).toContain("Not an OS memory limit");
		expect(element.textContent).toContain("Baseline required");
		expect(element.textContent).toContain("2 direct and 3 shell samples");
	} finally {
		confirm.mockRestore();
		await act(async()=>root.unmount());
		element.remove();
		calls.mockReset();
	}
});