// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";

const calls = vi.hoisted(() => vi.fn());
vi.mock("@/lib/desktop-client", () => ({ desktopClient: { invoke: calls } }));

import { SetupCenter } from "./setup-center-view";

it("reads status only on open and installs only after explicit notice acceptance", async () => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	calls.mockResolvedValue({
		preferences: null,
		fullStatus: "Setup needed",
		features: [
			{
				id: "qbdi",
				label: "qbdi",
				status: "Setup needed",
				reason: "Owned execution required",
			},
		],
		packs: [],
		limitations: [],
	});
	const element = document.createElement("div");
	document.body.append(element);
	const root = createRoot(element);
	const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
	try {
		await act(async () => root.render(<SetupCenter />));
		expect(calls).toHaveBeenCalledTimes(1);
		expect(calls.mock.calls[0][0]).toBe("setup_center_status");
		const button = [...element.querySelectorAll("button")].find(
			(b) => b.textContent === "Install all supported components",
		)!;
		await act(async () => button.click());
		expect(calls).toHaveBeenCalledTimes(1);
		confirm.mockReturnValue(true);
		await act(async () => button.click());
		expect(confirm.mock.calls.at(-1)?.[0]).toContain("reviewed and accept");
		expect(calls).toHaveBeenCalledWith(
			"setup_center_install_full",
			{
				environmentId: "local",
				confirmed: true,
				acceptedPlatformToolsLicense: true,
			},
			{ timeoutMs: 300000 },
		);
		expect(element.textContent).toContain("qbdi: Setup needed");
	} finally {
		confirm.mockRestore();
		await act(async () => root.unmount());
		element.remove();
		calls.mockReset();
	}
});

it("saves the selected IDA folder and requests only the explicitly approved ARM64 fixture", async () => {
  Object.assign(globalThis,{IS_REACT_ACT_ENVIRONMENT:true});calls.mockReset();
  const status={preferences:{schemaVersion:1,idaHome:"C:\\Licensed IDA",adbPath:"",deviceSerial:"",deviceKind:"physical",workerEndpoint:"",workerPublicKey:"",acceptedPlatformToolsLicense:false},features:[],packs:[],limitations:[],fullStatus:"Setup needed",licensedArchitectures:[],desktopBuild:{version:"0.3.0",sourceCommit:"owned-build"}};
  calls.mockResolvedValue(status);
  const element=document.createElement("div");document.body.append(element);const root=createRoot(element);const confirm=vi.spyOn(window,"confirm").mockReturnValue(true);
  try {
    await act(async()=>root.render(<SetupCenter/>));
    const select=[...element.querySelectorAll("select")].find(e=>e.closest("label")?.textContent?.includes("IDA acceptance processor"))!;
    await act(async()=>{select.value="arm64";select.dispatchEvent(new Event("change",{bubbles:true}));});
    const button=[...element.querySelectorAll("button")].find(e=>e.textContent==="Test licensed IDA")!;
    await act(async()=>button.click());
    expect(calls).toHaveBeenCalledWith("setup_center_test_ida",{environmentId:"local",confirmed:true,authorizedLicense:true,architecture:"arm64",idaHome:status.preferences.idaHome},{timeoutMs:300000});
    expect(confirm.mock.calls.at(-1)?.[0]).toContain("fixed owned arm64");
    expect(element.textContent).toContain("owned-build");
    expect(element.textContent).toContain("Not verified");
  } finally {await act(async()=>root.unmount());element.remove();confirm.mockRestore();calls.mockReset();}
});
