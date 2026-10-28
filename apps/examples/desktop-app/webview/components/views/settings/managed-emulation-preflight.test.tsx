// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
const invoke = vi.hoisted(() => vi.fn());
vi.mock("@/lib/desktop-client", () => ({ desktopClient: { invoke } }));
import { ManagedEmulationPreflightPanel } from "./managed-emulation-preflight";
it("does no automatic probe; cancellation, repeated clicks and transport failures never become readiness", async () => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	invoke.mockReset();
	const host = document.createElement("div"),
		root = createRoot(host);
	const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
	try {
		await act(async () => root.render(<ManagedEmulationPreflightPanel />));
		expect(invoke).not.toHaveBeenCalled();
		expect(host.textContent).toContain(
			"managed installation is not implemented",
		);
		const button = host.querySelector("button")!;
		await act(async () => button.click());
		expect(invoke).not.toHaveBeenCalled();
		confirm.mockReturnValue(true);
		let finish!: (value: unknown) => void;
		invoke.mockImplementationOnce(
			() =>
				new Promise((resolve) => {
					finish = resolve;
				}),
		);
		await act(async () => {
			button.click();
			button.click();
		});
		expect(invoke).toHaveBeenCalledExactlyOnceWith(
			"setup_center_emulation_host_preflight",
			{ environmentId: "local", confirmed: true },
		);
		expect(button.disabled).toBe(true);
		await act(async () =>
			finish({
				hostPrerequisites: "observed",
				query: "observed",
				osBuild: "19045",
				checkedAt: "2026-10-28T00:00:00.000Z",
				checks: [
					{
						id: "hyper-v",
						label: "Hyper-V feature enabled",
						state: "observed",
					},
				],
				capacity: { totalMemoryGiB: 16, freeMemoryGiB: 8, freeStorageGiB: 40 },
			}),
		);
		expect(host.querySelector("time")?.dateTime).toBe(
			"2026-10-28T00:00:00.000Z",
		);
		expect(host.textContent).toContain(
			"Containment: not tested. Engine readiness: not tested.",
		);
		expect(host.textContent).toContain("not reserved resources");
		invoke.mockRejectedValueOnce(
			new Error("SECRET arbitrary transport diagnostic"),
		);
		await act(async () => button.click());
		expect(host.querySelector('[role="alert"]')?.textContent).toContain(
			"No installation or readiness is inferred",
		);
		expect(host.querySelector("time")).toBeNull();
		expect(host.textContent).not.toContain("SECRET");
	} finally {
		await act(async () => root.unmount());
		confirm.mockRestore();
	}
});
