// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { desktopClient } from "@/lib/desktop-client";
import { EmulationProfileControls } from "./emulation-profile-controls";
it("presents honest optional profiles, changes architecture explicitly, and prepares only typed requests", async () => {
	const container = document.createElement("div");
	document.body.appendChild(container);
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	const root = createRoot(container),
		prepare = vi.fn(async () => {}),
		rpc = vi.spyOn(desktopClient, "invoke").mockResolvedValue({
			ready: false,
			error: "No independent worker configured",
		});
	const select = async (label: string, value: string) => {
		const e = container.querySelector(
			`select[aria-label="${label}"]`,
		) as HTMLSelectElement;
		await act(async () => {
			e.value = value;
			e.dispatchEvent(new Event("change", { bubbles: true }));
		});
	};
	const click = async (text: string) => {
		const e = [...container.querySelectorAll("button")].find(
			(b) => b.textContent === text,
		);
		await act(async () => {
			e?.click();
		});
	};
	try {
		await act(async () =>
			root.render(
				<EmulationProfileControls
					target="owned.elf"
					common={{ sessionId: "owner" }}
					onPrepare={prepare}
				/>,
			),
		);
		expect(container.textContent).toContain(
			"Unicorn and Speakeasy are preserved",
		);
		await click("Check engine readiness");
		expect(container.textContent).toContain("No independent worker");
		expect(prepare).not.toHaveBeenCalled();
		for (const architecture of ["arm32", "arm64"]) {
			await select("Emulation architecture", architecture);
			await click("Prepare emulation task");
			expect(prepare).toHaveBeenLastCalledWith(
				expect.objectContaining({
					engine: "qiling",
					architecture,
					scenario: { kind: "entry" },
				}),
			);
		}
		await select("Emulation engine", "rnidbg");
		expect(container.textContent).toContain("experimental");
		expect(
			(
				container.querySelector(
					'select[aria-label="Emulation architecture"]',
				) as HTMLSelectElement
			).options,
		).toHaveLength(1);
		await click("Prepare emulation task");
		expect(prepare).toHaveBeenCalledWith({
			operation: "emulate_profile",
			target: "owned.elf",
			engine: "rnidbg",
			architecture: "arm64",
			scenario: { kind: "initialize" },
			instruction_limit: 10000,
			timeout_ms: 60000,
		});
		await select("Emulation engine", "unidbg");
		await select("Emulation architecture", "arm32");
		await click("Prepare emulation task");
		expect(prepare).toHaveBeenLastCalledWith(
			expect.objectContaining({ engine: "unidbg", architecture: "arm32" }),
		);
	} finally {
		await act(async () => root.unmount());
		container.remove();
		rpc.mockRestore();
	}
});
