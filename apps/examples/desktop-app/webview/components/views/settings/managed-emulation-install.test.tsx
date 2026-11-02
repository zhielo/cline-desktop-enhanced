// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { ManagedEmulationInstall } from "./managed-emulation-install";
import type { ManagedPackStatus } from "../../../../sidecar/managed-emulation-pack.mjs";
const ids = ["qiling", "unidbg", "rnidbg", "speakeasy"] as const;
const status: ManagedPackStatus = {
	available: true,
	activation: "not-implemented",
	engineReadiness: "not-tested",
	engines: ids.map((id) => ({ id, status: "not-installed" })),
};
async function render(
	statusValue = status,
	busy = false,
	controls: Pick<
		Parameters<typeof ManagedEmulationInstall>[0],
		"job" | "cancel"
	> = {},
) {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	const element = document.createElement("div");
	document.body.append(element);
	const root = createRoot(element);
	const action = vi.fn(async () => {});
	await act(async () =>
		root.render(
			<ManagedEmulationInstall
				status={statusValue}
				busy={busy}
				action={action}
				{...controls}
			/>,
		),
	);
	return {
		element,
		action,
		close: async () => {
			await act(async () => root.unmount());
			element.remove();
		},
	};
}
it("default Install all four passes the fixed complete engine list and does not run on render", async () => {
	const view = await render();
	try {
		expect(view.action).not.toHaveBeenCalled();
		const button = [...view.element.querySelectorAll("button")].find(
			(b) => b.textContent === "Install all four",
		)!;
		await act(async () => button.click());
		expect(view.action).toHaveBeenCalledExactlyOnceWith(
			"setup_center_emulation_install",
			expect.stringContaining("does not start a VM"),
			{ engines: [...ids] },
		);
	} finally {
		await view.close();
	}
});
it("cancellation targets only the displayed running emulation install and is not a completion claim", async () => {
	const cancel = vi.fn(async () => {});
	const view = await render(status, true, {
		job: {
			id: "owned-install",
			command: "setup_center_emulation_install",
			status: "running",
		},
		cancel,
	});
	try {
		const button = [...view.element.querySelectorAll("button")].find(
			(b) => b.textContent === "Request installation cancellation",
		)!;
		expect(button.disabled).toBe(false);
		await act(async () => button.click());
		expect(cancel).toHaveBeenCalledExactlyOnceWith("owned-install");
		expect(view.action).not.toHaveBeenCalled();
	} finally {
		await view.close();
	}
	const unrelated = await render(status, true, {
		job: {
			id: "legacy-install",
			command: "setup_center_install_full",
			status: "running",
		},
		cancel,
	});
	try {
		expect(unrelated.element.textContent).not.toContain(
			"Request installation cancellation",
		);
	} finally {
		await unrelated.close();
	}
});
it("individual selection installs only checked engines while Install all four stays independent", async () => {
	const view = await render();
	try {
		const inputs = [...view.element.querySelectorAll("input")];
		await act(async () => {
			inputs[1]!.click();
			inputs[3]!.click();
		});
		const selected = [...view.element.querySelectorAll("button")].find(
			(b) => b.textContent === "Install selected engines (2)",
		)!;
		await act(async () => selected.click());
		expect(view.action).toHaveBeenLastCalledWith(
			"setup_center_emulation_install",
			expect.any(String),
			{ engines: ["qiling", "rnidbg"] },
		);
		const all = [...view.element.querySelectorAll("button")].find(
			(b) => b.textContent === "Install all four",
		)!;
		await act(async () => all.click());
		expect(view.action).toHaveBeenLastCalledWith(
			"setup_center_emulation_install",
			expect.any(String),
			{ engines: [...ids] },
		);
		await act(async () => {
			inputs[0]!.click();
			inputs[2]!.click();
		});
		expect(
			[...view.element.querySelectorAll("button")].find(
				(b) => b.textContent === "Install selected engines (0)",
			)!.disabled,
		).toBe(true);
	} finally {
		await view.close();
	}
});
it("missing reviewed payloads and busy setup disable every mutation without claiming readiness", async () => {
	for (const [value, busy] of [
		[{ ...status, available: false }, false],
		[status, true],
	] as const) {
		const view = await render(value, busy);
		try {
			expect(
				[...view.element.querySelectorAll("button")].every((b) => b.disabled),
			).toBe(true);
			expect(view.element.textContent).toContain(
				"Installed files are not runtime readiness",
			);
			expect(view.action).not.toHaveBeenCalled();
		} finally {
			await view.close();
		}
	}
});
