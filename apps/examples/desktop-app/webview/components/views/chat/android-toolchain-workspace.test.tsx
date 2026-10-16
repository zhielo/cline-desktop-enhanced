// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
const invoke = vi.hoisted(() =>
	vi.fn(async (_command: string, _args?: unknown) => ({
		state: "installed-not-tested",
	})),
);
vi.mock("@/lib/desktop-client", () => ({ desktopClient: { invoke } }));
import { AndroidToolchainWorkspace } from "./android-toolchain-workspace";
afterEach(() => {
	invoke.mockClear();
	document.body.innerHTML = "";
});
it("opens with read-only readiness and no automatic fixtures, signing or installation", async () => {
	const host = document.createElement("div"),
		root = createRoot(host),
		prepare = vi.fn();
	try {
		await act(async () =>
			root.render(
				<AndroidToolchainWorkspace environmentId="local" onPrepare={prepare} />,
			),
		);
		expect(invoke).toHaveBeenCalledTimes(1);
		expect(invoke.mock.calls[0][0]).toBe("setup_center_android_status");
		expect(prepare).not.toHaveBeenCalled();
		expect(host.textContent).toContain("installed-not-tested");
		expect(host.textContent).toContain(
			"Each step requires a fresh exact-request approval",
		);
		expect(
			Array.from(host.querySelectorAll("button")).find((b) =>
				b.textContent?.includes("Prepare exact"),
			)?.disabled,
		).toBe(true);
		const ids = Array.from(host.querySelectorAll("input,select")).map(
			(e) => e.id,
		);
		expect(new Set(ids).size).toBe(ids.length);
	} finally {
		await act(async () => root.unmount());
	}
});
it("does not invoke local tools for remote environments", async () => {
	const host = document.createElement("div"),
		root = createRoot(host);
	try {
		await act(async () =>
			root.render(
				<AndroidToolchainWorkspace
					environmentId="ssh:owned"
					onPrepare={() => {}}
				/>,
			),
		);
		expect(invoke).not.toHaveBeenCalled();
		expect(host.textContent).toContain("unsupported remote");
	} finally {
		await act(async () => root.unmount());
	}
});
