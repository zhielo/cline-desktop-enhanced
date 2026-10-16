// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";

Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
const invoke = vi.hoisted(() =>
	vi.fn(async (name: string) =>
		name === "binary_triage_status"
			? {
					capabilities: [
						{
							id: "radare2",
							state: "installed-not-tested",
							reason: "Needs owned fixture",
						},
					],
				}
			: [],
	),
);
vi.mock("@/lib/desktop-client", () => ({ desktopClient: { invoke } }));

import { GuidedInvestigation } from "./guided-investigation";

afterEach(() => {
	invoke.mockClear();
	document.body.innerHTML = "";
});
it("opening reads readiness/history only and requires explicit execution", async () => {
	const host = document.createElement("div");
	document.body.append(host);
	const root = createRoot(host);
	try {
		await act(async () =>
			root.render(
				<GuidedInvestigation
					sessionId="owned"
					environmentId="local"
					onNavigate={() => {}}
				/>,
			),
		);
		expect(host.textContent).toContain("Installed but untested");
		expect(host.textContent).toContain("No match");
		expect(
			invoke.mock.calls.every(([name]) =>
				["binary_triage_status", "binary_triage_history"].includes(name),
			),
		).toBe(true);
		const run = Array.from(host.querySelectorAll("button")).find(
			(b) => b.textContent === "Review and run static triage",
		);
		expect(run?.disabled).toBe(true);
		const ids = Array.from(host.querySelectorAll("input,select")).map(
			(e) => e.id,
		);
		expect(new Set(ids).size).toBe(ids.length);
	} finally {
		await act(async () => root.unmount());
	}
});
it("remote guide does not request local readiness", async () => {
	const host = document.createElement("div"),
		root = createRoot(host);
	try {
		await act(async () =>
			root.render(
				<GuidedInvestigation
					sessionId="remote"
					environmentId="ssh:owned"
					onNavigate={() => {}}
				/>,
			),
		);
		expect(invoke).not.toHaveBeenCalled();
		expect(host.textContent).toContain("Unsupported");
	} finally {
		await act(async () => root.unmount());
	}
});
