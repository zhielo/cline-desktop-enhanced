// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
const command = vi.hoisted(() => vi.fn());
vi.mock("@/lib/desktop-client", () => ({ desktopClient: { invoke: command } }));
import { SessionToolInventoryPanel } from "./session-tool-inventory";
it("does no automatic inspection, requires explicit selection, and shows unavailable/stale evidence honestly", async () => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	command.mockReset();
	const el = document.createElement("div"),
		root = createRoot(el);
	const button = (label: string) =>
		[...el.querySelectorAll("button")].find((b) => b.textContent === label)!;
	try {
		await act(async () => root.render(<SessionToolInventoryPanel />));
		expect(command).not.toHaveBeenCalled();
		command.mockResolvedValueOnce({
			sessions: [{ sessionId: "owner", local: true }],
		});
		await act(async () => button("Refresh attached sessions").click());
		expect(button("Inspect last request").disabled).toBe(true);
		const owningSelect = el.querySelector("select")!;
		expect(owningSelect.labels).toHaveLength(1);
		expect(owningSelect.labels![0].textContent?.trim()).toBe("Owning session");
		expect(owningSelect.labels![0].htmlFor).toBe(owningSelect.id);
		expect(owningSelect.labels![0].contains(owningSelect)).toBe(false);
		await act(async () => {
			const select = el.querySelector("select")!;
			select.value = "owner";
			select.dispatchEvent(new Event("change", { bubbles: true }));
		});
		command.mockResolvedValueOnce({
			sessionId: "owner",
			status: "unavailable",
			authorization: "Not granted.",
		});
		await act(async () => button("Inspect last request").click());
		expect(command).toHaveBeenLastCalledWith("session_tool_inventory", {
			sessionId: "owner",
		});
		expect(el.textContent).toContain("Unavailable");
		command.mockResolvedValueOnce({
			sessionId: "owner",
			status: "stale",
			providerId: "fixture",
			modelId: "fixture",
			evidence: {
				capturedAt: "owned time",
				iteration: 1,
				toolCount: 1,
				toolNames: ["<script>inert</script>"],
				modelToolCount: 0,
				modelToolNames: [],
				truncated: false,
			},
			authorization: "Not granted.",
		});
		await act(async () => button("Inspect last request").click());
		expect(el.textContent).toContain("Stale");
		expect(el.querySelector("script")).toBeNull();
		expect(el.textContent).toContain("<script>inert</script>");
		expect(command.mock.calls.map((c) => c[0])).toEqual([
			"session_tool_inventory_sessions",
			"session_tool_inventory",
			"session_tool_inventory",
		]);
	} finally {
		await act(async () => root.unmount());
	}
});
