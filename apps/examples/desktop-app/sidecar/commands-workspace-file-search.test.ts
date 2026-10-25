import { describe, expect, it, vi } from "vitest";
import { handleCommand } from "./commands";
import type { SidecarContext } from "./types";
const { search } = vi.hoisted(() => ({ search: vi.fn() }));
vi.mock("./workspace-file-search", () => ({ listWorkspaceFiles: search }));
function context() {
	return {
		localWorkspaceRoot: "/owned-fixture",
		activeEnvironmentId: "local",
		runtimeBindings: new Map([["local", { kind: "local" }]]),
	} as unknown as SidecarContext;
}
describe("owned workspace file search commands", () => {
	it("cancels an environment-routed request from the owner context and frees its identity", async () => {
		const ctx = context();
		search.mockImplementation(
			(_root, _query, options: { signal: AbortSignal }) =>
				new Promise((resolve) => {
					options.signal.addEventListener(
						"abort",
						() =>
							resolve({ files: [], complete: false, stopReason: "cancelled" }),
						{ once: true },
					);
				}),
		);
		const pending = handleCommand(ctx, "list_workspace_files", {
			environmentId: "local",
			searchId: "owned-search",
		});
		await Promise.resolve();
		await expect(
			handleCommand(ctx, "list_workspace_files", {
				environmentId: "local",
				searchId: "owned-search",
			}),
		).rejects.toThrow("already active");
		// A different sidecar owner cannot cancel this request, even with the same ID.
		expect(
			await handleCommand(context(), "cancel_workspace_file_search", {
				searchId: "owned-search",
			}),
		).toEqual({ cancelled: false });
		expect(
			await handleCommand(ctx, "cancel_workspace_file_search", {
				searchId: "owned-search",
			}),
		).toEqual({ cancelled: true });
		expect(await pending).toMatchObject({ stopReason: "cancelled" });
		expect(
			await handleCommand(ctx, "cancel_workspace_file_search", {
				searchId: "owned-search",
			}),
		).toEqual({ cancelled: false });
	});
	it("rejects malformed identities before filesystem traversal", async () => {
		const ctx = context();
		search.mockClear();
		await expect(
			handleCommand(ctx, "list_workspace_files", { searchId: "../invalid" }),
		).rejects.toThrow("Invalid workspace search identity");
		expect(search).not.toHaveBeenCalled();
	});
});
