import { expect, it, vi } from "vitest";
import type { SidecarContext, SidecarWebSocketClient } from "./types";
const read = vi.hoisted(() =>
	vi.fn(async () => ({
		managedInstallation: "not-implemented",
		engineReadiness: "not-tested",
	})),
);
vi.mock("./managed-emulation-preflight", () => ({
	readManagedEmulationPreflight: read,
}));
it("requires explicit trusted local confirmation before any host probe and passes no client arguments to the query", async () => {
	const { handleCommand } = await import("./commands");
	const ctx = {
		runtimeBindings: new Map([
			["local", { kind: "local" }],
			["remote", { kind: "ssh" }],
		]),
		activeEnvironmentId: "local",
	} as unknown as SidecarContext;
	const trusted = {
		connection: { data: { canApproveTools: true } } as SidecarWebSocketClient,
	};
	read.mockClear();
	await expect(
		handleCommand(ctx, "setup_center_emulation_host_preflight", {
			confirmed: true,
		}),
	).rejects.toThrow("trusted desktop");
	await expect(
		handleCommand(ctx, "setup_center_emulation_host_preflight", {}, trusted),
	).rejects.toThrow("confirmation");
	await expect(
		handleCommand(
			ctx,
			"setup_center_emulation_host_preflight",
			{ environmentId: "remote", confirmed: true },
			trusted,
		),
	).rejects.toThrow("local-only");
	expect(read).not.toHaveBeenCalled();
	await expect(
		handleCommand(
			ctx,
			"setup_center_emulation_host_preflight",
			{
				environmentId: "local",
				confirmed: true,
				command: "DO NOT EXECUTE",
				path: "SECRET",
			},
			trusted,
		),
	).resolves.toMatchObject({ managedInstallation: "not-implemented" });
	expect(read).toHaveBeenCalledExactlyOnceWith();
});
