import { beforeEach, expect, it, vi } from "vitest";
import type { SidecarContext, SidecarWebSocketClient } from "./types";
const owned = vi.hoisted(() => ({ test: vi.fn(), start: vi.fn() }));
vi.mock("./setup-center", async () => ({
	...(await vi.importActual<typeof import("./setup-center")>("./setup-center")),
	testLicensedIda: owned.test,
}));
vi.mock("./setup-jobs", async () => ({
	...(await vi.importActual<typeof import("./setup-jobs")>("./setup-jobs")),
	startSetupJob: owned.start,
}));
function context(): SidecarContext {
	return {
		localWorkspaceRoot: "/workspace",
		activeEnvironmentId: "local",
		runtimeBindings: new Map([
			["local", { kind: "local", environmentId: "local" }],
		]),
		wsClients: new Set(),
		logger: { debug: vi.fn(), log: vi.fn(), error: vi.fn() },
	} as unknown as SidecarContext;
}
const connection = (trusted: boolean) =>
	({ data: { canApproveTools: trusted } }) as unknown as SidecarWebSocketClient;
beforeEach(() => {
	owned.test
		.mockReset()
		.mockResolvedValue({ status: "passed", scope: "owned fixture" });
	owned.start
		.mockReset()
		.mockImplementation((_command, _args, operation) => ({
			job: { id: "owned", status: "running" },
			completion: operation(vi.fn()),
		}));
});
it("permits an explicitly confirmed trusted owned IDA test without license self-attestation", async () => {
	const { handleCommand } = await import("./commands");
	const result = await handleCommand(
		context(),
		"setup_center_test_ida",
		{ environmentId: "local", confirmed: true, architecture: "arm64" },
		{ connection: connection(true) },
	);
	expect(owned.test).toHaveBeenCalledWith("arm64");
	expect(result).toMatchObject({ status: "passed" });
});
it("still rejects untrusted, unconfirmed and unsupported-architecture tests before starting IDA", async () => {
	const { handleCommand } = await import("./commands");
	for (const [args, trusted, reason] of [
		[{ environmentId: "local", confirmed: true }, false, /trusted desktop/],
		[{ environmentId: "local" }, true, /confirmation/],
		[
			{ environmentId: "local", confirmed: true, architecture: "invalid" },
			true,
			/Unsupported IDA/,
		],
	] as const)
		await expect(
			handleCommand(context(), "setup_center_test_ida", args, {
				connection: connection(trusted),
			}),
		).rejects.toThrow(reason);
	expect(owned.start).not.toHaveBeenCalled();
	expect(owned.test).not.toHaveBeenCalled();
});
it("preserves actual IDA runtime failures rather than converting them into readiness", async () => {
	const { handleCommand } = await import("./commands");
	owned.test.mockRejectedValue(
		new Error("Actual IDA processor decompiler unavailable"),
	);
	await expect(
		handleCommand(
			context(),
			"setup_center_test_ida",
			{ environmentId: "local", confirmed: true },
			{ connection: connection(true) },
		),
	).rejects.toThrow("Actual IDA processor decompiler unavailable");
	expect(owned.test).toHaveBeenCalledTimes(1);
});
