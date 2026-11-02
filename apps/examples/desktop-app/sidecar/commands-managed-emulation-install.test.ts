import { expect, it, vi } from "vitest";
import type { SidecarContext, SidecarWebSocketClient } from "./types";
const calls = vi.hoisted(() => ({
	install: vi.fn(async () => ({
		installed: ["qiling"],
		activation: "not-implemented",
	})),
	verify: vi.fn(async () => ({
		verified: ["qiling"],
		engineReadiness: "not-tested",
	})),
	status: vi.fn(async () => ({ available: false, engines: [] })),
	cancel: vi.fn(() => ({ cancellationRequested: true, completed: false })),
	job: null as null | { id: string; command: string; status: string },
}));
vi.mock("./managed-emulation-setup", () => ({
	installManagedEmulationPack: calls.install,
	verifyManagedEmulationPack: calls.verify,
	managedEmulationPackStatus: calls.status,
	cancelManagedEmulationInstall: calls.cancel,
}));
// Admission/recovery persistence has its own real-file suites. This test
// isolates the command's authority boundary and exact forwarded arguments.
vi.mock("./setup-jobs", async (original) => ({
	...(await original<typeof import("./setup-jobs")>()),
	getSetupJob: (id?: string) => (calls.job?.id === id ? calls.job : null),
	startSetupJob: (
		_command: string,
		_args: unknown,
		run: (phase: (value: string) => void) => Promise<unknown>,
	) => ({
		job: { id: "owned-test-job", status: "running" },
		completion: run(() => {}),
	}),
}));
it("install and verification require trusted explicit local confirmation, never accept paths or catalogs", async () => {
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
	for (const command of [
		"setup_center_emulation_install",
		"setup_center_emulation_verify_files",
	]) {
		calls.install.mockClear();
		calls.verify.mockClear();
		await expect(
			handleCommand(ctx, command, { confirmed: true }),
		).rejects.toThrow("trusted desktop");
		await expect(handleCommand(ctx, command, {}, trusted)).rejects.toThrow(
			"confirmation",
		);
		await expect(
			handleCommand(
				ctx,
				command,
				{ environmentId: "remote", confirmed: true },
				trusted,
			),
		).rejects.toThrow("local-only");
		expect(calls.install).not.toHaveBeenCalled();
		expect(calls.verify).not.toHaveBeenCalled();
		await handleCommand(
			ctx,
			command,
			{
				environmentId: "local",
				confirmed: true,
				engines: ["qiling"],
				catalog: "UNTRUSTED",
				sourceRoot: "UNTRUSTED",
				command: "DO NOT EXECUTE",
			},
			trusted,
		);
		expect(
			command.endsWith("_install") ? calls.install : calls.verify,
		).toHaveBeenCalledExactlyOnceWith(["qiling"], expect.any(Function));
	}
});
it("cancellation cannot affect a different, terminal, remote or untrusted setup operation", async () => {
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
	const command = "setup_center_emulation_cancel_install";
	const args = {
		environmentId: "local",
		confirmed: true,
		jobId: "11111111-1111-4111-8111-111111111111",
	};
	calls.cancel.mockClear();
	await expect(handleCommand(ctx, command, args)).rejects.toThrow(
		"trusted desktop",
	);
	await expect(
		handleCommand(ctx, command, { ...args, confirmed: false }, trusted),
	).rejects.toThrow("confirmation");
	await expect(
		handleCommand(ctx, command, { ...args, environmentId: "remote" }, trusted),
	).rejects.toThrow("local-only");
	for (const job of [
		null,
		{ id: args.jobId, command: "setup_center_install_full", status: "running" },
		{
			id: args.jobId,
			command: "setup_center_emulation_install",
			status: "completed",
		},
		{
			id: "22222222-2222-4222-8222-222222222222",
			command: "setup_center_emulation_install",
			status: "running",
		},
	]) {
		calls.job = job;
		await expect(handleCommand(ctx, command, args, trusted)).rejects.toThrow(
			"exact running",
		);
	}
	expect(calls.cancel).not.toHaveBeenCalled();
	calls.job = {
		id: args.jobId,
		command: "setup_center_emulation_install",
		status: "running",
	};
	await expect(
		handleCommand(ctx, command, args, trusted),
	).resolves.toMatchObject({ cancellationRequested: true, completed: false });
	expect(calls.cancel).toHaveBeenCalledExactlyOnceWith();
	calls.job = null;
});
