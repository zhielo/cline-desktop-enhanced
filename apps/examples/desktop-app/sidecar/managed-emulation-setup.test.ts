import { expect, it, vi } from "vitest";
const signals = vi.hoisted(() => [] as AbortSignal[]);
vi.mock("./managed-emulation-pack.mjs", async (original) => ({
	...(await original<typeof import("./managed-emulation-pack.mjs")>()),
	createManagedEmulationPack: () => ({
		install: (_selection: unknown, { signal }: { signal: AbortSignal }) => {
			signals.push(signal);
			return new Promise((_resolve, reject) =>
				signal.addEventListener("abort", () => reject(signal.reason), {
					once: true,
				}),
			);
		},
	}),
}));
it("cancellation is cooperative, installation-scoped and never leaks to a later operation", async () => {
	const { installManagedEmulationPack, cancelManagedEmulationInstall } =
		await import("./managed-emulation-setup");
	expect(() => cancelManagedEmulationInstall()).toThrow("No cancellable");
	const first = installManagedEmulationPack(["qiling"], () => {});
	await expect(
		installManagedEmulationPack(["unidbg"], () => {}),
	).rejects.toThrow("already running");
	expect(signals).toHaveLength(1);
	expect(cancelManagedEmulationInstall()).toEqual({
		cancellationRequested: true,
		completed: false,
	});
	await expect(first).rejects.toMatchObject({ name: "AbortError" });
	expect(() => cancelManagedEmulationInstall()).toThrow("No cancellable");
	const next = installManagedEmulationPack(["unidbg"], () => {});
	expect(signals).toHaveLength(2);
	expect(signals[1]!.aborted).toBe(false);
	cancelManagedEmulationInstall();
	await expect(next).rejects.toMatchObject({ name: "AbortError" });
});
