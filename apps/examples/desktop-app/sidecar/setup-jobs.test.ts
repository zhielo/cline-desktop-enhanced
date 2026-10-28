import {
	mkdtemp,
	rm,
	writeFile,
	readFile,
	mkdir,
	lstat,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import {
	assertSetupIdle,
	getSetupJob,
	startSetupJob,
	inspectSetupRecovery,
	recoverSetupAfterReboot,
} from "./setup-jobs";
const io = vi.hoisted(() => ({ failRename: false }));
vi.mock("node:fs", async () => {
	const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
	return {
		...actual,
		renameSync: (...args: Parameters<typeof actual.renameSync>) => {
			if (io.failRename) throw new Error("Injected durable closure failure");
			return actual.renameSync(...args);
		},
	};
});
const boot = vi.hoisted(() => ({ read: vi.fn() }));
vi.mock("./setup-boot-identity", async () => ({
	...(await vi.importActual<typeof import("./setup-boot-identity")>(
		"./setup-boot-identity",
	)),
	readSetupBootIdentity: boot.read,
}));
const oldBoot = {
	schemaVersion: 1 as const,
	platform: "win32" as const,
	hostId: "a".repeat(64),
	bootId: "11111111-1111-1111-1111-111111111111",
};
const newBoot = { ...oldBoot, bootId: "22222222-2222-2222-2222-222222222222" };
boot.read.mockReturnValue(oldBoot);
it("returns immediate job identity, coalesces identical admission and permits read-only reconnect while setup continues", async () => {
	const root = await mkdtemp(join(tmpdir(), "setup-jobs-"));
	vi.stubEnv("CLINE_DATA_DIR", root);
	let finish!: () => void;
	const operation = vi.fn(async (phase) => {
		phase("Owned fixture stage");
		await new Promise<void>((resolve) => {
			finish = resolve;
		});
		return { receipt: "owned" };
	});
	try {
		const first = startSetupJob(
			"setup_center_install_full",
			{ confirmed: true, background: true },
			operation,
		);
		const duplicate = startSetupJob(
			"setup_center_install_full",
			{ confirmed: true },
			operation,
		);
		expect(duplicate.job.id).toBe(first.job.id);
		expect(duplicate.completion).toBe(first.completion);
		await vi.waitFor(() => expect(operation).toHaveBeenCalledTimes(1));
		expect(getSetupJob(first.job.id)?.phase).toBe("Owned fixture stage");
		expect(() =>
			startSetupJob("setup_center_rollback_core", {}, operation),
		).toThrow("different setup");
		expect(() => assertSetupIdle()).toThrow("admission lease");
		finish();
		await first.completion;
		expect(getSetupJob()?.status).toBe("completed");
		assertSetupIdle();
	} finally {
		vi.unstubAllEnvs();
		await rm(root, { recursive: true, force: true });
	}
});
it("preserves failed or interrupted host state without secrets or automatic replay", async () => {
	const root = await mkdtemp(join(tmpdir(), "setup-failed-"));
	vi.stubEnv("CLINE_DATA_DIR", root);
	try {
		const operation = vi.fn(async () => {
			throw new Error("API_KEY=private-token-value");
		});
		const first = startSetupJob("setup_center_test_full", {}, operation);
		await expect(first.completion).rejects.toThrow("API_KEY");
		expect(getSetupJob()?.status).toBe("failed");
		expect(getSetupJob()?.error).not.toContain("private-token-value");
		await writeFile(
			join(root, "setup-center", "latest-job.json"),
			JSON.stringify({ ...getSetupJob(), status: "running", hostPid: -1 }),
		);
		expect(getSetupJob()?.status).toBe("interrupted");
		expect(() => assertSetupIdle()).toThrow("interrupted");
		expect(operation).toHaveBeenCalledTimes(1);
	} finally {
		vi.unstubAllEnvs();
		await rm(root, { recursive: true, force: true });
	}
});
it("retains cross-process admission after unconfirmed subprocess termination instead of permitting a duplicate", async () => {
	const root = await mkdtemp(join(tmpdir(), "setup-uncertain-"));
	vi.stubEnv("CLINE_DATA_DIR", root);
	try {
		const first = startSetupJob("setup_center_test_ida", {}, async () => ({
			result: { outputDrainTimedOut: true },
		}));
		await first.completion;
		expect(getSetupJob()?.status).toBe("interrupted");
		expect(() => assertSetupIdle()).toThrow("admission lease");
		expect(() =>
			startSetupJob("setup_center_install_full", {}, async () => ({})),
		).toThrow("admission lease");
	} finally {
		vi.unstubAllEnvs();
		await rm(root, { recursive: true, force: true });
	}
});

async function retainedLease(root: string, identity: unknown = oldBoot) {
	const directory = join(root, "setup-center");
	await mkdir(directory, { recursive: true });
	const job = {
		id: "12345678-1234-1234-1234-123456789abc",
		command: "setup_center_test_full",
		identity: "x",
		hostPid: 1,
		status: "running",
		phase: "old",
		startedAt: new Date().toISOString(),
		updatedAt: new Date().toISOString(),
		bootIdentity: identity,
		recoveryScope: "native-host-only/v1",
	};
	await writeFile(
		join(directory, "setup-admission.json"),
		JSON.stringify({
			id: job.id,
			hostPid: 1,
			bootIdentity: identity,
			recoveryScope: "native-host-only/v1",
		}),
	);
	await writeFile(join(directory, `job-${job.id}.json`), JSON.stringify(job));
	await writeFile(join(directory, "latest-job.json"), JSON.stringify(job));
	return job;
}
it("recovers only the exact retained job after verified reboot without replay or readiness claims", async () => {
	const root = await mkdtemp(join(tmpdir(), "setup-recovery-"));
	vi.stubEnv("CLINE_DATA_DIR", root);
	boot.read.mockReturnValue(newBoot);
	try {
		const job = await retainedLease(root);
		expect(await inspectSetupRecovery()).toMatchObject({
			canRecover: true,
			jobId: job.id,
		});
		expect(getSetupJob()?.status).toBe("interrupted");
		const result = await recoverSetupAfterReboot(job.id);
		expect(result).toMatchObject({
			replayed: false,
			readinessEstablished: false,
			job: {
				status: "failed",
				recoveredAfterReboot: {
					fromBootId: oldBoot.bootId,
					toBootId: newBoot.bootId,
				},
			},
		});
		assertSetupIdle();
		await expect(
			lstat(join(root, "setup-center", "setup-admission.json")),
		).rejects.toThrow();
		expect(getSetupJob()?.status).toBe("failed");
	} finally {
		vi.unstubAllEnvs();
		boot.read.mockReturnValue(oldBoot);
		await rm(root, { recursive: true, force: true });
	}
});
it("refuses same boot, changed host, legacy, missing and mismatched evidence without changing the lease", async () => {
	for (const [stored, current] of [
		[oldBoot, oldBoot],
		[oldBoot, { ...newBoot, hostId: "b".repeat(64) }],
		[undefined, newBoot],
		[oldBoot, null],
	] as const) {
		const root = await mkdtemp(join(tmpdir(), "setup-recovery-blocked-"));
		vi.stubEnv("CLINE_DATA_DIR", root);
		boot.read.mockReturnValue(current);
		try {
			const job = await retainedLease(
				root,
				stored === undefined ? null : stored,
			);
			const path = join(root, "setup-center", "setup-admission.json"),
				before = await readFile(path, "utf8");
			expect((await inspectSetupRecovery()).canRecover).toBe(false);
			await expect(recoverSetupAfterReboot(job.id)).rejects.toThrow();
			expect(await readFile(path, "utf8")).toBe(before);
			expect(() => assertSetupIdle()).toThrow("admission");
		} finally {
			vi.unstubAllEnvs();
			await rm(root, { recursive: true, force: true });
		}
	}
	boot.read.mockReturnValue(oldBoot);
});
it("rejects stale job confirmation, conflicting records and recovery lock without releasing admission", async () => {
	const root = await mkdtemp(join(tmpdir(), "setup-recovery-race-"));
	vi.stubEnv("CLINE_DATA_DIR", root);
	boot.read.mockReturnValue(newBoot);
	try {
		const job = await retainedLease(root);
		await expect(
			recoverSetupAfterReboot("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
		).rejects.toThrow("changed");
		await writeFile(
			join(root, "setup-center", `job-${job.id}.json`),
			JSON.stringify({ ...job, bootIdentity: newBoot }),
		);
		await expect(recoverSetupAfterReboot(job.id)).rejects.toThrow("disagree");
		await writeFile(join(root, "setup-center", "setup-recovery.json"), "{}");
		expect(await inspectSetupRecovery()).toMatchObject({ canRecover: false });
		expect(() => assertSetupIdle()).toThrow("recovery");
		await expect(recoverSetupAfterReboot(job.id)).rejects.toThrow();
		expect(
			await readFile(
				join(root, "setup-center", "setup-admission.json"),
				"utf8",
			),
		).toContain(job.id);
	} finally {
		vi.unstubAllEnvs();
		boot.read.mockReturnValue(oldBoot);
		await rm(root, { recursive: true, force: true });
	}
});

it("does not treat host reboot as proof of remote, device or saved VM termination", async () => {
	const root = await mkdtemp(join(tmpdir(), "setup-recovery-domain-"));
	vi.stubEnv("CLINE_DATA_DIR", root);
	boot.read.mockReturnValue(newBoot);
	try {
		const job = await retainedLease(root);
		for (const command of [
			"setup_center_test_worker",
			"setup_center_test_device",
			"setup_center_install_emulation",
		]) {
			const changed = { ...job, command };
			await writeFile(
				join(root, "setup-center", `job-${job.id}.json`),
				JSON.stringify(changed),
			);
			await writeFile(
				join(root, "setup-center", "latest-job.json"),
				JSON.stringify(changed),
			);
			expect((await inspectSetupRecovery()).canRecover).toBe(false);
			await expect(recoverSetupAfterReboot(job.id)).rejects.toThrow(
				"Native-host-only",
			);
		}
	} finally {
		vi.unstubAllEnvs();
		boot.read.mockReturnValue(oldBoot);
		await rm(root, { recursive: true, force: true });
	}
});

it("retains admission if durable recovery closure cannot be persisted", async () => {
	const root = await mkdtemp(join(tmpdir(), "setup-recovery-durable-"));
	vi.stubEnv("CLINE_DATA_DIR", root);
	boot.read.mockReturnValue(newBoot);
	try {
		const job = await retainedLease(root),
			file = join(root, "setup-center", "setup-admission.json"),
			before = await readFile(file, "utf8");
		io.failRename = true;
		await expect(recoverSetupAfterReboot(job.id)).rejects.toThrow(
			"durable closure failure",
		);
		expect(await readFile(file, "utf8")).toBe(before);
		expect(getSetupJob()?.status).toBe("interrupted");
		expect(() => assertSetupIdle()).toThrow("admission lease");
	} finally {
		io.failRename = false;
		vi.unstubAllEnvs();
		boot.read.mockReturnValue(oldBoot);
		await rm(root, { recursive: true, force: true });
	}
});

it("returns admission immediately and keeps status responsive while boot evidence is pending", async () => {
	const root = await mkdtemp(join(tmpdir(), "setup-recovery-async-"));
	vi.stubEnv("CLINE_DATA_DIR", root);
	let release!: (value: typeof oldBoot) => void;
	boot.read.mockImplementationOnce(
		() =>
			new Promise((resolve) => {
				release = resolve;
			}),
	);
	try {
		vi.resetModules();
		const isolated = await import("./setup-jobs"),
			operation = vi.fn(async () => ({}));
		const accepted = isolated.startSetupJob(
			"setup_center_test_ghidra",
			{},
			operation,
		);
		expect(accepted.job.status).toBe("running");
		await vi.waitFor(() => expect(typeof release).toBe("function"));
		expect(operation).not.toHaveBeenCalled();
		expect(isolated.getSetupJob(accepted.job.id)?.status).toBe("running");
		expect(() => isolated.assertSetupIdle()).toThrow("admission lease");
		release(oldBoot);
		await accepted.completion;
		expect(operation).toHaveBeenCalledTimes(1);
		isolated.assertSetupIdle();
	} finally {
		vi.unstubAllEnvs();
		boot.read.mockReturnValue(oldBoot);
		await rm(root, { recursive: true, force: true });
	}
});
