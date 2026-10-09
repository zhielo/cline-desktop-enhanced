import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { assertSetupIdle, getSetupJob, startSetupJob } from "./setup-jobs";
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
		await Promise.resolve();
		expect(operation).toHaveBeenCalledTimes(1);
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
