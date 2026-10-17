import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { disassembleDexDirectory } from "./dex-directory";

let root: string;
beforeEach(async () => {
	root = await fs.mkdtemp(path.join(os.tmpdir(), "cline-dex-batch-"));
});
afterEach(async () => {
	await fs.rm(root, { recursive: true, force: true });
});
it("orders top-level DEX files deterministically and reuses the existing child executor", async () => {
	await fs.writeFile(path.join(root, "classes2.dex"), "owned");
	await fs.writeFile(path.join(root, "classes.dex"), "owned");
	await fs.mkdir(path.join(root, "nested"));
	await fs.writeFile(path.join(root, "nested", "hidden.dex"), "owned");
	const run = vi.fn().mockResolvedValue({
		succeeded: true,
		sha256: "a".repeat(64),
		outputDirectory: "/managed/decoded",
	});
	const result = await disassembleDexDirectory({ target: root }, run);
	expect(result.status).toBe("completed");
	expect(result.results.map((item) => item.file)).toEqual([
		"classes.dex",
		"classes2.dex",
	]);
	expect(run).toHaveBeenCalledTimes(2);
	expect(run.mock.calls[0][0]).toMatchObject({
		operation: "disassemble_smali",
		engine: "auto",
	});
});
it("stops after failure and reports skipped files truthfully", async () => {
	for (const file of ["a.dex", "b.dex"])
		await fs.writeFile(path.join(root, file), "owned");
	const run = vi.fn().mockResolvedValue({ succeeded: false });
	const result = await disassembleDexDirectory({ target: root }, run);
	expect(result.status).toBe("partial");
	expect(result.skipped).toEqual(["b.dex"]);
	expect(run).toHaveBeenCalledTimes(1);
});
it("rejects oversized inventory before executing anything", async () => {
	for (let i = 0; i < 33; i++)
		await fs.writeFile(path.join(root, `${i}.dex`), "owned");
	const run = vi.fn();
	await expect(disassembleDexDirectory({ target: root }, run)).rejects.toThrow(
		"32-file",
	);
	expect(run).not.toHaveBeenCalled();
});
it("rejects external output and empty inventory", async () => {
	const run = vi.fn();
	await expect(
		disassembleDexDirectory(
			{ target: root, output_directory: path.join(root, "out") },
			run,
		),
	).rejects.toThrow("managed");
	await expect(disassembleDexDirectory({ target: root }, run)).rejects.toThrow(
		"No top-level",
	);
	expect(run).not.toHaveBeenCalled();
});
it("honors cancellation without dispatching a child", async () => {
	await fs.writeFile(path.join(root, "a.dex"), "owned");
	const controller = new AbortController();
	controller.abort();
	const run = vi.fn();
	await expect(
		disassembleDexDirectory({ target: root }, run, controller.signal),
	).rejects.toThrow();
	expect(run).not.toHaveBeenCalled();
});
it.skipIf(process.platform === "win32")(
	"rejects symlinked inputs",
	async () => {
		await fs.writeFile(path.join(root, "a.dex"), "owned");
		await fs.symlink(path.join(root, "a.dex"), path.join(root, "b.dex"));
		const run = vi.fn();
		await expect(
			disassembleDexDirectory({ target: root }, run),
		).rejects.toThrow("Symlink");
		expect(run).not.toHaveBeenCalled();
	},
);

it("does not dispatch a file whose inventory size changed", async () => {
	await fs.writeFile(path.join(root, "a.dex"), "owned");
	await fs.writeFile(path.join(root, "b.dex"), "owned");
	const run = vi.fn().mockImplementation(async () => {
		await fs.appendFile(path.join(root, "b.dex"), "changed");
		return { succeeded: true };
	});
	const result = await disassembleDexDirectory({ target: root }, run);
	expect(result.status).toBe("partial");
	expect(run).toHaveBeenCalledTimes(1);
});
it("reports cancellation even when a child returns a cached success after abort", async () => {
	await fs.writeFile(path.join(root, "a.dex"), "owned");
	const controller = new AbortController();
	const result = await disassembleDexDirectory(
		{ target: root },
		async () => {
			controller.abort();
			return { reusedAnalysis: true };
		},
		controller.signal,
	);
	expect(result.status).toBe("cancelled");
});
