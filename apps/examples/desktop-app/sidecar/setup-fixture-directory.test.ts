import { lstat, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createReverseEngineeringExecutor } from "@cline/core";
import { afterEach, expect, it, vi } from "vitest";
import { createSetupFixtureDirectory } from "./setup-fixture-directory";

const roots: string[] = [];
afterEach(async () => {
	vi.unstubAllEnvs();
	await Promise.all(
		roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
	);
});

it.each([
	"ida",
	"ghidra",
] as const)("creates a unique private %s fixture independently of the durable data directory", async (engine) => {
	vi.stubEnv("CLINE_DATA_DIR", resolve(".owned-data-outside-temporary-root"));
	const first = await createSetupFixtureDirectory(engine);
	const second = await createSetupFixtureDirectory(engine);
	roots.push(first, second);
	expect(first).not.toBe(second);
	expect(dirname(first)).toBe(await realpath(tmpdir()));
	expect(first).toContain(`cline-owned-${engine}-`);
	expect((await lstat(first)).isSymbolicLink()).toBe(false);
	if (process.platform !== "win32")
		expect((await lstat(first)).mode & 0o777).toBe(0o700);
});

it("rejects unknown fixture engines", async () => {
	await expect(createSetupFixtureDirectory("other" as "ida")).rejects.toThrow(
		"Unsupported setup fixture engine",
	);
});

it.each([
	"ida",
	"ghidra",
] as const)("uses the real executor output policy for %s fixture paths without external acknowledgement", async (engine) => {
	const root = await createSetupFixtureDirectory(engine);
	roots.push(root);
	const target = join(root, "owned.zip");
	await writeFile(
		target,
		Buffer.from(
			"UEsDBBQAAAAAAGIZN11H3dx5AgAAAAIAAAANAAAAc2FmZS9maWxlLnR4dG9rUEsBAhQDFAAAAAAAYhk3XUfd3HkCAAAAAgAAAA0AAAAAAAAAAAAAAIABAAAAAHNhZmUvZmlsZS50eHRQSwUGAAAAAAEAAQA7AAAALQAAAAAA",
			"base64",
		),
	);
	// The real executor's common output guard runs for extraction and decompilation.
	// No mock, selected third-party engine, external acknowledgement or target execution.
	const output = join(root, "analysis");
	const result = JSON.parse(
		await createReverseEngineeringExecutor()(
			{
				engine: "auto",
				operation: "extract",
				target,
				output_directory: output,
			},
			{} as never,
		),
	);
	expect(result.outputScope).toBe("managed");
	expect(await readFile(join(output, "safe", "file.txt"), "utf8")).toBe("ok");
});
