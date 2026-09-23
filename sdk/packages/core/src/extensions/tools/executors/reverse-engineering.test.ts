import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createReverseEngineeringExecutor } from "./reverse-engineering";

const ZIP_WITH_TRAVERSAL =
	"UEsDBBQAAAAAAGIZN11H3dx5AgAAAAIAAAANAAAAc2FmZS9maWxlLnR4dG9rUEsDBBQAAAAAAGIZN10fKKpnAgAAAAIAAAANAAAALi4vZXNjYXBlLnR4dG5vUEsBAhQDFAAAAAAAYhk3XUfd3HkCAAAAAgAAAA0AAAAAAAAAAAAAAIABAAAAAHNhZmUvZmlsZS50eHRQSwECFAMUAAAAAABiGTddHyiqZwIAAAACAAAADQAAAAAAAAAAAAAAgAEtAAAALi4vZXNjYXBlLnR4dFBLBQYAAAAAAgACAHYAAABaAAAAAAA=";

const temporaryDirectories: string[] = [];

afterEach(async () => {
	await Promise.all(
		temporaryDirectories.splice(0).map((directory) =>
			fs.rm(directory, { recursive: true, force: true }),
		),
	);
});

describe("reverse-engineering discovery", () => {
	it("does not require a target path", async () => {
		const execute = createReverseEngineeringExecutor();
		const result = JSON.parse(
			await execute({ engine: "auto", operation: "discover" }, {} as never),
		);
		expect(result.capabilities.platform).toBe(process.platform);
		expect(result.capabilities).toHaveProperty("ghidra");
		expect(result.capabilities).toHaveProperty("ida");
	});
});

describe("reverse-engineering archive inspection", () => {
	it("reports traversal without extracting any entry", async () => {
		const directory = await fs.mkdtemp(path.join(os.tmpdir(), "cline-re-test-"));
		temporaryDirectories.push(directory);
		const target = path.join(directory, "sample.zip");
		await fs.writeFile(target, Buffer.from(ZIP_WITH_TRAVERSAL, "base64"));

		const execute = createReverseEngineeringExecutor();
		const result = JSON.parse(
			await execute(
				{ engine: "auto", operation: "inspect", target },
				{} as never,
			),
		);

		expect(result.archive.parsedEntries).toBe(2);
		expect(result.archive.findings.unsafePaths).toBe(1);
		expect(result.archive.extractionRecommended).toBe(false);
		expect(await fs.readdir(directory)).toEqual(["sample.zip"]);
	});

	it("extracts a clean ZIP into a private output directory", async () => {
		const directory = await fs.mkdtemp(path.join(os.tmpdir(), "cline-re-test-"));
		temporaryDirectories.push(directory);
		const target = path.join(directory, "sample.zip");
		const cleanZip =
			"UEsDBBQAAAAAAGIZN11H3dx5AgAAAAIAAAANAAAAc2FmZS9maWxlLnR4dG9rUEsBAhQDFAAAAAAAYhk3XUfd3HkCAAAAAgAAAA0AAAAAAAAAAAAAAIABAAAAAHNhZmUvZmlsZS50eHRQSwUGAAAAAAEAAQA7AAAALQAAAAAA";
		await fs.writeFile(target, Buffer.from(cleanZip, "base64"));
		const outputDirectory = path.join(directory, "output");

		const execute = createReverseEngineeringExecutor();
		const result = JSON.parse(
			await execute(
				{
					engine: "auto",
					operation: "extract",
					target,
					output_directory: outputDirectory,
				},
				{} as never,
			),
		);

		expect(result.extractedEntries).toBe(1);
		expect(await fs.readFile(path.join(outputDirectory, "safe", "file.txt"), "utf8")).toBe(
			"ok",
		);
	});

	it("inspects a non-ZIP binary without trying to parse a ZIP directory", async () => {
		const directory = await fs.mkdtemp(path.join(os.tmpdir(), "cline-re-test-"));
		temporaryDirectories.push(directory);
		const target = path.join(directory, "sample.bin");
		await fs.writeFile(target, Buffer.from([0x7f, 0x45, 0x4c, 0x46]));

		const execute = createReverseEngineeringExecutor();
		const result = JSON.parse(
			await execute(
				{ engine: "auto", operation: "inspect", target },
				{} as never,
			),
		);

		expect(result.format).toBe("binary");
		expect(result.archive).toBeUndefined();
	});
});
