import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createReverseEngineeringExecutor } from "./reverse-engineering";

const ZIP_WITH_TRAVERSAL =
	"UEsDBBQAAAAAAGIZN11H3dx5AgAAAAIAAAANAAAAc2FmZS9maWxlLnR4dG9rUEsDBBQAAAAAAGIZN10fKKpnAgAAAAIAAAANAAAALi4vZXNjYXBlLnR4dG5vUEsBAhQDFAAAAAAAYhk3XUfd3HkCAAAAAgAAAA0AAAAAAAAAAAAAAIABAAAAAHNhZmUvZmlsZS50eHRQSwECFAMUAAAAAABiGTddHyiqZwIAAAACAAAADQAAAAAAAAAAAAAAgAEtAAAALi4vZXNjYXBlLnR4dFBLBQYAAAAAAgACAHYAAABaAAAAAAA=";

const temporaryDirectories: string[] = [];
const originalPath = process.env.PATH;
const originalCacheDirectory = process.env.CLINE_RE_CACHE_DIR;
const originalGhidraHome = process.env.GHIDRA_HOME;
const originalIdaHome = process.env.IDA_HOME;
const originalJadxHome = process.env.JADX_HOME;

afterEach(async () => {
	process.env.PATH = originalPath;
	if (originalCacheDirectory === undefined)
		delete process.env.CLINE_RE_CACHE_DIR;
	else process.env.CLINE_RE_CACHE_DIR = originalCacheDirectory;
	if (originalGhidraHome === undefined) delete process.env.GHIDRA_HOME;
	else process.env.GHIDRA_HOME = originalGhidraHome;
	if (originalIdaHome === undefined) delete process.env.IDA_HOME;
	else process.env.IDA_HOME = originalIdaHome;
	if (originalJadxHome === undefined) delete process.env.JADX_HOME;
	else process.env.JADX_HOME = originalJadxHome;
	await Promise.all(
		temporaryDirectories
			.splice(0)
			.map((directory) => fs.rm(directory, { recursive: true, force: true })),
	);
});

async function executable(directory: string, name: string, body: string) {
	const target = path.join(directory, name);
	await fs.mkdir(path.dirname(target), { recursive: true });
	await fs.writeFile(target, `#!/bin/sh\nset -eu\n${body}\n`);
	await fs.chmod(target, 0o700);
	return target;
}

describe("reverse-engineering discovery", () => {
	it("does not require a target path", async () => {
		const execute = createReverseEngineeringExecutor();
		const result = JSON.parse(
			await execute({ engine: "auto", operation: "discover" }, {} as never),
		);
		expect(result.capabilities.platform).toBe(process.platform);
		expect(result.capabilities).toHaveProperty("ghidra");
		expect(result.capabilities).toHaveProperty("ida");
		expect(result.capabilities).toHaveProperty("androidStudio.plugins");
		expect(result.capabilities).toHaveProperty("supplementalTools");
		expect(result.capabilities).toHaveProperty("toolSelectionGuide");
	});
});

describe("reverse-engineering archive inspection", () => {
	it("compares original and modified APK containers without extracting them", async () => {
		const directory = await fs.mkdtemp(
			path.join(os.tmpdir(), "cline-re-test-"),
		);
		temporaryDirectories.push(directory);
		const original = path.join(directory, "original.apk");
		const modified = path.join(directory, "modified.apk");
		const cleanZip =
			"UEsDBBQAAAAAAGIZN11H3dx5AgAAAAIAAAANAAAAc2FmZS9maWxlLnR4dG9rUEsBAhQDFAAAAAAAYhk3XUfd3HkCAAAAAgAAAA0AAAAAAAAAAAAAAIABAAAAAHNhZmUvZmlsZS50eHRQSwUGAAAAAAEAAQA7AAAALQAAAAAA";
		await fs.writeFile(original, Buffer.from(cleanZip, "base64"));
		await fs.writeFile(modified, Buffer.from(ZIP_WITH_TRAVERSAL, "base64"));

		const result = JSON.parse(
			await createReverseEngineeringExecutor()(
				{
					engine: "auto",
					operation: "compare_apks",
					target: original,
					compare_target: modified,
				},
				{} as never,
			),
		);

		expect(result.identicalFile).toBe(false);
		expect(result.summary).toMatchObject({
			originalEntries: 1,
			modifiedEntries: 2,
			added: 1,
			removed: 0,
		});
		expect(result.added).toEqual(["../escape.txt"]);
		expect(await fs.readdir(directory)).toEqual([
			"modified.apk",
			"original.apk",
		]);
	});

	it("reports traversal without extracting any entry", async () => {
		const directory = await fs.mkdtemp(
			path.join(os.tmpdir(), "cline-re-test-"),
		);
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
		const directory = await fs.mkdtemp(
			path.join(os.tmpdir(), "cline-re-test-"),
		);
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
		expect(
			await fs.readFile(path.join(outputDirectory, "safe", "file.txt"), "utf8"),
		).toBe("ok");
	});

	it("inspects a non-ZIP binary without trying to parse a ZIP directory", async () => {
		const directory = await fs.mkdtemp(
			path.join(os.tmpdir(), "cline-re-test-"),
		);
		temporaryDirectories.push(directory);
		const target = path.join(directory, "sample.bin");
		const elf = Buffer.alloc(32);
		elf.set([0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01]);
		elf.writeUInt16LE(0x0003, 18);
		elf.writeUInt32LE(0x8048000, 24);
		await fs.writeFile(target, elf);

		const execute = createReverseEngineeringExecutor();
		const result = JSON.parse(
			await execute(
				{ engine: "auto", operation: "inspect", target },
				{} as never,
			),
		);

		expect(result.format).toBe("elf");
		expect(result.bits).toBe(32);
		expect(result.archive).toBeUndefined();
	});

	it("returns structured PE architecture and entry-point metadata", async () => {
		const directory = await fs.mkdtemp(
			path.join(os.tmpdir(), "cline-re-test-"),
		);
		temporaryDirectories.push(directory);
		const target = path.join(directory, "sample.exe");
		const pe = Buffer.alloc(512);
		pe.write("MZ", 0, "ascii");
		pe.writeUInt32LE(0x80, 0x3c);
		pe.writeUInt32LE(0x00004550, 0x80);
		pe.writeUInt16LE(0x8664, 0x84);
		pe.writeUInt16LE(5, 0x86);
		pe.writeUInt16LE(0x20b, 0x98);
		pe.writeUInt32LE(0x1234, 0xa8);
		pe.writeBigUInt64LE(0x140000000n, 0xb0);
		await fs.writeFile(target, pe);

		const result = JSON.parse(
			await createReverseEngineeringExecutor()(
				{ engine: "auto", operation: "inspect", target },
				{} as never,
			),
		);

		expect(result.format).toBe("pe");
		expect(result.architecture).toBe("x86_64");
		expect(result.bits).toBe(64);
		expect(result.sectionCount).toBe(5);
		expect(result.entryPoint).toBe("0x1234");
		expect(result.imageBase).toBe("0x140000000");
	});

	it("extracts and classifies bounded security-relevant strings", async () => {
		const directory = await fs.mkdtemp(
			path.join(os.tmpdir(), "cline-re-test-"),
		);
		temporaryDirectories.push(directory);
		const target = path.join(directory, "classes.dex");
		await fs.writeFile(
			target,
			Buffer.from(
				"\u0000https://api.example.com/v1\u0000Lcom/example/Security;\u0000frida_detected\u0000",
				"latin1",
			),
		);

		const result = JSON.parse(
			await createReverseEngineeringExecutor()(
				{
					engine: "auto",
					operation: "scan_strings",
					target,
					min_string_length: 6,
				},
				{} as never,
			),
		);

		expect(result.results.map((item: { value: string }) => item.value)).toEqual(
			expect.arrayContaining([
				"https://api.example.com/v1",
				"Lcom/example/Security;",
				"frida_detected",
			]),
		);
		expect(result.categoryCounts).toMatchObject({
			url: 1,
			securityRelevant: 1,
		});
	});

	it("triages wrapped Dex and high-entropy payload indicators", async () => {
		const directory = await fs.mkdtemp(
			path.join(os.tmpdir(), "cline-re-test-"),
		);
		temporaryDirectories.push(directory);
		const target = path.join(directory, "classes.dex");
		const payload = Buffer.alloc(128 * 1024);
		for (let index = 0; index < payload.length; index += 1) {
			payload[index] = (index * 131 + (index >> 3) * 17) & 0xff;
		}
		await fs.writeFile(target, payload);

		const result = JSON.parse(
			await createReverseEngineeringExecutor()(
				{ engine: "auto", operation: "triage_obfuscation", target },
				{} as never,
			),
		);

		expect(result.assessment).toBe(
			"strong-obfuscation-or-protection-indicators",
		);
		expect(result.findings).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ kind: "wrapped-dex", severity: "high" }),
			]),
		);
		expect(result.recommendedNextSteps.join(" ")).toContain(
			"disassemble_smali",
		);
	});
});

describe("reverse-engineering Smali reading", () => {
	it("returns a complete method body including labels and instructions", async () => {
		const directory = await fs.mkdtemp(
			path.join(os.tmpdir(), "cline-re-smali-"),
		);
		temporaryDirectories.push(directory);
		const smaliPath = path.join(
			directory,
			"smali",
			"com",
			"example",
			"Main.smali",
		);
		await fs.mkdir(path.dirname(smaliPath), { recursive: true });
		await fs.writeFile(
			smaliPath,
			[
				".class public Lcom/example/Main;",
				".super Ljava/lang/Object;",
				"",
				".method public check(I)Z",
				"    .locals 1",
				"    if-lez p1, :deny",
				"    const/4 v0, 0x1",
				"    return v0",
				"    :deny",
				"    const/4 v0, 0x0",
				"    return v0",
				".end method",
			].join("\n"),
		);

		const result = JSON.parse(
			await createReverseEngineeringExecutor()(
				{
					engine: "auto",
					operation: "read_smali_method",
					target: directory,
					smali_class: "com.example.Main",
					smali_method: "check(I)Z",
				},
				{} as never,
			),
		);

		expect(result.signature).toContain("check(I)Z");
		expect(result.body).toContain("if-lez p1, :deny");
		expect(result.body).toContain(".end method");
		expect(result.truncated).toBe(false);

		const search = JSON.parse(
			await createReverseEngineeringExecutor()(
				{
					engine: "auto",
					operation: "search_smali",
					target: directory,
					smali_query: "if-lez",
					context_lines: 1,
				},
				{} as never,
			),
		);
		expect(search.matches).toHaveLength(1);
		expect(search.matches[0]).toMatchObject({
			method: "public check(I)Z",
			text: "    if-lez p1, :deny",
		});
	});
});

describe("reverse-engineering engine execution", () => {
	it("decompiles every eligible IDA function and preserves a reusable database", async () => {
		if (process.platform === "win32") return;
		const directory = await fs.mkdtemp(
			path.join(os.tmpdir(), "cline-re-test-"),
		);
		temporaryDirectories.push(directory);
		const bin = path.join(directory, "bin");
		await executable(bin, "idat64", 'printf "%s\\n" "$@"');
		process.env.PATH = `${bin}${path.delimiter}${originalPath ?? ""}`;
		const target = path.join(directory, "sample.bin");
		await fs.writeFile(target, "sample");
		const outputDirectory = path.join(directory, "analysis");

		const result = JSON.parse(
			await createReverseEngineeringExecutor()(
				{
					engine: "ida",
					operation: "decompile",
					target,
					output_directory: outputDirectory,
				},
				{} as never,
			),
		);

		expect(result.exitCode).toBe(0);
		expect(result.args).toContain(
			`-Ohexrays:${path.join(outputDirectory, "decompiled.c")}:ALL`,
		);
		expect(
			JSON.parse(
				await fs.readFile(
					path.join(outputDirectory, "cline-analysis.json"),
					"utf8",
				),
			).sha256,
		).toBe(result.sha256);
	});

	it("passes advanced bounded JADX options through structured arguments", async () => {
		if (process.platform === "win32") return;
		const directory = await fs.mkdtemp(
			path.join(os.tmpdir(), "cline-re-test-"),
		);
		temporaryDirectories.push(directory);
		const bin = path.join(directory, "bin");
		await executable(bin, "jadx", 'printf "%s\\n" "$@"');
		process.env.PATH = `${bin}${path.delimiter}${originalPath ?? ""}`;
		const target = path.join(directory, "sample.apk");
		await fs.writeFile(target, "sample");

		const result = JSON.parse(
			await createReverseEngineeringExecutor()(
				{
					engine: "jadx",
					operation: "decompile",
					target,
					output_directory: path.join(directory, "jadx-output"),
					jadx_mode: "fallback",
					jadx_threads: 3,
					jadx_single_class: "com.example.Main",
					jadx_output_format: "json",
					jadx_deobfuscate: true,
					jadx_call_graph: "json",
					jadx_no_resources: true,
				},
				{} as never,
			),
		);

		expect(result.args).toEqual(
			expect.arrayContaining([
				"--decompilation-mode",
				"fallback",
				"--threads-count",
				"3",
				"--single-class",
				"com.example.Main",
				"--output-format",
				"json",
				"--deobf",
				"--call-graph",
				"json",
				"--no-res",
			]),
		);
	});

	it("reuses a hash-keyed Ghidra project instead of importing twice", async () => {
		if (process.platform === "win32") return;
		const directory = await fs.mkdtemp(
			path.join(os.tmpdir(), "cline-re-test-"),
		);
		temporaryDirectories.push(directory);
		const ghidraHome = path.join(directory, "ghidra");
		await executable(
			path.join(ghidraHome, "support"),
			"analyzeHeadless",
			'mkdir -p "$1"; touch "$1/$2.gpr"; printf "%s\\n" "$@"',
		);
		process.env.GHIDRA_HOME = ghidraHome;
		const target = path.join(directory, "sample.bin");
		await fs.writeFile(target, "sample");
		const outputDirectory = path.join(directory, "ghidra-output");
		const execute = createReverseEngineeringExecutor();

		const first = JSON.parse(
			await execute(
				{
					engine: "ghidra",
					operation: "analyze",
					target,
					output_directory: outputDirectory,
					max_cpu: 2,
				},
				{} as never,
			),
		);
		const second = JSON.parse(
			await execute(
				{
					engine: "ghidra",
					operation: "analyze",
					target,
					output_directory: outputDirectory,
					max_cpu: 2,
				},
				{} as never,
			),
		);

		expect(first.reusedAnalysis).toBe(false);
		expect(first.args).toContain("-import");
		expect(first.args).toEqual(expect.arrayContaining(["-max-cpu", "2"]));
		expect(second.reusedAnalysis).toBe(true);
		expect(second.args).toContain("-process");
		expect(second.args).not.toContain("-import");
	});

	it("supports an editable APK-to-Smali-to-APK round trip", async () => {
		if (process.platform === "win32") return;
		const directory = await fs.mkdtemp(
			path.join(os.tmpdir(), "cline-re-test-"),
		);
		temporaryDirectories.push(directory);
		const bin = path.join(directory, "bin");
		await executable(
			bin,
			"apktool",
			`command="$1"; shift
output=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then output="$2"; shift 2; else shift; fi
done
if [ "$command" = "d" ]; then
  mkdir -p "$output/smali/com/example"
  printf '.class public Lcom/example/Main;\\n' > "$output/smali/com/example/Main.smali"
else
  printf 'rebuilt-apk' > "$output"
fi`,
		);
		await executable(
			bin,
			"smali",
			`shift
output=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then output="$2"; shift 2; else shift; fi
done
printf 'dex-output' > "$output"`,
		);
		process.env.PATH = `${bin}${path.delimiter}${originalPath ?? ""}`;
		const apk = path.join(directory, "sample.apk");
		await fs.writeFile(apk, "apk");
		const decoded = path.join(directory, "decoded");
		const rebuilt = path.join(directory, "rebuilt.apk");
		const assembledDex = path.join(directory, "classes.dex");
		const execute = createReverseEngineeringExecutor();

		const disassembled = JSON.parse(
			await execute(
				{
					engine: "auto",
					operation: "disassemble_smali",
					target: apk,
					output_directory: decoded,
				},
				{} as never,
			),
		);
		await fs.appendFile(
			path.join(decoded, "smali", "com", "example", "Main.smali"),
			"# edited\n",
		);
		const rebuiltResult = JSON.parse(
			await execute(
				{
					engine: "auto",
					operation: "rebuild_apk",
					target: decoded,
					output_file: rebuilt,
				},
				{} as never,
			),
		);
		const assembledResult = JSON.parse(
			await execute(
				{
					engine: "auto",
					operation: "assemble_smali",
					target: path.join(decoded, "smali"),
					output_file: assembledDex,
					smali_api_level: 35,
				},
				{} as never,
			),
		);

		expect(disassembled.exitCode).toBe(0);
		expect(disassembled.artifacts[0].path).toContain("Main.smali");
		expect(rebuiltResult.succeeded).toBe(true);
		expect(await fs.readFile(rebuilt, "utf8")).toBe("rebuilt-apk");
		expect(assembledResult.succeeded).toBe(true);
		expect(await fs.readFile(assembledDex, "utf8")).toBe("dex-output");
		expect(await fs.stat(`${decoded}.cline-analysis.json`)).toBeTruthy();
		await expect(
			fs.stat(path.join(decoded, "cline-analysis.json")),
		).rejects.toThrow();
	});
});
