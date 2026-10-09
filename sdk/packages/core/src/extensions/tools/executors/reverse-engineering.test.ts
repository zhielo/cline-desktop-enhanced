import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	createReverseEngineeringExecutor,
	shouldRefreshEngineEnvironment,
} from "./reverse-engineering";
import * as supervisedProcess from "./supervised-process";
import * as windowsEnvironment from "./windows-tool-environment";

const ZIP_WITH_TRAVERSAL =
	"UEsDBBQAAAAAAGIZN11H3dx5AgAAAAIAAAANAAAAc2FmZS9maWxlLnR4dG9rUEsDBBQAAAAAAGIZN10fKKpnAgAAAAIAAAANAAAALi4vZXNjYXBlLnR4dG5vUEsBAhQDFAAAAAAAYhk3XUfd3HkCAAAAAgAAAA0AAAAAAAAAAAAAAIABAAAAAHNhZmUvZmlsZS50eHRQSwECFAMUAAAAAABiGTddHyiqZwIAAAACAAAADQAAAAAAAAAAAAAAgAEtAAAALi4vZXNjYXBlLnR4dFBLBQYAAAAAAgACAHYAAABaAAAAAAA=";

const temporaryDirectories: string[] = [];
const originalPath = process.env.PATH;
const originalCacheDirectory = process.env.CLINE_RE_CACHE_DIR;
const originalGhidraHome = process.env.GHIDRA_HOME;
const originalIdaHome = process.env.IDA_HOME;
const originalJadxHome = process.env.JADX_HOME;

afterEach(async () => {
	vi.restoreAllMocks();
	vi.unstubAllEnvs();
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

		const registry = vi
			.spyOn(windowsEnvironment, "readWindowsRegistryValue")
			.mockRejectedValue(
				new Error("File-only comparison must not query the registry"),
			);
		const discovery = vi
			.spyOn(supervisedProcess, "commandAvailable")
			.mockRejectedValue(
				new Error("File-only comparison must not discover external tools"),
			);
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

		expect(registry).not.toHaveBeenCalled();
		expect(discovery).not.toHaveBeenCalled();
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

	it("requires acknowledgement for output outside managed roots", async () => {
		const directory = await fs.mkdtemp(
			path.join(os.tmpdir(), "cline-re-test-"),
		);
		temporaryDirectories.push(directory);
		const target = path.join(directory, "sample.zip");
		const cleanZip =
			"UEsDBBQAAAAAAGIZN11H3dx5AgAAAAIAAAANAAAAc2FmZS9maWxlLnR4dG9rUEsBAhQDFAAAAAAAYhk3XUfd3HkCAAAAAgAAAA0AAAAAAAAAAAAAAIABAAAAAHNhZmUvZmlsZS50eHRQSwUGAAAAAAEAAQA7AAAALQAAAAAA";
		await fs.writeFile(target, Buffer.from(cleanZip, "base64"));
		const outputDirectory = path.join(
			process.cwd(),
			`.cline-re-external-${process.pid}-${Date.now()}`,
		);
		temporaryDirectories.push(outputDirectory);
		const execute = createReverseEngineeringExecutor();
		await expect(
			execute(
				{
					engine: "auto",
					operation: "extract",
					target,
					output_directory: outputDirectory,
				},
				{} as never,
			),
		).rejects.toThrow("acknowledge_external_output=true");
		const approved = JSON.parse(
			await execute(
				{
					engine: "auto",
					operation: "extract",
					target,
					output_directory: outputDirectory,
					acknowledge_external_output: true,
				},
				{} as never,
			),
		);
		expect(approved.outputScope).toBe("external-approved");
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
		const literal = JSON.parse(
			await createReverseEngineeringExecutor()(
				{
					engine: "auto",
					operation: "scan_strings",
					target,
					string_pattern: "https?://",
				},
				{} as never,
			),
		);
		expect(literal.patternMode).toBe("literal");
		expect(literal.results).toHaveLength(0);
		const regex = JSON.parse(
			await createReverseEngineeringExecutor()(
				{
					engine: "auto",
					operation: "scan_strings",
					target,
					string_pattern: "https?://",
					string_pattern_regex: true,
				},
				{} as never,
			),
		);
		expect(regex.patternMode).toBe("regex");
		expect(regex.results).toHaveLength(1);
	});
});

describe("advanced forensic reports", () => {
	it("writes resumable JSON and HTML reports with hashed evidence", async () => {
		const directory = await fs.mkdtemp(
			path.join(os.tmpdir(), "cline-forensic-report-"),
		);
		temporaryDirectories.push(directory);
		const target = path.join(directory, "sample.bin");
		await fs.writeFile(
			target,
			Buffer.from(
				"\u0000https://api.example.com\u0000debug_token\u0000",
				"latin1",
			),
		);
		const execute = createReverseEngineeringExecutor();
		const jsonPath = path.join(directory, "report.json");
		const first = JSON.parse(
			await execute(
				{
					engine: "auto",
					operation: "forensic_report",
					target,
					report_output_file: jsonPath,
				},
				{} as never,
			),
		);
		expect(first.completedStages).toEqual(
			expect.arrayContaining(["inspection", "strings"]),
		);
		expect(first.artifact.sha256).toMatch(/^[a-f0-9]{64}$/);
		const report = JSON.parse(await fs.readFile(jsonPath, "utf8"));
		expect(report.stringIndicators.categoryCounts).toMatchObject({
			url: 1,
			securityRelevant: 1,
		});
		const resumed = JSON.parse(
			await execute(
				{
					engine: "auto",
					operation: "forensic_report",
					target,
					report_output_file: jsonPath,
				},
				{} as never,
			),
		);
		expect(resumed.resumed).toBe(true);
		const htmlPath = path.join(directory, "report.html");
		await execute(
			{
				engine: "auto",
				operation: "forensic_report",
				target,
				report_format: "html",
				report_output_file: htmlPath,
			},
			{} as never,
		);
		expect(await fs.readFile(htmlPath, "utf8")).toContain(
			"Forensic analysis report",
		);
	});

	it("combines APK structure, signature, and manifest security evidence", async () => {
		if (process.platform === "win32") return;
		const directory = await fs.mkdtemp(
			path.join(os.tmpdir(), "cline-apk-report-"),
		);
		temporaryDirectories.push(directory);
		const bin = path.join(directory, "bin");
		await executable(
			bin,
			"apksigner",
			"printf 'Verified using v2 scheme (APK Signature Scheme v2): true\\nSigner #1 certificate SHA-256 digest: aa\\n'",
		);
		await executable(
			bin,
			"aapt2",
			"printf 'E: manifest\\nA: android:name=\"android.permission.INTERNET\"\\nA: android:exported=true\\n'",
		);
		process.env.PATH = `${bin}${path.delimiter}${originalPath ?? ""}`;
		const target = path.join(directory, "sample.apk");
		await fs.writeFile(target, Buffer.from(ZIP_WITH_TRAVERSAL, "base64"));
		const result = JSON.parse(
			await createReverseEngineeringExecutor()(
				{
					engine: "auto",
					operation: "apk_security_report",
					target,
				},
				{} as never,
			),
		);
		const report = JSON.parse(await fs.readFile(result.reportFile, "utf8"));
		expect(report.apkSecurity.signature.verified).toBe(true);
		expect(report.apkSecurity.signature.schemes.v2).toBe(true);
		expect(report.apkSecurity.manifest.permissions).toContain(
			"android.permission.INTERNET",
		);
		expect(report.apkSecurity.manifest.exportedSignals).toBe(1);
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
		await expect(
			createReverseEngineeringExecutor()(
				{
					engine: "auto",
					operation: "search_smali",
					target: directory,
					smali_query: "(a+)+$",
					smali_regex: true,
				},
				{} as never,
			),
		).rejects.toThrow("nested quantifier");
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
		await executable(
			bin,
			"idat64",
			`for arg in "$@"; do
  case "$arg" in
    -o*) printf 'owned packed DB\n' > "\${arg#-o}" ;;
    -S*)
      script="\${arg#-S}"
      output="$(sed -n 's/^OUTPUT_PATH = "\\(.*\\)"$/\\1/p' "$script")"
      mkdir -p "$(dirname "$output")"
      printf 'int recovered(void) { return 1; }\\n' > "$output"
      ;;
  esac
done
printf "%s\\n" "$@"`,
		);
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
		expect(result.succeeded).toBe(true);
		expect(result.artifactVerified).toBe(true);
		expect(
			result.args.some((argument: string) => argument.startsWith("-Ohexrays")),
		).toBe(false);
		const scriptArgument = result.args.find((argument: string) =>
			argument.startsWith("-S"),
		);
		expect(scriptArgument).toBeDefined();
		const scriptPath = scriptArgument.slice(2).replace(/^"|"$/g, "");
		const scriptSource = await fs.readFile(scriptPath, "utf8");
		expect(scriptSource).toContain("ida_hexrays.decompile(function)");
		expect(scriptSource).toContain("idc.qexit(exit_code)");
		expect(
			await fs.readFile(
				path.join(result.outputDirectory, "decompiled.c"),
				"utf8",
			),
		).toContain("int recovered");
		expect(
			result.artifacts.find(
				(artifact: { path: string }) => artifact.path === "decompiled.c",
			).sha256,
		).toMatch(/^[a-f0-9]{64}$/);
		expect(
			JSON.parse(
				await fs.readFile(
					path.join(result.outputDirectory, "cline-analysis.json"),
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
		await fs.appendFile(
			path.join(ghidraHome, "support", "analyzeHeadless"),
			"\n# executable identity changed\n",
		);
		const changed = JSON.parse(
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
		expect(changed.reusedAnalysis).toBe(false);
		expect(changed.args).toContain("-import");
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

describe("targeted adapter routing (mock engines, not real decompilation)", () => {
	it("passes exact Ghidra selector as separate base64 data and invalidates reuse on change", async () => {
		if (process.platform === "win32") return;
		const dir = await fs.mkdtemp(path.join(os.tmpdir(), "target-adapter-"));
		temporaryDirectories.push(dir);
		const home = path.join(dir, "ghidra");
		await executable(
			path.join(home, "support"),
			"analyzeHeadless",
			`mkdir -p "$1"; touch "$1/$2.gpr"
while [ "$#" -gt 0 ]; do
 if [ "$1" = "-postScript" ]; then shift 2; printf '/* mock selected */' > "$1"; break; else shift; fi
done`,
		);
		process.env.GHIDRA_HOME = home;
		const target = path.join(dir, "owned.bin");
		await fs.writeFile(target, "owned");
		const execute = createReverseEngineeringExecutor();
		const run = async (symbol: string) =>
			JSON.parse(
				await execute(
					{
						engine: "ghidra",
						operation: "decompile",
						target,
						output_directory: path.join(dir, "out"),
						function_selector: { symbol },
					},
					{} as never,
				),
			);
		const first = await run("chosen");
		expect(first.args).toEqual(
			expect.arrayContaining([
				"ClineDecompileSelected.java",
				"symbol",
				Buffer.from("chosen").toString("base64"),
			]),
		);
		expect(first.succeeded).toBe(true);
		const same = await run("chosen");
		expect(same.reusedAnalysis).toBe(true);
		const changed = await run("different");
		expect(changed.reusedAnalysis).toBe(false);
	});
	it("writes exact IDA selector into a fixed script without enabling arbitrary scripts", async () => {
		if (process.platform === "win32") return;
		const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ida-selected-"));
		temporaryDirectories.push(dir);
		const bin = path.join(dir, "bin");
		await executable(bin, "idat64", 'printf "%s\\n" "$@"');
		process.env.PATH = `${bin}${path.delimiter}${originalPath ?? ""}`;
		const target = path.join(dir, "owned.bin");
		await fs.writeFile(target, "owned");
		const result = JSON.parse(
			await createReverseEngineeringExecutor()(
				{
					engine: "ida",
					operation: "decompile",
					target,
					output_directory: path.join(dir, "out"),
					function_selector: { address: "0x1000" },
				},
				{} as never,
			),
		);
		const arg = result.args.find((a: string) => a.startsWith("-S"));
		const source = await fs.readFile(
			arg.slice(2).replace(/^"|"$/g, ""),
			"utf8",
		);
		expect(source).toContain('SELECTOR = {"address":"0x1000"}');
		expect(source).toContain("function.start_ea==address");
		expect(result.succeeded).toBe(false);
	});
	it("separates cached JADX analyses by selected class", async () => {
		if (process.platform === "win32") return;
		const dir = await fs.mkdtemp(path.join(os.tmpdir(), "jadx-class-cache-"));
		temporaryDirectories.push(dir);
		const bin = path.join(dir, "bin");
		await executable(
			bin,
			"jadx",
			`while [ "$#" -gt 0 ]; do
 if [ "$1" = "-d" ]; then mkdir -p "$2"; printf '/* mock class */' > "$2/decompiled.c"; fi
 shift
done`,
		);
		process.env.PATH = `${bin}${path.delimiter}${originalPath ?? ""}`;
		const target = path.join(dir, "owned.apk");
		await fs.writeFile(target, "owned");
		const execute = createReverseEngineeringExecutor();
		const out = path.join(dir, "out");
		const run = async (name: string) => {
			await execute(
				{
					engine: "jadx",
					operation: "decompile",
					target,
					output_directory: out,
					jadx_single_class: name,
				},
				{} as never,
			);
			return JSON.parse(
				await fs.readFile(path.join(out, "cline-analysis.json"), "utf8"),
			).analysisOptionsHash;
		};
		expect(await run("example.First")).not.toBe(await run("example.Second"));
	});
});

it.each([
	{
		engine: "auto",
		operation: "inspect",
		managed_worker: true,
		confirm_managed_worker: true,
	},
	{
		engine: "ghidra",
		operation: "decompile",
		managed_worker: true,
		function_selector: { address: "0x10" },
	},
	{
		engine: "ghidra",
		operation: "decompile",
		managed_worker: true,
		confirm_managed_worker: true,
		function_selector: { address: "0x10" },
		script_path: "/untrusted.py",
	},
	{
		engine: "jadx",
		operation: "decompile",
		managed_worker: true,
		confirm_managed_worker: true,
		function_selector: { address: "0x10" },
	},
])("rejects invalid managed-worker mode before discovery or engine execution: %j", async (request) => {
	await expect(
		createReverseEngineeringExecutor()(
			request as never,
			{ sessionId: "owned-session" } as never,
		),
	).rejects.toThrow("Managed workers require");
});

it.each([
	{
		engine: "auto",
		operation: "project_edit",
		project_edit: { mode: "preview" },
		function_selector: { address: "0x10" },
	},
	{
		engine: "ghidra",
		operation: "project_edit",
		project_edit: { mode: "preview" },
	},
	{
		engine: "ghidra",
		operation: "project_edit",
		project_edit: { mode: "preview" },
		function_selector: { address: "0x10" },
		script_path: "/untrusted.py",
	},
	{ engine: "ghidra", operation: "inspect", project_edit: { mode: "preview" } },
])("rejects unsafe native edit envelopes before discovery: %j", async (request) => {
	await expect(
		createReverseEngineeringExecutor()(
			request as never,
			{ sessionId: "owned-session" } as never,
		),
	).rejects.toThrow(/Native project edits require|project_edit data/);
});

it("explicit desktop IDA selection wins over registry refresh and never falls back to another executable", async () => {
	const selected = await fs.mkdtemp(path.join(os.tmpdir(), "ida-explicit-"));
	temporaryDirectories.push(selected);
	vi.stubEnv("CLINE_IDA_SELECTED_HOME", selected);
	expect(shouldRefreshEngineEnvironment("IDA_HOME")).toBe(false);
	expect(shouldRefreshEngineEnvironment("IDADIR")).toBe(false);
	expect(shouldRefreshEngineEnvironment("GHIDRA_HOME")).toBe(true);
	vi.spyOn(supervisedProcess, "commandAvailable").mockImplementation(
		async (command) => /^idat(?:64)?(?:\.exe)?$/i.test(command),
	);
	vi.spyOn(supervisedProcess, "runSupervised").mockResolvedValue({
		exitCode: 0,
		stdout: "owned fixture",
		stderr: "",
		timedOut: false,
		cancelled: false,
	});
	const result = JSON.parse(
		await createReverseEngineeringExecutor()(
			{ engine: "ida", operation: "discover", discovery_depth: "fast" },
			{} as never,
		),
	);
	expect(result.capabilities.ida.headless).toBeUndefined();
	expect(supervisedProcess.commandAvailable).not.toHaveBeenCalledWith(
		process.platform === "win32" ? "idat64.exe" : "idat64",
	);
});

it("uses a fixed analyze lifecycle, isolates fresh attempts and reuses IDA databases across changed function selectors", async () => {
	const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ida-lifecycle-"));
	temporaryDirectories.push(dir);
	const home = path.join(dir, "ida");
	await fs.mkdir(home);
	const command = path.join(
		home,
		process.platform === "win32" ? "idat.exe" : "idat",
	);
	await fs.writeFile(command, "owned executable identity");
	await fs.writeFile(
		path.join(home, "hexarm64.dll"),
		"owned fixture plugin marker",
	);
	await fs.chmod(command, 0o700);
	vi.stubEnv("CLINE_IDA_SELECTED_HOME", home);
	vi.stubEnv("CLINE_DATA_DIR", path.join(dir, "data"));
	vi.spyOn(windowsEnvironment, "readWindowsRegistryValue").mockResolvedValue(
		undefined,
	);
	vi.spyOn(supervisedProcess, "commandAvailable").mockImplementation(
		async (value) => value === command,
	);
	const sources: string[] = [];
	vi.spyOn(supervisedProcess, "runSupervised").mockImplementation(
		async (_cmd, args, _timeout, _signal, spawn, env) => {
			if (args.includes("-A")) {
				spawn?.(12345);
				const scriptArg = args.find((value) => value.startsWith("-S"))!;
				const scriptFile = scriptArg.slice(2).replace(/^"|"$/g, "");
				sources.push(await fs.readFile(scriptFile, "utf8"));
				const attempt = path.dirname(scriptFile);
				await fs.writeFile(
					path.join(attempt, "analysis.i64"),
					"owned packed database",
				);
				if (scriptFile.includes("decompile"))
					await fs.writeFile(
						path.join(attempt, "decompiled.c"),
						sources.at(-1)!,
					);
				if (env?.CLINE_IDA_PROGRESS_PATH)
					await fs.writeFile(
						env.CLINE_IDA_PROGRESS_PATH,
						'{"phase":"database-saved"}\n{"phase":"script-exiting"}\n',
					);
			}
			return {
				exitCode: 0,
				stdout: "IDA owned mock 9.1",
				stderr: "",
				timedOut: false,
				cancelled: false,
			};
		},
	);
	const target = path.join(dir, "owned.bin");
	await fs.writeFile(target, "owned target");
	const execute = createReverseEngineeringExecutor();
	const request = {
		engine: "ida" as const,
		target,
		output_directory: path.join(dir, "out"),
		timeout_ms: 10000,
	};
	const analyze = JSON.parse(
		await execute({ ...request, operation: "analyze" }, {} as never),
	);
	expect(analyze.succeeded).toBe(true);
	expect(sources[0]).toContain("ida_auto.auto_wait()");
	expect(sources[0]).toContain("save_database");
	expect(sources[0]).toContain("idc.qexit(exit_code)");
	expect(sources[0]).not.toContain("ida_hexrays");
	const first = JSON.parse(
		await execute(
			{
				...request,
				operation: "decompile",
				function_selector: { address: "0x1000" },
			},
			{} as never,
		),
	);
	const changed = JSON.parse(
		await execute(
			{
				...request,
				operation: "decompile",
				function_selector: { address: "0x2000" },
			},
			{} as never,
		),
	);
	expect(first.reusedAnalysis).toBe(true);
	expect(changed.reusedAnalysis).toBe(true);
	expect(changed.args.some((value: string) => value.startsWith("-o"))).toBe(
		false,
	);
	expect(changed.outputDirectory).not.toBe(first.outputDirectory);
	expect(sources.at(-1)).toContain('"address":"0x2000"');
	const fresh = JSON.parse(
		await execute(
			{ ...request, operation: "analyze", reuse_analysis: false },
			{} as never,
		),
	);
	expect(fresh.reusedAnalysis).toBe(false);
	expect(fresh.outputDirectory).not.toBe(changed.outputDirectory);
	expect(
		await fs.readFile(path.join(first.outputDirectory, "analysis.i64"), "utf8"),
	).toBe("owned packed database");
});
