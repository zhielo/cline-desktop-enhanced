import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import {
	digestFile,
	androidChildEnvironment,
	androidCommandIdentity,
	bundledAndroidTool,
	runAndroidTool,
	verifyAndroidToolchain,
} from "./android-toolchain";
import * as processTools from "./supervised-process";
vi.mock("node:fs/promises", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs/promises")>();
	return { ...actual, open: vi.fn(actual.open) };
});
const directories: string[] = [];
afterEach(async () => {
	vi.restoreAllMocks();
	vi.unstubAllEnvs();
	for (const d of directories.splice(0))
		await fs.rm(d, { recursive: true, force: true });
});
async function pack() {
	const root = await fs.mkdtemp(path.join(os.tmpdir(), "owned Android pack "));
	directories.push(root);
	const files: Record<string, string> = {};
	for (const name of [
		process.platform === "win32" ? "jre/bin/java.exe" : "jre/bin/java",
		"tools.lock.json",
		"launcher/ClineAndroidLauncher.class",
		process.platform === "win32" ? "jre/bin/keytool.exe" : "jre/bin/keytool",
		"apktool.jar",
		"smali/lib/smali-3.0.10.jar",
		"smali/lib/smali-baksmali-3.0.10.jar",
		"jadx/lib/jadx-1.5.6-all.jar",
		"bundletool.jar",
		"build-tools/lib/apksigner.jar",
		"build-tools/zipalign.exe",
		"build-tools/aapt2.exe",
		"build-tools/dexdump.exe",
	]) {
		await fs.mkdir(path.dirname(path.join(root, name)), { recursive: true });
		await fs.writeFile(path.join(root, name), "owned");
		files[name] = createHash("sha256").update("owned").digest("hex");
	}
	await fs.writeFile(
		path.join(root, "manifest.json"),
		JSON.stringify({
			schemaVersion: 1,
			profile: "cline-android-toolchain/1",
			files,
		}),
	);
	vi.stubEnv("CLINE_ANDROID_TOOLCHAIN_ROOT", root);
	return root;
}
it("distinguishes presence/integrity from actual execution and rejects tamper", async () => {
	const root = await pack();
	expect((await verifyAndroidToolchain()).identity).toMatch(/^[a-f0-9]{64}$/);
	await fs.appendFile(path.join(root, "apktool.jar"), "tamper");
	await expect(bundledAndroidTool("apktool")).rejects.toThrow("integrity");
});
it("rejects untracked classpath jars instead of executing them", async () => {
	const root = await pack();
	await fs.writeFile(path.join(root, "smali/lib/injected.jar"), "bad");
	await expect(verifyAndroidToolchain()).rejects.toThrow("Untracked");
});
it("rejects traversal manifest entries and symlinks", async () => {
	const root = await pack();
	const file = path.join(root, "manifest.json"),
		manifest = JSON.parse(await fs.readFile(file, "utf8"));
	manifest.files["../outside"] = "0".repeat(64);
	await fs.writeFile(file, JSON.stringify(manifest));
	await expect(verifyAndroidToolchain()).rejects.toThrow(
		"Invalid Android manifest path",
	);
});
it("uses literal Java argument arrays with no shell or injected Java environment", async () => {
	const root = await pack();
	vi.stubEnv("PROCESSOR_ARCHITECTURE", "AMD64");
	vi.stubEnv("PROCESSOR_ARCHITEW6432", "AMD64");
	vi.stubEnv("JAVA_TOOL_OPTIONS", "-javaagent:untrusted.jar");
	vi.stubEnv("JDK_JAVA_OPTIONS", "untrusted");
	vi.stubEnv("CLASSPATH", "untrusted");
	vi.stubEnv("CLINE_ANDROID_TEST_STORE_PASSWORD", "private");
	const run = vi.spyOn(processTools, "runSupervised").mockResolvedValue({
		exitCode: 0,
		stdout: "",
		stderr: "",
		timedOut: false,
		cancelled: false,
	});
	await runAndroidTool(
		path.join(root, "smali/lib/smali-3.0.10.jar"),
		["assemble", "C:/space & literal/输入"],
		1000,
	);
	expect(run.mock.calls[0][1]).toContain(
		`u:${Buffer.from("C:/space & literal/输入", "utf8").toString("base64")}`,
	);
	expect(
		run.mock.calls[0][1].every((arg) =>
			Array.from(arg).every((char) => char.charCodeAt(0) <= 127),
		),
	).toBe(true);
	expect(run.mock.calls[0][7]).toBe(root);
	expect(run.mock.calls[0][1]).toContain("ClineAndroidLauncher");
	expect(run.mock.calls[0][0]).toContain("jre");
	expect(run.mock.calls[0][6]).toBe(true);
	expect(run.mock.calls[0][5]).not.toHaveProperty("JAVA_TOOL_OPTIONS");
	expect(androidChildEnvironment().PROCESSOR_ARCHITECTURE).toBe("AMD64");
	expect(androidChildEnvironment().PROCESSOR_ARCHITEW6432).toBe("AMD64");
	expect(androidChildEnvironment()).not.toHaveProperty(
		"CLINE_ANDROID_TEST_STORE_PASSWORD",
	);
});
it("binds cache identities to tool bytes and exact API options", async () => {
	const root = await pack(),
		command = path.join(root, "apktool.jar");
	expect(await androidCommandIdentity(command, { api: 28 })).not.toBe(
		await androidCommandIdentity(command, { api: 34 }),
	);
});

it("hashes multi-chunk files repeatedly without retaining stream descriptors", async () => {
	const root = await pack(),
		file = path.join(root, "hash-input.bin");
	const content = Buffer.alloc(150001, 0x5a);
	await fs.writeFile(file, content);
	const expected = createHash("sha256").update(content).digest("hex");
	for (let i = 0; i < 1100; i++) expect(await digestFile(file)).toBe(expected);
}, 30000);
it("isolates native Unicode paths behind ASCII filenames and never overwrites output", async () => {
	const root = await pack(),
		input = path.join(root, "owned 输入.apk");
	await fs.writeFile(input, "owned APK");
	let stage = "";
	const run = vi
		.spyOn(processTools, "runSupervised")
		.mockImplementation(
			async (
				_command,
				argv,
				_timeout,
				_signal,
				_onSpawn,
				env,
				replace,
				cwd,
			) => {
				stage = cwd!;
				expect(argv).toEqual(["-P", "16", "4", "input.apk", "output.apk"]);
				expect(replace).toBe(true);
				expect(env).not.toHaveProperty("JAVA_TOOL_OPTIONS");
				expect(await fs.readFile(path.join(stage, "input.apk"), "utf8")).toBe(
					"owned APK",
				);
				await fs.writeFile(path.join(stage, "output.apk"), "aligned APK");
				return {
					exitCode: 0,
					stdout: "",
					stderr: "",
					timedOut: false,
					cancelled: false,
				};
			},
		);
	// Inputs/output live outside the verified resource inventory.
	const scratch = await fs.mkdtemp(
		path.join(os.tmpdir(), "native fixture 测试 "),
	);
	directories.push(scratch);
	const target = path.join(scratch, "owned 输入.apk"),
		destination = path.join(scratch, "aligned 输出.apk");
	await fs.rename(input, target); // remove input from the immutable pack before verification
	await runAndroidTool(
		path.join(root, "build-tools/zipalign.exe"),
		["-P", "16", "4", target, destination],
		1000,
	);
	expect(await fs.readFile(destination, "utf8")).toBe("aligned APK");
	expect(await fs.stat(stage).catch(() => undefined)).toBeUndefined();
	await expect(
		runAndroidTool(
			path.join(root, "build-tools/zipalign.exe"),
			["-P", "16", "4", target, destination],
			1000,
		),
	).rejects.toThrow();
	expect(await fs.readFile(destination, "utf8")).toBe("aligned APK");
	expect(run).toHaveBeenCalledTimes(2);
});
it("retains native scratch ownership when child termination is unconfirmed", async () => {
	const root = await pack(),
		scratch = await fs.mkdtemp(path.join(os.tmpdir(), "native fixture "));
	directories.push(scratch);
	const target = path.join(scratch, "owned.apk");
	await fs.writeFile(target, "owned APK");
	let stage = "";
	vi.spyOn(processTools, "runSupervised").mockImplementation(
		async (_c, _a, _t, _s, _o, _e, _r, cwd) => {
			stage = cwd!;
			directories.push(stage);
			return {
				exitCode: 0,
				stdout: "",
				stderr: "",
				timedOut: false,
				cancelled: false,
				outputDrainTimedOut: true,
			};
		},
	);
	const output = path.join(scratch, "aligned.apk");
	const result = await runAndroidTool(
		path.join(root, "build-tools/zipalign.exe"),
		["-P", "16", "4", target, output],
		1000,
	);
	expect(result.outputDrainTimedOut).toBe(true);
	expect((await fs.stat(stage)).isDirectory()).toBe(true);
	expect(await fs.stat(output).catch(() => undefined)).toBeUndefined();
});
it("closes the digest handle when a read fails", async () => {
	const close = vi.fn().mockResolvedValue(undefined);
	vi.spyOn(fs, "open").mockResolvedValue({
		stat: vi.fn().mockResolvedValue({ isFile: () => true, size: 1 }),
		read: vi.fn().mockRejectedValue(new Error("owned read failure")),
		close,
	} as unknown as Awaited<ReturnType<typeof fs.open>>);
	await expect(digestFile("owned")).rejects.toThrow("owned read failure");
	expect(close).toHaveBeenCalledTimes(1);
});
