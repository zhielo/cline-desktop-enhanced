import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import {
	androidChildEnvironment,
	androidCommandIdentity,
	bundledAndroidTool,
	runAndroidTool,
	verifyAndroidToolchain,
} from "./android-toolchain";
import * as processTools from "./supervised-process";
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
