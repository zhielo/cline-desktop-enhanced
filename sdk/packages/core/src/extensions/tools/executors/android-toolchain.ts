/** Fixed Java/native invocations. Target files are data; no batch/shell launcher is used by the pack. */
import { createHash } from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { constants } from "node:fs";
import { runSupervised } from "./supervised-process";

export const ANDROID_TOOLCHAIN_PROFILE = "cline-android-toolchain/1";
export const ANDROID_TOOLS = [
	"apktool",
	"smali",
	"baksmali",
	"jadx",
	"bundletool",
	"apksigner",
	"zipalign",
	"aapt2",
	"dexdump",
] as const;
export type AndroidTool = (typeof ANDROID_TOOLS)[number];
const entry: Record<AndroidTool, string> = {
	apktool: "apktool.jar",
	smali: "smali/lib/smali-3.0.10.jar",
	baksmali: "smali/lib/smali-baksmali-3.0.10.jar",
	jadx: "jadx/lib/jadx-1.5.6-all.jar",
	bundletool: "bundletool.jar",
	apksigner: "build-tools/lib/apksigner.jar",
	zipalign: "build-tools/zipalign.exe",
	aapt2: "build-tools/aapt2.exe",
	dexdump: "build-tools/dexdump.exe",
};
export function androidToolchainRoot(): string | undefined {
	return (
		process.env.CLINE_ANDROID_TOOLCHAIN_ROOT ||
		(process.platform === "win32"
			? path.join(
					path.dirname(process.execPath),
					"resources",
					"android-toolchain",
				)
			: undefined)
	);
}
export async function digestFile(file: string): Promise<string> {
	const handle = await fs.open(file, "r");
	try {
		const info = await handle.stat();
		if (!info.isFile() || info.size > 512 * 1024 * 1024)
			throw new Error("Android file budget exceeded");
		const hash = createHash("sha256");
		for await (const chunk of handle.createReadStream({ autoClose: false }))
			hash.update(chunk);
		return hash.digest("hex");
	} finally {
		await handle.close();
	}
}
async function confined(root: string, relative: string) {
	if (
		!relative ||
		relative.includes("\\") ||
		relative.split("/").some((p) => !p || p === "." || p === "..") ||
		path.isAbsolute(relative)
	)
		throw new Error("Invalid Android manifest path");
	let current = root;
	for (const part of relative.split("/")) {
		current = path.join(current, part);
		if ((await fs.lstat(current)).isSymbolicLink())
			throw new Error("Linked Android resource forbidden");
	}
	const canonical = await fs.realpath(current),
		base = await fs.realpath(root),
		rel = path.relative(base, canonical);
	if (rel.startsWith(`..${path.sep}`) || rel === ".." || path.isAbsolute(rel))
		throw new Error("Android resource escaped pack");
	return current;
}
export async function verifyAndroidToolchain(root = androidToolchainRoot()) {
	if (
		!root ||
		!path.isAbsolute(root) ||
		(await fs.lstat(root)).isSymbolicLink()
	)
		throw new Error("Android toolchain missing or linked");
	const manifestFile = await confined(root, "manifest.json"),
		info = await fs.stat(manifestFile);
	if (info.size > 1024 * 1024)
		throw new Error("Android manifest budget exceeded");
	const manifest = JSON.parse(
		(await fs.readFile(manifestFile, "utf8")).replace(/^\uFEFF/, ""),
	);
	if (
		manifest.schemaVersion !== 1 ||
		manifest.profile !== ANDROID_TOOLCHAIN_PROFILE ||
		!manifest.files ||
		typeof manifest.files !== "object" ||
		Array.isArray(manifest.files)
	)
		throw new Error("Invalid Android toolchain manifest");
	let walked = 0;
	async function walk(dir: string, prefix = "") {
		for (const item of await fs.readdir(dir, { withFileTypes: true })) {
			if (++walked > 10000)
				throw new Error("Android pack entry budget exceeded");
			const name = prefix + item.name;
			if (item.isSymbolicLink())
				throw new Error("Linked Android pack resource");
			if (item.isDirectory()) await walk(path.join(dir, item.name), name + "/");
			else if (name !== "manifest.json" && !manifest.files[name])
				throw new Error("Untracked Android pack resource");
		}
	}
	await walk(root);
	const files = Object.entries(manifest.files);
	if (files.length < 10 || files.length > 4096)
		throw new Error("Android inventory budget exceeded");
	let bytes = 0;
	for (const [relative, hash] of files) {
		if (typeof hash !== "string" || !/^[a-f0-9]{64}$/.test(hash))
			throw new Error("Invalid Android file digest");
		const file = await confined(root, relative);
		bytes += (await fs.stat(file)).size;
		if (bytes > 2 * 1024 ** 3 || (await digestFile(file)) !== hash)
			throw new Error("Android toolchain integrity mismatch");
	}
	const java =
		process.platform === "win32" ? "jre/bin/java.exe" : "jre/bin/java";
	for (const file of [java, "tools.lock.json", ...Object.values(entry)])
		if (!manifest.files[file])
			throw new Error(`Missing Android pack entry: ${file}`);
	return {
		root,
		java: path.join(root, java),
		identity: createHash("sha256")
			.update(JSON.stringify(manifest.files))
			.digest("hex"),
		files: manifest.files as Record<string, string>,
	};
}
export async function bundledAndroidTools(): Promise<
	Partial<Record<AndroidTool, string>>
> {
	const root = androidToolchainRoot();
	if (!root) return {};
	try {
		await fs.access(path.join(root, "manifest.json"));
	} catch {
		return {};
	}
	const verified = await verifyAndroidToolchain(root);
	return Object.fromEntries(
		ANDROID_TOOLS.map((tool) => [tool, path.join(verified.root, entry[tool])]),
	);
}
export async function bundledAndroidTool(
	tool: AndroidTool,
): Promise<string | undefined> {
	const root = androidToolchainRoot();
	if (!root) return undefined;
	try {
		await fs.access(path.join(root, "manifest.json"));
	} catch {
		return undefined;
	}
	// A present but invalid pack must never silently fall back to an unrelated PATH tool.
	const verified = await verifyAndroidToolchain(root);
	return path.join(verified.root, entry[tool]);
}
export function androidChildEnvironment(
	extra: Record<string, string> = {},
): Record<string, string> {
	const env: Record<string, string> = {};
	for (const key of [
		"SystemRoot",
		"WINDIR",
		"TEMP",
		"TMP",
		"TMPDIR",
		"HOME",
		"USERPROFILE",
		"LOCALAPPDATA",
		"PATH",
		"LANG",
		"LC_ALL",
	])
		if (process.env[key]) env[key] = process.env[key]!;
	if (
		process.platform !== "win32" &&
		(!env.LANG || env.LANG === "C" || env.LANG === "POSIX")
	) {
		env.LANG = "C.UTF-8";
		env.LC_ALL = "C.UTF-8";
	}
	// No JAVA_TOOL_OPTIONS, JDK_JAVA_OPTIONS, CLASSPATH, credentials or target project configuration.
	return { ...env, ...extra };
}
export async function runAndroidTool(
	command: string,
	args: string[],
	timeout: number,
	signal?: AbortSignal,
	extraEnvironment: Record<string, string> = {},
) {
	const root = androidToolchainRoot();
	const relative = root
		? path.relative(root, command).split(path.sep).join("/")
		: "";
	const tool = ANDROID_TOOLS.find((t) => entry[t] === relative);
	if (!tool) return runSupervised(command, args, timeout, signal);
	const pack = await verifyAndroidToolchain(root);
	let executable = command,
		argv = args;
	if (command.endsWith(".jar")) {
		executable = pack.java;
		const base = ["-Xmx768m", "-Djava.awt.headless=true"];
		argv =
			tool === "smali" || tool === "baksmali"
				? [
						...base,
						"-cp",
						path.join(pack.root, "smali/lib/*"),
						`com.android.tools.smali.${tool}.Main`,
						...args,
					]
				: tool === "jadx"
					? [...base, "-cp", command, "jadx.cli.JadxCLI", ...args]
					: [...base, "-jar", command, ...args];
	}
	return runSupervised(
		executable,
		argv,
		timeout,
		signal,
		undefined,
		androidChildEnvironment(extraEnvironment),
		true,
	);
}
export async function androidCommandIdentity(
	command: string,
	options: unknown,
) {
	if (!path.isAbsolute(command)) {
		const candidates = (process.env.PATH ?? "")
			.split(path.delimiter)
			.map((p) => path.join(p, command));
		let resolved: string | undefined;
		for (const file of candidates) {
			try {
				await fs.access(
					file,
					process.platform === "win32" ? constants.F_OK : constants.X_OK,
				);
				resolved = await fs.realpath(file);
				break;
			} catch {}
		}
		if (!resolved) throw new Error("Android executable identity unavailable");
		command = resolved;
	}
	const root = androidToolchainRoot();
	const packed =
		root &&
		Object.values(entry).some(
			(p) => path.resolve(root, p) === path.resolve(command),
		);
	return createHash("sha256")
		.update(
			JSON.stringify({
				profile: ANDROID_TOOLCHAIN_PROFILE,
				command: path.resolve(command),
				executable: await digestFile(command),
				pack: packed ? (await verifyAndroidToolchain(root)).identity : null,
				options,
			}),
		)
		.digest("hex");
}
