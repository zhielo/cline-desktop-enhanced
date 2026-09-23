import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, type Dirent } from "node:fs";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { inflateRaw } from "node:zlib";
import { promisify } from "node:util";
import type { ReverseEngineeringExecutor } from "../types";

const MAX_OUTPUT_CHARS = 200_000;
const MAX_ZIP_ENTRIES = 100_000;
const MAX_ZIP_DIRECTORY_BYTES = 16 * 1024 * 1024;
const MAX_LISTED_ENTRIES = 2_000;
const MAX_EXTRACTED_ENTRIES = 25_000;
const MAX_ENTRY_UNCOMPRESSED_BYTES = 512 * 1024 * 1024;
const MAX_TOTAL_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024;
const inflateRawAsync = promisify(inflateRaw);

type Engine = "ghidra" | "ida" | "jadx";
type ToolInventory = Record<Engine, string | undefined>;
type AndroidReUtilities = {
	apktool?: string;
	baksmali?: string;
	smali?: string;
	apksigner?: string;
	zipalign?: string;
};

const ANALYSIS_MANIFEST = "cline-analysis.json";
const analysisLocks = new Map<string, Promise<void>>();

async function withAnalysisLock<T>(
	key: string,
	work: () => Promise<T>,
): Promise<T> {
	const previous = analysisLocks.get(key) ?? Promise.resolve();
	let release!: () => void;
	const current = new Promise<void>((resolve) => {
		release = resolve;
	});
	const queued = previous.catch(() => undefined).then(() => current);
	analysisLocks.set(key, queued);
	await previous.catch(() => undefined);
	try {
		return await work();
	} finally {
		release();
		if (analysisLocks.get(key) === queued) analysisLocks.delete(key);
	}
}

function splitPathEntries(value: string | undefined): string[] {
	return (value ?? "")
		.split(path.delimiter)
		.map((entry) => entry.trim())
		.filter(Boolean);
}

function expandWindowsEnvironment(value: string): string {
	return value.replace(/%([^%]+)%/g, (_match, name: string) => {
		const replacement = process.env[name] ?? process.env[name.toUpperCase()];
		return replacement ?? _match;
	});
}

async function readWindowsRegistryPath(
	key: string,
): Promise<string | undefined> {
	if (process.platform !== "win32") return undefined;
	return new Promise((resolve) => {
		const child = spawn("reg.exe", ["query", key, "/v", "Path"], {
			stdio: ["ignore", "pipe", "ignore"],
			windowsHide: true,
		});
		let output = "";
		child.stdout?.on("data", (chunk) => {
			output = boundedAppend(output, chunk);
		});
		child.once("error", () => resolve(undefined));
		child.once("exit", (code) => {
			if (code !== 0) return resolve(undefined);
			const line = output
				.split(/\r?\n/)
				.find((candidate) => /\bREG_(?:EXPAND_)?SZ\b/i.test(candidate));
			const value = line?.split(/\bREG_(?:EXPAND_)?SZ\b/i)[1]?.trim();
			resolve(value ? expandWindowsEnvironment(value) : undefined);
		});
	});
}

/**
 * Desktop sidecars inherit their environment at startup. Refresh PATH from the
 * Windows registry before discovery so tools installed while the app is open
 * become available without killing the sidecar.
 */
async function refreshProcessPath(): Promise<boolean> {
	if (process.platform !== "win32") return false;
	const [machinePath, userPath] = await Promise.all([
		readWindowsRegistryPath(
			"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
		),
		readWindowsRegistryPath("HKCU\\Environment"),
	]);
	const entries = [
		...splitPathEntries(process.env.PATH),
		...splitPathEntries(machinePath),
		...splitPathEntries(userPath),
	];
	const seen = new Set<string>();
	const merged = entries.filter((entry) => {
		const key = path.normalize(entry).toLowerCase();
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});
	const next = merged.join(path.delimiter);
	const changed = next !== process.env.PATH;
	process.env.PATH = next;
	return changed;
}

async function exists(filePath: string): Promise<boolean> {
	try {
		await fs.access(filePath);
		return true;
	} catch {
		return false;
	}
}

async function listMatchingDirectories(
	parent: string | undefined,
	prefixes: string[],
): Promise<string[]> {
	if (!parent || !(await exists(parent))) return [];
	try {
		const entries = await fs.readdir(parent, { withFileTypes: true });
		return entries
			.filter(
				(entry) =>
					entry.isDirectory() &&
					prefixes.some((prefix) =>
						entry.name.toLowerCase().startsWith(prefix.toLowerCase()),
					),
			)
			.map((entry) => path.join(parent, entry.name))
			.sort()
			.reverse();
	} catch {
		return [];
	}
}

async function windowsInstallRoots(engine: Engine): Promise<string[]> {
	if (process.platform !== "win32") return [];
	const parents = [
		process.env.ProgramFiles,
		process.env["ProgramFiles(x86)"],
		process.env.LOCALAPPDATA
			? path.join(process.env.LOCALAPPDATA, "Programs")
			: undefined,
	];
	const prefixes =
		engine === "ghidra"
			? ["ghidra"]
			: engine === "ida"
				? ["IDA Professional", "IDA Pro", "IDA 9", "IDA9"]
				: ["jadx"];
	const roots: string[] = [];
	for (const parent of parents) {
		roots.push(...(await listMatchingDirectories(parent, prefixes)));
	}
	if (engine === "ghidra") {
		const userHome = process.env.USERPROFILE;
		roots.push(
			...(await listMatchingDirectories(userHome, ["ghidra"])),
			...(await listMatchingDirectories(
				userHome ? path.join(userHome, "Downloads") : undefined,
				["ghidra"],
			)),
		);
	}
	return [...new Set(roots)];
}

async function executableCandidates(engine: Engine): Promise<string[]> {
	const win = process.platform === "win32";
	const discoveredRoots = await windowsInstallRoots(engine);
	if (engine === "ghidra") {
		const home = process.env.GHIDRA_HOME ?? process.env.GHIDRA_INSTALL_DIR;
		const roots = [...(home ? [home] : []), ...discoveredRoots];
		return [
			...roots.flatMap((root) => [
				path.join(
					root,
					"support",
					win ? "analyzeHeadless.bat" : "analyzeHeadless",
				),
				path.join(root, win ? "ghidraRun.bat" : "ghidraRun"),
			]),
			win ? "analyzeHeadless.bat" : "analyzeHeadless",
			win ? "ghidraRun.bat" : "ghidraRun",
		];
	}
	if (engine === "ida") {
		const home = process.env.IDA_HOME ?? process.env.IDADIR;
		const roots = [...(home ? [home] : []), ...discoveredRoots];
		const names = win
			? ["idat64.exe", "ida64.exe", "idat.exe", "ida.exe"]
			: ["idat64", "ida64", "idat", "ida"];
		return [
			...roots.flatMap((root) => names.map((name) => path.join(root, name))),
			...names,
		];
	}
	const home = process.env.JADX_HOME;
	const roots = [...(home ? [home] : []), ...discoveredRoots];
	const names = win ? ["jadx.bat", "jadx-gui.bat"] : ["jadx", "jadx-gui"];
	return [
		...roots.flatMap((root) =>
			names.flatMap((name) => [
				path.join(root, "bin", name),
				path.join(root, name),
			]),
		),
		...names,
	];
}

async function commandAvailable(command: string): Promise<boolean> {
	if (path.isAbsolute(command)) {
		try {
			const stat = await fs.stat(command);
			return stat.isFile();
		} catch {
			return false;
		}
	}
	const locator = process.platform === "win32" ? "where" : "which";
	return new Promise((resolve) => {
		const child = spawn(locator, [command], {
			stdio: "ignore",
			windowsHide: true,
		});
		child.once("error", () => resolve(false));
		child.once("exit", (code) => resolve(code === 0));
	});
}

async function discover(
	engine: Engine,
	gui = false,
): Promise<string | undefined> {
	const candidates = (await executableCandidates(engine)).filter((candidate) =>
		gui
			? !candidate.toLowerCase().includes("headless") &&
				!/^idat(?:64)?(?:\.exe)?$/i.test(path.basename(candidate)) &&
				!/^jadx(?:\.bat)?$/i.test(path.basename(candidate))
			: engine === "ghidra"
				? /analyzeheadless(?:\.bat)?$/i.test(path.basename(candidate))
				: engine === "ida"
					? /^idat(?:64)?(?:\.exe)?$/i.test(path.basename(candidate))
					: /^jadx(?:\.bat)?$/i.test(path.basename(candidate)),
	);
	for (const candidate of candidates)
		if (await commandAvailable(candidate)) return candidate;
	return undefined;
}

async function discoverFirst(commands: string[]): Promise<string | undefined> {
	for (const command of commands) {
		if (await commandAvailable(command)) return command;
	}
	return undefined;
}

async function discoverAndroidUtilities(): Promise<AndroidReUtilities> {
	const win = process.platform === "win32";
	const suffix = win ? ".bat" : "";
	const executableSuffix = win ? ".exe" : "";
	const [apktool, baksmali, smali, apksigner, zipalign] = await Promise.all([
		discoverFirst([`apktool${suffix}`, `apktool${executableSuffix}`]),
		discoverFirst([`baksmali${suffix}`, `baksmali${executableSuffix}`]),
		discoverFirst([`smali${suffix}`, `smali${executableSuffix}`]),
		discoverFirst([`apksigner${suffix}`, `apksigner${executableSuffix}`]),
		discoverFirst([`zipalign${executableSuffix}`]),
	]);
	return { apktool, baksmali, smali, apksigner, zipalign };
}

async function sha256(filePath: string): Promise<string> {
	return new Promise((resolve, reject) => {
		const hash = createHash("sha256");
		const stream = createReadStream(filePath);
		stream.on("data", (chunk) => hash.update(chunk));
		stream.once("error", reject);
		stream.once("end", () => resolve(hash.digest("hex")));
	});
}

async function sha256Directory(directory: string): Promise<string> {
	const hash = createHash("sha256");
	const visit = async (current: string) => {
		const entries = await fs.readdir(current, { withFileTypes: true });
		entries.sort((left, right) => left.name.localeCompare(right.name));
		for (const entry of entries) {
			const absolute = path.join(current, entry.name);
			const relative = path.relative(directory, absolute).replace(/\\/g, "/");
			if (entry.isSymbolicLink()) {
				throw new Error(
					`Symbolic links are not allowed in Smali/APK build inputs: ${relative}`,
				);
			}
			if (entry.isDirectory()) {
				hash.update(`D\0${relative}\0`);
				await visit(absolute);
			} else if (entry.isFile()) {
				hash.update(`F\0${relative}\0`);
				await new Promise<void>((resolve, reject) => {
					const stream = createReadStream(absolute);
					stream.on("data", (chunk) => hash.update(chunk));
					stream.once("error", reject);
					stream.once("end", resolve);
				});
				hash.update("\0");
			}
		}
	};
	await visit(directory);
	return hash.digest("hex");
}

function boundedAppend(current: string, chunk: Buffer | string): string {
	if (current.length >= MAX_OUTPUT_CHARS) return current;
	return (current + chunk.toString()).slice(0, MAX_OUTPUT_CHARS);
}

function spawnPortable(command: string, args: string[]) {
	if (process.platform === "win32" && /\.(bat|cmd)$/i.test(command)) {
		return spawn(
			process.env.ComSpec ?? "cmd.exe",
			["/d", "/s", "/c", command, ...args],
			{
				windowsHide: true,
				stdio: ["ignore", "pipe", "pipe"],
				windowsVerbatimArguments: false,
			},
		);
	}
	return spawn(command, args, {
		windowsHide: true,
		stdio: ["ignore", "pipe", "pipe"],
	});
}

async function runSupervised(
	command: string,
	args: string[],
	timeoutMs: number,
	signal?: AbortSignal,
) {
	return new Promise<{
		exitCode: number | null;
		stdout: string;
		stderr: string;
		timedOut: boolean;
		cancelled: boolean;
	}>((resolve, reject) => {
		if (signal?.aborted) {
			resolve({
				exitCode: null,
				stdout: "",
				stderr: "",
				timedOut: false,
				cancelled: true,
			});
			return;
		}
		const child = spawnPortable(command, args);
		let stdout = "";
		let stderr = "";
		let timedOut = false;
		let cancelled = false;
		child.stdout?.on("data", (chunk) => {
			stdout = boundedAppend(stdout, chunk);
		});
		child.stderr?.on("data", (chunk) => {
			stderr = boundedAppend(stderr, chunk);
		});
		const kill = () => {
			if (child.pid && process.platform === "win32")
				spawn("taskkill", ["/pid", String(child.pid), "/t", "/f"], {
					stdio: "ignore",
					windowsHide: true,
				});
			else child.kill("SIGKILL");
		};
		const timer = setTimeout(() => {
			timedOut = true;
			kill();
		}, timeoutMs);
		const abort = () => {
			cancelled = true;
			kill();
		};
		signal?.addEventListener("abort", abort, { once: true });
		child.once("error", (error) => {
			clearTimeout(timer);
			signal?.removeEventListener("abort", abort);
			reject(error);
		});
		child.once("exit", (exitCode) => {
			clearTimeout(timer);
			signal?.removeEventListener("abort", abort);
			resolve({ exitCode, stdout, stderr, timedOut, cancelled });
		});
	});
}

async function toolVersion(
	engine: Engine,
	command: string | undefined,
): Promise<string | undefined> {
	if (!command) return undefined;
	if (engine === "ghidra" || engine === "ida") {
		const root = installationRoot(command, engine);
		return root ? path.basename(root) : undefined;
	}
	try {
		const result = await runSupervised(command, ["--version"], 10_000);
		const version = `${result.stdout}\n${result.stderr}`
			.trim()
			.split(/\r?\n/)
			.find(Boolean);
		return version?.slice(0, 300);
	} catch {
		return undefined;
	}
}

interface ZipEntry {
	name: string;
	normalized: string;
	compressedSize: number;
	uncompressedSize: number;
	crc32: number;
	compressionMethod: number;
	generalPurposeBitFlag: number;
	localHeaderOffset: number;
	unsafePath: boolean;
	symlink: boolean;
	duplicate: boolean;
	isDirectory: boolean;
}

interface ZipInspection {
	format: "zip";
	declaredEntries: number;
	parsedEntries: number;
	listedEntries: number;
	entriesTruncated: boolean;
	totalCompressed: number;
	totalUncompressed: number;
	compressionRatio: number;
	findings: {
		unsafePaths: number;
		symlinks: number;
		duplicates: number;
		suspiciousRatios: number;
	};
	extractionRecommended: boolean;
	entries: Array<
		Omit<
			ZipEntry,
			| "normalized"
			| "compressionMethod"
			| "generalPurposeBitFlag"
			| "localHeaderOffset"
		>
	>;
	parsed: ZipEntry[];
}

async function inspectZip(target: string): Promise<ZipInspection> {
	const handle = await fs.open(target, "r");
	try {
		const stat = await handle.stat();
		const tailSize = Math.min(stat.size, 65_557);
		const tail = Buffer.alloc(tailSize);
		await handle.read(tail, 0, tailSize, stat.size - tailSize);
		let eocd = -1;
		for (let i = tail.length - 22; i >= 0; i--)
			if (tail.readUInt32LE(i) === 0x06054b50) {
				eocd = i;
				break;
			}
		if (eocd < 0)
			throw new Error("ZIP end-of-central-directory record not found");
		const declaredEntries = tail.readUInt16LE(eocd + 10);
		const directorySize = tail.readUInt32LE(eocd + 12);
		const directoryOffset = tail.readUInt32LE(eocd + 16);
		if (
			declaredEntries === 0xffff ||
			directorySize === 0xffffffff ||
			directoryOffset === 0xffffffff
		)
			throw new Error("ZIP64 archives require a dedicated external inspector");
		if (
			declaredEntries > MAX_ZIP_ENTRIES ||
			directorySize > MAX_ZIP_DIRECTORY_BYTES ||
			directoryOffset + directorySize > stat.size
		)
			throw new Error(
				"ZIP central directory exceeds safe inspection limits or file bounds",
			);
		const directory = Buffer.alloc(directorySize);
		await handle.read(directory, 0, directorySize, directoryOffset);
		const seen = new Set<string>();
		const entries: ZipInspection["entries"] = [];
		const parsed: ZipEntry[] = [];
		let offset = 0;
		let unsafePaths = 0,
			symlinks = 0,
			duplicates = 0,
			suspiciousRatios = 0,
			parsedEntries = 0;
		let totalCompressed = 0,
			totalUncompressed = 0;
		while (offset < directory.length) {
			if (
				offset + 46 > directory.length ||
				directory.readUInt32LE(offset) !== 0x02014b50
			)
				throw new Error("Malformed ZIP central directory");
			const compressed = directory.readUInt32LE(offset + 20);
			const uncompressed = directory.readUInt32LE(offset + 24);
			const generalPurposeBitFlag = directory.readUInt16LE(offset + 8);
			const compressionMethod = directory.readUInt16LE(offset + 10);
			const crc32 = directory.readUInt32LE(offset + 16);
			const nameLength = directory.readUInt16LE(offset + 28);
			const extraLength = directory.readUInt16LE(offset + 30);
			const commentLength = directory.readUInt16LE(offset + 32);
			const externalAttrs = directory.readUInt32LE(offset + 38);
			const localHeaderOffset = directory.readUInt32LE(offset + 42);
			const end = offset + 46 + nameLength + extraLength + commentLength;
			if (end > directory.length)
				throw new Error("ZIP entry exceeds central directory bounds");
			const name = directory
				.subarray(offset + 46, offset + 46 + nameLength)
				.toString("utf8");
			const normalized = name.replace(/\\/g, "/");
			const unsafe =
				normalized.includes("\0") ||
				normalized.startsWith("/") ||
				/^[A-Za-z]:\//.test(normalized) ||
				normalized.split("/").includes("..");
			const mode = externalAttrs >>> 16;
			const symlink = (mode & 0xf000) === 0xa000;
			const collisionKey =
				process.platform === "win32"
					? normalized.normalize("NFC").toLowerCase()
					: normalized;
			const duplicate = seen.has(collisionKey);
			const isDirectory = normalized.endsWith("/");
			const ratio = uncompressed / Math.max(compressed, 1);
			seen.add(collisionKey);
			if (unsafe) unsafePaths++;
			if (symlink) symlinks++;
			if (duplicate) duplicates++;
			if (ratio > 1000) suspiciousRatios++;
			totalCompressed += compressed;
			totalUncompressed += uncompressed;
			parsedEntries++;
			const entry: ZipEntry = {
				name,
				normalized,
				compressedSize: compressed,
				uncompressedSize: uncompressed,
				crc32,
				compressionMethod,
				generalPurposeBitFlag,
				localHeaderOffset,
				unsafePath: unsafe,
				symlink,
				duplicate,
				isDirectory,
			};
			parsed.push(entry);
			if (entries.length < MAX_LISTED_ENTRIES) {
				const {
					normalized: _normalized,
					compressionMethod: _compressionMethod,
					generalPurposeBitFlag: _generalPurposeBitFlag,
					localHeaderOffset: _localHeaderOffset,
					...listed
				} = entry;
				entries.push(listed);
			}
			offset = end;
		}
		if (parsedEntries !== declaredEntries)
			throw new Error(
				`ZIP declared ${declaredEntries} entries but parsed ${parsedEntries}`,
			);
		return {
			format: "zip",
			declaredEntries,
			parsedEntries,
			listedEntries: entries.length,
			entriesTruncated: parsedEntries > entries.length,
			totalCompressed,
			totalUncompressed,
			compressionRatio: totalUncompressed / Math.max(totalCompressed, 1),
			findings: { unsafePaths, symlinks, duplicates, suspiciousRatios },
			extractionRecommended:
				unsafePaths === 0 &&
				symlinks === 0 &&
				duplicates === 0 &&
				suspiciousRatios === 0,
			entries,
			parsed,
		};
	} finally {
		await handle.close();
	}
}

async function isZip(target: string): Promise<boolean> {
	const handle = await fs.open(target, "r");
	try {
		const signature = Buffer.alloc(4);
		const { bytesRead } = await handle.read(signature, 0, 4, 0);
		if (bytesRead !== 4) return false;
		const value = signature.readUInt32LE(0);
		return value === 0x04034b50 || value === 0x06054b50 || value === 0x08074b50;
	} finally {
		await handle.close();
	}
}

function machineName(machine: number): string {
	return (
		{
			0x014c: "x86",
			0x8664: "x86_64",
			0x01c0: "arm",
			0xaa64: "arm64",
			0x01f0: "powerpc",
			0x0003: "x86",
			0x003e: "x86_64",
			0x0028: "arm",
			0x00b7: "arm64",
			0x0008: "mips",
			0x0014: "powerpc",
			0x00f3: "riscv",
		}[machine] ?? `machine-0x${machine.toString(16)}`
	);
}

function sampleEntropy(buffer: Buffer): number {
	if (buffer.length === 0) return 0;
	const counts = new Uint32Array(256);
	for (const byte of buffer) counts[byte]! += 1;
	let entropy = 0;
	for (const count of counts) {
		if (count === 0) continue;
		const probability = count / buffer.length;
		entropy -= probability * Math.log2(probability);
	}
	return Number(entropy.toFixed(3));
}

async function inspectBinary(target: string) {
	const handle = await fs.open(target, "r");
	try {
		const stat = await handle.stat();
		const sample = Buffer.alloc(Math.min(stat.size, 1024 * 1024));
		await handle.read(sample, 0, sample.length, 0);
		const result: Record<string, unknown> = {
			format: "binary",
			sampleEntropy: sampleEntropy(sample),
			sampleBytes: sample.length,
		};

		if (sample.length >= 64 && sample[0] === 0x4d && sample[1] === 0x5a) {
			const peOffset = sample.readUInt32LE(0x3c);
			if (
				peOffset + 24 <= sample.length &&
				sample.readUInt32LE(peOffset) === 0x00004550
			) {
				const machine = sample.readUInt16LE(peOffset + 4);
				const sectionCount = sample.readUInt16LE(peOffset + 6);
				const timestamp = sample.readUInt32LE(peOffset + 8);
				const optionalOffset = peOffset + 24;
				const optionalMagic =
					optionalOffset + 2 <= sample.length
						? sample.readUInt16LE(optionalOffset)
						: 0;
				const is64 = optionalMagic === 0x20b;
				const entryPoint =
					optionalOffset + 20 <= sample.length
						? sample.readUInt32LE(optionalOffset + 16)
						: undefined;
				const imageBase =
					optionalOffset + (is64 ? 32 : 32) <= sample.length
						? is64
							? `0x${sample.readBigUInt64LE(optionalOffset + 24).toString(16)}`
							: `0x${sample.readUInt32LE(optionalOffset + 28).toString(16)}`
						: undefined;
				return {
					...result,
					format: "pe",
					architecture: machineName(machine),
					bits: is64 ? 64 : 32,
					sectionCount,
					compileTimestamp:
						timestamp > 0
							? new Date(timestamp * 1000).toISOString()
							: undefined,
					entryPoint:
						entryPoint === undefined
							? undefined
							: `0x${entryPoint.toString(16)}`,
					imageBase,
				};
			}
		}

		if (
			sample.length >= 32 &&
			sample[0] === 0x7f &&
			sample.subarray(1, 4).toString("ascii") === "ELF"
		) {
			const bits = sample[4] === 2 ? 64 : 32;
			const littleEndian = sample[5] !== 2;
			const read16 = (offset: number) =>
				littleEndian
					? sample.readUInt16LE(offset)
					: sample.readUInt16BE(offset);
			const machine = read16(18);
			const entry =
				bits === 64
					? littleEndian
						? sample.readBigUInt64LE(24)
						: sample.readBigUInt64BE(24)
					: BigInt(
							littleEndian ? sample.readUInt32LE(24) : sample.readUInt32BE(24),
						);
			return {
				...result,
				format: "elf",
				architecture: machineName(machine),
				bits,
				endianness: littleEndian ? "little" : "big",
				entryPoint: `0x${entry.toString(16)}`,
			};
		}

		if (
			sample.length >= 8 &&
			sample.subarray(0, 4).toString("ascii") === "dex\n"
		) {
			return {
				...result,
				format: "dex",
				version: sample.subarray(4, 7).toString("ascii"),
			};
		}

		const magic = sample.length >= 4 ? sample.readUInt32BE(0) : 0;
		const mach = new Map<number, { bits: number; endianness: string }>([
			[0xfeedface, { bits: 32, endianness: "big" }],
			[0xcefaedfe, { bits: 32, endianness: "little" }],
			[0xfeedfacf, { bits: 64, endianness: "big" }],
			[0xcffaedfe, { bits: 64, endianness: "little" }],
			[0xcafebabe, { bits: 0, endianness: "fat" }],
		]).get(magic);
		if (mach) return { ...result, format: "mach-o", ...mach };

		if (magic === 0x0061736d) {
			return { ...result, format: "wasm" };
		}
		return result;
	} finally {
		await handle.close();
	}
}

function archiveKind(target: string, entries: ZipEntry[]) {
	const extension = path.extname(target).toLowerCase();
	if (extension === ".apk") return "apk";
	if (extension === ".aab") return "aab";
	if (extension === ".jar") return "jar";
	if (entries.some((entry) => entry.normalized === "AndroidManifest.xml"))
		return "apk";
	return "zip";
}

const CRC32_TABLE = Uint32Array.from({ length: 256 }, (_, index) => {
	let value = index;
	for (let bit = 0; bit < 8; bit++) {
		value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
	}
	return value >>> 0;
});

function crc32(payload: Buffer) {
	let value = 0xffffffff;
	for (const byte of payload) {
		value = CRC32_TABLE[(value ^ byte) & 0xff]! ^ (value >>> 8);
	}
	return (value ^ 0xffffffff) >>> 0;
}

async function extractZip(
	target: string,
	outputDir: string,
	inspection: ZipInspection,
) {
	if (!inspection.extractionRecommended) {
		throw new Error(
			"Archive extraction refused because inspection found unsafe paths, symlinks, duplicate names, or suspicious compression ratios.",
		);
	}
	if (
		inspection.parsedEntries > MAX_EXTRACTED_ENTRIES ||
		inspection.totalUncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES
	) {
		throw new Error(
			"Archive extraction exceeds configured entry or output-size limits.",
		);
	}

	const input = await fs.open(target, "r");
	const created: string[] = [];
	try {
		for (const entry of inspection.parsed) {
			if (entry.uncompressedSize > MAX_ENTRY_UNCOMPRESSED_BYTES) {
				throw new Error(
					`Archive entry exceeds the per-entry limit: ${entry.name}`,
				);
			}
			if (![0, 8].includes(entry.compressionMethod)) {
				throw new Error(
					`Unsupported ZIP compression method ${entry.compressionMethod} for ${entry.name}`,
				);
			}
			if ((entry.generalPurposeBitFlag & 0x1) !== 0) {
				throw new Error(
					`Encrypted ZIP entries are not supported: ${entry.name}`,
				);
			}
			const destination = path.resolve(
				outputDir,
				...entry.normalized.split("/"),
			);
			const relative = path.relative(outputDir, destination);
			if (
				relative === ".." ||
				relative.startsWith(`..${path.sep}`) ||
				path.isAbsolute(relative)
			) {
				throw new Error(
					`Archive entry escapes the extraction root: ${entry.name}`,
				);
			}
			if (entry.isDirectory) {
				await fs.mkdir(destination, { recursive: true, mode: 0o700 });
				continue;
			}

			const localHeader = Buffer.alloc(30);
			const localRead = await input.read(
				localHeader,
				0,
				localHeader.length,
				entry.localHeaderOffset,
			);
			if (
				localRead.bytesRead !== localHeader.length ||
				localHeader.readUInt32LE(0) !== 0x04034b50
			) {
				throw new Error(`Invalid ZIP local header for ${entry.name}`);
			}
			const nameLength = localHeader.readUInt16LE(26);
			const extraLength = localHeader.readUInt16LE(28);
			const dataOffset =
				entry.localHeaderOffset + 30 + nameLength + extraLength;
			const compressed = Buffer.alloc(entry.compressedSize);
			const payloadRead = await input.read(
				compressed,
				0,
				entry.compressedSize,
				dataOffset,
			);
			if (payloadRead.bytesRead !== entry.compressedSize) {
				throw new Error(`Truncated ZIP payload for ${entry.name}`);
			}
			const payload =
				entry.compressionMethod === 0
					? compressed
					: await inflateRawAsync(compressed, {
							maxOutputLength: Math.min(
								entry.uncompressedSize + 1,
								MAX_ENTRY_UNCOMPRESSED_BYTES + 1,
							),
						});
			if (payload.length !== entry.uncompressedSize) {
				throw new Error(`ZIP size mismatch for ${entry.name}`);
			}
			if (crc32(payload) !== entry.crc32) {
				throw new Error(`ZIP checksum mismatch for ${entry.name}`);
			}
			await fs.mkdir(path.dirname(destination), {
				recursive: true,
				mode: 0o700,
			});
			await fs.writeFile(destination, payload, {
				flag: "wx",
				mode: 0o600,
			});
			created.push(destination);
		}
		return {
			outputDirectory: outputDir,
			extractedEntries: created.length,
			totalUncompressed: inspection.totalUncompressed,
			sample: created.slice(0, 200),
			sampleTruncated: created.length > 200,
		};
	} catch (error) {
		await fs.rm(outputDir, { recursive: true, force: true });
		throw error;
	} finally {
		await input.close();
	}
}

async function createExtractionDirectory(requested?: string) {
	if (!requested)
		return fs.mkdtemp(path.join(os.tmpdir(), "cline-re-extract-"));
	const outputDir = path.resolve(requested);
	if (await exists(outputDir)) {
		throw new Error(
			"output_directory must not already exist for extraction; choose a new directory",
		);
	}
	await fs.mkdir(path.dirname(outputDir), { recursive: true, mode: 0o700 });
	await fs.mkdir(outputDir, { mode: 0o700 });
	return outputDir;
}

function shellLikeQuote(value: string): string {
	if (/^[A-Za-z0-9_./:\\-]+$/.test(value)) return value;
	return `"${value.replace(/(["\\])/g, "\\$1")}"`;
}

function analysisCacheRoot(): string {
	return path.resolve(
		process.env.CLINE_RE_CACHE_DIR ??
			path.join(os.homedir(), ".cline", "reverse-engineering"),
	);
}

async function resolveAnalysisDirectory(
	requested: string | undefined,
	reuseAnalysis: boolean,
	hash: string,
	engine: Engine,
): Promise<{ outputDir: string; persistent: boolean }> {
	if (requested) {
		return { outputDir: path.resolve(requested), persistent: true };
	}
	if (!reuseAnalysis) {
		return {
			outputDir: await fs.mkdtemp(path.join(os.tmpdir(), "cline-re-")),
			persistent: false,
		};
	}
	return {
		outputDir: path.join(analysisCacheRoot(), hash, engine),
		persistent: true,
	};
}

async function readJsonFile(filePath: string) {
	try {
		return JSON.parse(await fs.readFile(filePath, "utf8")) as Record<
			string,
			unknown
		>;
	} catch {
		return undefined;
	}
}

async function writeJsonFile(
	destination: string,
	value: Record<string, unknown>,
) {
	const temporary = `${destination}.${process.pid}.${Date.now()}.tmp`;
	await fs.writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, {
		mode: 0o600,
	});
	await fs.rename(temporary, destination);
}

async function readAnalysisManifest(outputDir: string) {
	return readJsonFile(path.join(outputDir, ANALYSIS_MANIFEST));
}

async function writeAnalysisManifest(
	outputDir: string,
	manifest: Record<string, unknown>,
) {
	await writeJsonFile(path.join(outputDir, ANALYSIS_MANIFEST), manifest);
}

async function listGeneratedArtifacts(outputDir: string) {
	const artifacts: Array<{ path: string; size: number }> = [];
	const visit = async (directory: string) => {
		if (artifacts.length >= 200) return;
		let entries: Dirent[];
		try {
			entries = await fs.readdir(directory, { withFileTypes: true });
		} catch {
			return;
		}
		for (const entry of entries) {
			if (artifacts.length >= 200) return;
			const absolute = path.join(directory, entry.name);
			if (entry.isDirectory()) {
				await visit(absolute);
			} else if (entry.isFile() && entry.name !== ANALYSIS_MANIFEST) {
				const stat = await fs.stat(absolute);
				artifacts.push({
					path: path.relative(outputDir, absolute),
					size: stat.size,
				});
			}
		}
	};
	await visit(outputDir);
	return artifacts;
}

const GHIDRA_DECOMPILE_SCRIPT = `// Generated by Cline Enhanced for authorized static analysis.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.File;
import java.io.PrintWriter;

public class ClineDecompileAll extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 1) {
            throw new IllegalArgumentException("Expected output file path");
        }
        File output = new File(getScriptArgs()[0]);
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try (PrintWriter writer = new PrintWriter(output, "UTF-8")) {
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                writer.println("/* " + function.getName() + " @ " + function.getEntryPoint() + " */");
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    writer.println(result.getDecompiledFunction().getC());
                } else {
                    writer.println("/* decompilation failed: " + result.getErrorMessage() + " */");
                }
                writer.println();
            }
        } finally {
            decompiler.dispose();
        }
    }
}
`;

async function ensureGhidraDecompileScript(outputDir: string) {
	const scriptPath = path.join(outputDir, "ClineDecompileAll.java");
	await fs.writeFile(scriptPath, GHIDRA_DECOMPILE_SCRIPT, {
		mode: 0o600,
	});
	return scriptPath;
}

function installationRoot(command: string | undefined, engine: Engine) {
	if (!command || !path.isAbsolute(command)) return undefined;
	const commandDirectory = path.dirname(command);
	if (
		engine === "ghidra" &&
		path.basename(commandDirectory).toLowerCase() === "support"
	) {
		return path.dirname(commandDirectory);
	}
	return commandDirectory;
}

async function installationCapabilities(
	available: ToolInventory,
	androidUtilities: AndroidReUtilities,
) {
	const ghidraCommand = available.ghidra;
	const ghidraHome = installationRoot(ghidraCommand, "ghidra");
	const idaCommand = available.ida;
	const idaHome = installationRoot(idaCommand, "ida");
	const idalibActivationScript = idaHome
		? path.join(idaHome, "idalib", "python", "py-activate-idalib.py")
		: undefined;
	const bundledPyGhidra = ghidraHome
		? path.join(ghidraHome, "Ghidra", "Features", "PyGhidra", "pypkg", "dist")
		: undefined;
	return {
		platform: process.platform,
		ghidra: {
			headless: ghidraCommand,
			gui: await discover("ghidra", true),
			version: await toolVersion("ghidra", ghidraCommand),
			installDirectory: ghidraHome,
			bundledPyGhidra:
				bundledPyGhidra && (await exists(bundledPyGhidra))
					? bundledPyGhidra
					: undefined,
		},
		ida: {
			headless: idaCommand,
			gui: await discover("ida", true),
			version: await toolVersion("ida", idaCommand),
			installDirectory: idaHome,
			idalibActivationScript:
				idalibActivationScript && (await exists(idalibActivationScript))
					? idalibActivationScript
					: undefined,
		},
		jadx: {
			cli: available.jadx,
			gui: await discover("jadx", true),
			version: await toolVersion("jadx", available.jadx),
		},
		androidBuildTools: androidUtilities,
		cacheDirectory: analysisCacheRoot(),
	};
}

function chooseAuto(
	target: string,
	available: ToolInventory,
): Engine | undefined {
	if (
		[".apk", ".aab", ".dex", ".jar"].includes(
			path.extname(target).toLowerCase(),
		) &&
		available.jadx
	)
		return "jadx";
	return available.ghidra
		? "ghidra"
		: available.ida
			? "ida"
			: available.jadx
				? "jadx"
				: undefined;
}

function launchGui(command: string, args: string[]) {
	const child =
		process.platform === "win32" && /\.(bat|cmd)$/i.test(command)
			? spawn(
					process.env.ComSpec ?? "cmd.exe",
					["/d", "/s", "/c", command, ...args],
					{
						detached: true,
						stdio: "ignore",
						windowsHide: false,
					},
				)
			: spawn(command, args, {
					detached: true,
					stdio: "ignore",
					windowsHide: false,
				});
	child.unref();
	return { launched: true, pid: child.pid ?? null };
}

export function createReverseEngineeringExecutor(): ReverseEngineeringExecutor {
	return async (input, context) => {
		const started = Date.now();
		const pathRefreshed = await refreshProcessPath();
		const available: ToolInventory = {
			ghidra: await discover("ghidra"),
			ida: await discover("ida"),
			jadx: await discover("jadx"),
		};
		const androidUtilities = await discoverAndroidUtilities();
		if (input.operation === "discover") {
			const capabilities = await installationCapabilities(
				available,
				androidUtilities,
			);
			return JSON.stringify(
				{
					capabilities,
					pathRefreshed,
					recommendations: {
						ida: capabilities.ida.idalibActivationScript
							? `Activate idalib once with: uv run "${capabilities.ida.idalibActivationScript}"`
							: "Set IDADIR or IDA_HOME if IDA is installed but not detected.",
						ghidra: capabilities.ghidra.bundledPyGhidra
							? `Install bundled PyGhidra with: py -m pip install --no-index -f "${capabilities.ghidra.bundledPyGhidra}" pyghidra`
							: "Set GHIDRA_INSTALL_DIR if Ghidra is installed but not detected.",
					},
				},
				null,
				2,
			);
		}
		if (!input.target) throw new Error("target is required for this operation");
		if (!path.isAbsolute(input.target))
			throw new Error("target must be an absolute path");
		if (input.operation === "script" && !input.script_path)
			throw new Error("script_path is required for the script operation");
		const target = path.resolve(input.target);
		const stat = await fs.stat(target);
		const directoryOperation =
			input.operation === "assemble_smali" || input.operation === "rebuild_apk";
		if (directoryOperation ? !stat.isDirectory() : !stat.isFile()) {
			throw new Error(
				`Target must be ${directoryOperation ? "a directory" : "a file"}: ${target}`,
			);
		}
		const hash = stat.isDirectory()
			? await sha256Directory(target)
			: await sha256(target);
		const zip = stat.isFile() ? await isZip(target) : false;
		if (input.operation === "inspect") {
			if (!zip) {
				return JSON.stringify(
					{
						target,
						sha256: hash,
						size: stat.size,
						...(await inspectBinary(target)),
					},
					null,
					2,
				);
			}
			const archive = await inspectZip(target);
			const { parsed: _parsed, ...publicArchive } = archive;
			const names = archive.parsed.map((entry) => entry.normalized);
			return JSON.stringify(
				{
					target,
					sha256: hash,
					size: stat.size,
					kind: archiveKind(target, archive.parsed),
					archive: publicArchive,
					android:
						path.extname(target).toLowerCase() === ".apk" ||
						names.includes("AndroidManifest.xml")
							? {
									hasManifest: names.includes("AndroidManifest.xml"),
									dexFiles: names.filter((name) =>
										/^classes\d*\.dex$/i.test(name),
									),
									nativeLibraries: names.filter((name) =>
										/^lib\/[^/]+\/[^/]+\.so$/i.test(name),
									),
									abis: [
										...new Set(
											names
												.map(
													(name) =>
														/^lib\/([^/]+)\/[^/]+\.so$/i.exec(name)?.[1],
												)
												.filter((value): value is string => Boolean(value)),
										),
									],
								}
							: undefined,
				},
				null,
				2,
			);
		}
		if (input.operation === "extract") {
			if (!zip)
				throw new Error(
					"extract currently supports ZIP, APK, AAB, and JAR containers",
				);
			const outputDir = await createExtractionDirectory(input.output_directory);
			const archive = await inspectZip(target);
			return JSON.stringify(
				{
					target,
					sha256: hash,
					kind: archiveKind(target, archive.parsed),
					...(await extractZip(target, outputDir, archive)),
				},
				null,
				2,
			);
		}
		if (input.operation === "script") {
			if (!path.isAbsolute(input.script_path!)) {
				throw new Error("script_path must be an absolute path");
			}
			const scriptStat = await fs.stat(input.script_path!);
			if (!scriptStat.isFile()) {
				throw new Error(`script_path is not a file: ${input.script_path}`);
			}
		}
		if (input.operation === "disassemble_smali") {
			const extension = path.extname(target).toLowerCase();
			const apkContainer = [".apk", ".aab", ".apkm", ".xapk"].includes(
				extension,
			);
			const command = apkContainer
				? androidUtilities.apktool
				: androidUtilities.baksmali;
			if (!command) {
				throw new Error(
					apkContainer
						? "apktool was not found. Install apktool and add it to PATH."
						: "baksmali was not found. Install its launcher and add it to PATH.",
				);
			}
			const outputDir = path.resolve(
				input.output_directory ??
					path.join(analysisCacheRoot(), hash, "smali", "decoded"),
			);
			const smaliManifestPath = `${outputDir}.${ANALYSIS_MANIFEST}`;
			return withAnalysisLock(outputDir, async () => {
				const existingManifest = await readJsonFile(smaliManifestPath);
				if (
					input.reuse_analysis !== false &&
					existingManifest?.sha256 === hash &&
					existingManifest?.operation === "disassemble_smali"
				) {
					const artifacts = await listGeneratedArtifacts(outputDir);
					return JSON.stringify(
						{
							operation: input.operation,
							target,
							sha256: hash,
							outputDirectory: outputDir,
							command,
							reusedAnalysis: true,
							artifacts,
							artifactsTruncated: artifacts.length >= 200,
							durationMs: Date.now() - started,
						},
						null,
						2,
					);
				}
				if (input.output_directory && (await exists(outputDir))) {
					throw new Error(
						"output_directory already exists; choose a new directory or reuse the existing cached analysis",
					);
				}
				await fs.mkdir(path.dirname(outputDir), {
					recursive: true,
					mode: 0o700,
				});
				await fs.rm(outputDir, { recursive: true, force: true });
				const args = apkContainer
					? ["d", "-f", "-o", outputDir, target]
					: [
							"disassemble",
							target,
							"-o",
							outputDir,
							...(input.smali_api_level
								? ["--api", String(input.smali_api_level)]
								: []),
						];
				const result = await runSupervised(
					command,
					args,
					input.timeout_ms ?? 300_000,
					context.signal,
				);
				const succeeded =
					result.exitCode === 0 && !result.timedOut && !result.cancelled;
				if (succeeded) {
					await fs.mkdir(outputDir, { recursive: true, mode: 0o700 });
					await writeJsonFile(smaliManifestPath, {
						schemaVersion: 1,
						sha256: hash,
						target,
						operation: input.operation,
						tool: apkContainer ? "apktool" : "baksmali",
						updatedAt: new Date().toISOString(),
					});
				} else {
					await fs.rm(outputDir, { recursive: true, force: true });
					await fs.rm(smaliManifestPath, { force: true });
				}
				const artifacts = succeeded
					? await listGeneratedArtifacts(outputDir)
					: [];
				return JSON.stringify(
					{
						operation: input.operation,
						target,
						sha256: hash,
						outputDirectory: outputDir,
						command,
						args,
						reusedAnalysis: false,
						artifacts,
						artifactsTruncated: artifacts.length >= 200,
						durationMs: Date.now() - started,
						...result,
					},
					null,
					2,
				);
			});
		}
		if (
			input.operation === "assemble_smali" ||
			input.operation === "rebuild_apk"
		) {
			if (!input.output_file || !path.isAbsolute(input.output_file)) {
				throw new Error(
					"output_file must be an absolute path for Smali assembly or APK rebuilding",
				);
			}
			const outputFile = path.resolve(input.output_file);
			const expectedExtension =
				input.operation === "assemble_smali" ? ".dex" : ".apk";
			if (path.extname(outputFile).toLowerCase() !== expectedExtension) {
				throw new Error(
					`output_file must end with ${expectedExtension} for ${input.operation}`,
				);
			}
			const command =
				input.operation === "assemble_smali"
					? androidUtilities.smali
					: androidUtilities.apktool;
			if (!command) {
				throw new Error(
					input.operation === "assemble_smali"
						? "smali was not found. Install its launcher and add it to PATH."
						: "apktool was not found. Install apktool and add it to PATH.",
				);
			}
			await fs.mkdir(path.dirname(outputFile), {
				recursive: true,
				mode: 0o700,
			});
			const temporaryOutput = `${outputFile}.${process.pid}.${Date.now()}.tmp${expectedExtension}`;
			const args =
				input.operation === "assemble_smali"
					? [
							"assemble",
							target,
							"-o",
							temporaryOutput,
							...(input.smali_api_level
								? ["--api", String(input.smali_api_level)]
								: []),
						]
					: ["b", "-f", target, "-o", temporaryOutput];
			return withAnalysisLock(target, async () => {
				const result = await runSupervised(
					command,
					args,
					input.timeout_ms ?? 300_000,
					context.signal,
				);
				const succeeded =
					result.exitCode === 0 &&
					!result.timedOut &&
					!result.cancelled &&
					(await exists(temporaryOutput));
				if (succeeded) {
					await fs.rm(outputFile, { force: true });
					await fs.rename(temporaryOutput, outputFile);
				} else {
					await fs.rm(temporaryOutput, { force: true });
				}
				return JSON.stringify(
					{
						operation: input.operation,
						target,
						sha256: hash,
						outputFile,
						command,
						args,
						durationMs: Date.now() - started,
						...result,
						succeeded,
					},
					null,
					2,
				);
			});
		}
		const engine =
			input.engine === "auto" ? chooseAuto(target, available) : input.engine;
		if (!engine)
			throw new Error(
				"No compatible reverse-engineering engine was found. Configure GHIDRA_HOME, IDA_HOME/IDADIR, or JADX_HOME.",
			);
		const gui = input.operation === "open_gui";
		const command = gui ? await discover(engine, true) : available[engine];
		if (!command) throw new Error(`${engine} executable was not found`);
		const { outputDir, persistent } = await resolveAnalysisDirectory(
			input.output_directory,
			input.reuse_analysis !== false,
			hash,
			engine,
		);
		await fs.mkdir(outputDir, { recursive: true, mode: 0o700 });
		const timeoutMs = input.timeout_ms ?? 300_000;

		return withAnalysisLock(outputDir, async () => {
			const existingManifest = await readAnalysisManifest(outputDir);
			const sameArtifact =
				existingManifest?.sha256 === hash &&
				existingManifest?.engine === engine;
			const projectName = `cline-${hash.slice(0, 16)}`;
			const ghidraProject = path.join(outputDir, `${projectName}.gpr`);
			const idaDatabase = path.join(outputDir, "analysis.i64");
			let reusedAnalysis = false;
			let args: string[];

			if (engine === "ghidra") {
				if (gui) {
					args = [(await exists(ghidraProject)) ? ghidraProject : target];
					reusedAnalysis = args[0] === ghidraProject;
				} else {
					const projectExists = sameArtifact && (await exists(ghidraProject));
					reusedAnalysis = projectExists;
					args = projectExists
						? [outputDir, projectName, "-process", path.basename(target)]
						: [outputDir, projectName, "-import", target, "-overwrite"];
					args.push(
						"-analysisTimeoutPerFile",
						String(Math.max(1, Math.floor(timeoutMs / 1000))),
					);
					if (input.max_cpu) {
						args.push("-max-cpu", String(input.max_cpu));
					}
					const scriptPaths: string[] = [];
					const postScripts: string[] = [];
					if (input.operation === "decompile") {
						const decompileScript =
							await ensureGhidraDecompileScript(outputDir);
						scriptPaths.push(path.dirname(decompileScript));
						postScripts.push(
							"-postScript",
							path.basename(decompileScript),
							path.join(outputDir, "decompiled.c"),
						);
					}
					if (input.script_path) {
						scriptPaths.push(path.dirname(input.script_path));
						postScripts.push(
							"-postScript",
							path.basename(input.script_path),
							...(input.script_args ?? []),
						);
					}
					if (scriptPaths.length > 0) {
						args.push(
							"-scriptPath",
							[...new Set(scriptPaths)].join(path.delimiter),
							...postScripts,
						);
					}
				}
			} else if (engine === "ida") {
				const databaseExists = sameArtifact && (await exists(idaDatabase));
				reusedAnalysis = databaseExists;
				if (gui) {
					args = [databaseExists ? idaDatabase : target];
				} else {
					args = ["-A", `-L${path.join(outputDir, "ida.log")}`];
					if (!databaseExists) args.push(`-o${idaDatabase}`);
					if (input.operation === "decompile") {
						const decompilerOptions = databaseExists
							? "-Ohexrays:-nosave"
							: "-Ohexrays";
						args.push(
							`${decompilerOptions}:${path.join(outputDir, "decompiled.c")}:ALL`,
						);
					}
					if (input.script_path) {
						args.push(
							`-S${[input.script_path, ...(input.script_args ?? [])]
								.map(shellLikeQuote)
								.join(" ")}`,
						);
					}
					args.push(databaseExists ? idaDatabase : target);
				}
			} else if (gui) {
				args = [target];
			} else {
				args = [
					"-d",
					outputDir,
					"--decompilation-mode",
					input.jadx_mode ?? "auto",
					"--output-format",
					input.jadx_output_format ?? "java",
				];
				if (input.jadx_threads)
					args.push("--threads-count", String(input.jadx_threads));
				if (input.jadx_single_class)
					args.push("--single-class", input.jadx_single_class);
				if (input.jadx_deobfuscate) args.push("--deobf");
				if (input.jadx_call_graph)
					args.push("--call-graph", input.jadx_call_graph);
				if (input.jadx_export_gradle) args.push("--export-gradle");
				if (input.jadx_no_resources) args.push("--no-res");
				if (input.jadx_no_sources) args.push("--no-src");
				if (input.jadx_mappings_path) {
					if (!path.isAbsolute(input.jadx_mappings_path)) {
						throw new Error("jadx_mappings_path must be an absolute path");
					}
					args.push("--mappings-path", input.jadx_mappings_path);
				}
				args.push(target);
				reusedAnalysis = sameArtifact;
			}

			if (gui) {
				return JSON.stringify(
					{
						engine,
						operation: input.operation,
						target,
						sha256: hash,
						command,
						outputDirectory: outputDir,
						reusedAnalysis,
						handoffTarget: args[0],
						...launchGui(command, args),
					},
					null,
					2,
				);
			}
			const result = await runSupervised(
				command,
				args,
				timeoutMs,
				context.signal,
			);
			const succeeded =
				result.exitCode === 0 && !result.timedOut && !result.cancelled;
			if (succeeded) {
				await writeAnalysisManifest(outputDir, {
					schemaVersion: 1,
					sha256: hash,
					target,
					engine,
					engineVersion: await toolVersion(engine, available[engine]),
					operation: input.operation,
					updatedAt: new Date().toISOString(),
				});
			}
			const artifacts = await listGeneratedArtifacts(outputDir);
			return JSON.stringify(
				{
					engine,
					operation: input.operation,
					target,
					sha256: hash,
					outputDirectory: outputDir,
					persistent,
					reusedAnalysis,
					command,
					args,
					durationMs: Date.now() - started,
					artifacts,
					artifactsTruncated: artifacts.length >= 200,
					...result,
				},
				null,
				2,
			);
		});
	};
}
