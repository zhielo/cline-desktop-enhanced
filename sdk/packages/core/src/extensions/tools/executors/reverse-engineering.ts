import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { inflateRaw } from "node:zlib";
import { promisify } from "node:util";
import type { ReverseEngineeringInput } from "../schemas";
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
				path.join(root, "support", win ? "analyzeHeadless.bat" : "analyzeHeadless"),
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
		return [...roots.flatMap((root) => names.map((name) => path.join(root, name))), ...names];
	}
	const home = process.env.JADX_HOME;
	const roots = [...(home ? [home] : []), ...discoveredRoots];
	const names = win ? ["jadx.bat", "jadx-gui.bat"] : ["jadx", "jadx-gui"];
	return [
		...roots.flatMap((root) =>
			names.flatMap((name) => [path.join(root, "bin", name), path.join(root, name)]),
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
		const child = spawn(locator, [command], { stdio: "ignore", windowsHide: true });
		child.once("error", () => resolve(false));
		child.once("exit", (code) => resolve(code === 0));
	});
}

async function discover(engine: Engine, gui = false): Promise<string | undefined> {
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
	for (const candidate of candidates) if (await commandAvailable(candidate)) return candidate;
	return undefined;
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
	return spawn(command, args, { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
}

async function runSupervised(command: string, args: string[], timeoutMs: number, signal?: AbortSignal) {
	return new Promise<{ exitCode: number | null; stdout: string; stderr: string; timedOut: boolean; cancelled: boolean }>((resolve, reject) => {
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
		child.stdout?.on("data", (chunk) => { stdout = boundedAppend(stdout, chunk); });
		child.stderr?.on("data", (chunk) => { stderr = boundedAppend(stderr, chunk); });
		const kill = () => {
			if (child.pid && process.platform === "win32") spawn("taskkill", ["/pid", String(child.pid), "/t", "/f"], { stdio: "ignore", windowsHide: true });
			else child.kill("SIGKILL");
		};
		const timer = setTimeout(() => { timedOut = true; kill(); }, timeoutMs);
		const abort = () => {
			cancelled = true;
			kill();
		};
		signal?.addEventListener("abort", abort, { once: true });
		child.once("error", (error) => { clearTimeout(timer); signal?.removeEventListener("abort", abort); reject(error); });
		child.once("exit", (exitCode) => { clearTimeout(timer); signal?.removeEventListener("abort", abort); resolve({ exitCode, stdout, stderr, timedOut, cancelled }); });
	});
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
		for (let i = tail.length - 22; i >= 0; i--) if (tail.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
		if (eocd < 0) throw new Error("ZIP end-of-central-directory record not found");
		const declaredEntries = tail.readUInt16LE(eocd + 10);
		const directorySize = tail.readUInt32LE(eocd + 12);
		const directoryOffset = tail.readUInt32LE(eocd + 16);
		if (declaredEntries === 0xffff || directorySize === 0xffffffff || directoryOffset === 0xffffffff) throw new Error("ZIP64 archives require a dedicated external inspector");
		if (declaredEntries > MAX_ZIP_ENTRIES || directorySize > MAX_ZIP_DIRECTORY_BYTES || directoryOffset + directorySize > stat.size) throw new Error("ZIP central directory exceeds safe inspection limits or file bounds");
		const directory = Buffer.alloc(directorySize);
		await handle.read(directory, 0, directorySize, directoryOffset);
		const seen = new Set<string>();
			const entries: ZipInspection["entries"] = [];
			const parsed: ZipEntry[] = [];
		let offset = 0;
		let unsafePaths = 0, symlinks = 0, duplicates = 0, suspiciousRatios = 0, parsedEntries = 0;
		let totalCompressed = 0, totalUncompressed = 0;
		while (offset < directory.length) {
			if (offset + 46 > directory.length || directory.readUInt32LE(offset) !== 0x02014b50) throw new Error("Malformed ZIP central directory");
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
			if (end > directory.length) throw new Error("ZIP entry exceeds central directory bounds");
			const name = directory.subarray(offset + 46, offset + 46 + nameLength).toString("utf8");
			const normalized = name.replace(/\\/g, "/");
			const unsafe = normalized.includes("\0") || normalized.startsWith("/") || /^[A-Za-z]:\//.test(normalized) || normalized.split("/").includes("..");
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
			if (unsafe) unsafePaths++; if (symlink) symlinks++; if (duplicate) duplicates++; if (ratio > 1000) suspiciousRatios++;
			totalCompressed += compressed; totalUncompressed += uncompressed; parsedEntries++;
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
		if (parsedEntries !== declaredEntries) throw new Error(`ZIP declared ${declaredEntries} entries but parsed ${parsedEntries}`);
			return { format: "zip", declaredEntries, parsedEntries, listedEntries: entries.length, entriesTruncated: parsedEntries > entries.length, totalCompressed, totalUncompressed, compressionRatio: totalUncompressed / Math.max(totalCompressed, 1), findings: { unsafePaths, symlinks, duplicates, suspiciousRatios }, extractionRecommended: unsafePaths === 0 && symlinks === 0 && duplicates === 0 && suspiciousRatios === 0, entries, parsed };
	} finally { await handle.close(); }
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

function archiveKind(target: string, entries: ZipEntry[]) {
	const extension = path.extname(target).toLowerCase();
	if (extension === ".apk") return "apk";
	if (extension === ".aab") return "aab";
	if (extension === ".jar") return "jar";
	if (entries.some((entry) => entry.normalized === "AndroidManifest.xml")) return "apk";
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

async function extractZip(target: string, outputDir: string, inspection: ZipInspection) {
	if (!inspection.extractionRecommended) {
		throw new Error(
			"Archive extraction refused because inspection found unsafe paths, symlinks, duplicate names, or suspicious compression ratios.",
		);
	}
	if (
		inspection.parsedEntries > MAX_EXTRACTED_ENTRIES ||
		inspection.totalUncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES
	) {
		throw new Error("Archive extraction exceeds configured entry or output-size limits.");
	}

	const input = await fs.open(target, "r");
	const created: string[] = [];
	try {
		for (const entry of inspection.parsed) {
			if (entry.uncompressedSize > MAX_ENTRY_UNCOMPRESSED_BYTES) {
				throw new Error(`Archive entry exceeds the per-entry limit: ${entry.name}`);
			}
			if (![0, 8].includes(entry.compressionMethod)) {
				throw new Error(
					`Unsupported ZIP compression method ${entry.compressionMethod} for ${entry.name}`,
				);
			}
			if ((entry.generalPurposeBitFlag & 0x1) !== 0) {
				throw new Error(`Encrypted ZIP entries are not supported: ${entry.name}`);
			}
			const destination = path.resolve(outputDir, ...entry.normalized.split("/"));
			const relative = path.relative(outputDir, destination);
			if (
				relative === ".." ||
				relative.startsWith(`..${path.sep}`) ||
				path.isAbsolute(relative)
			) {
				throw new Error(`Archive entry escapes the extraction root: ${entry.name}`);
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
			const dataOffset = entry.localHeaderOffset + 30 + nameLength + extraLength;
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
			await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
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
	if (!requested) return fs.mkdtemp(path.join(os.tmpdir(), "cline-re-extract-"));
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
	available: Record<Engine, string | undefined>,
) {
	const ghidraCommand = available.ghidra;
	const ghidraHome = installationRoot(ghidraCommand, "ghidra");
	const idaCommand = available.ida;
	const idaHome = installationRoot(idaCommand, "ida");
	const idalibActivationScript = idaHome
		? path.join(idaHome, "idalib", "python", "py-activate-idalib.py")
		: undefined;
	const bundledPyGhidra = ghidraHome
		? path.join(
				ghidraHome,
				"Ghidra",
				"Features",
				"PyGhidra",
				"pypkg",
				"dist",
			)
		: undefined;
	return {
		platform: process.platform,
		ghidra: {
			headless: ghidraCommand,
			gui: await discover("ghidra", true),
			installDirectory: ghidraHome,
			bundledPyGhidra:
				bundledPyGhidra && (await exists(bundledPyGhidra))
					? bundledPyGhidra
					: undefined,
		},
		ida: {
			headless: idaCommand,
			gui: await discover("ida", true),
			installDirectory: idaHome,
			idalibActivationScript:
				idalibActivationScript && (await exists(idalibActivationScript))
					? idalibActivationScript
					: undefined,
		},
		jadx: {
			cli: available.jadx,
			gui: await discover("jadx", true),
		},
	};
}

function chooseAuto(target: string, available: Record<Engine, string | undefined>): Engine | undefined {
	if ([".apk", ".aab", ".dex", ".jar"].includes(path.extname(target).toLowerCase()) && available.jadx) return "jadx";
	return available.ghidra ? "ghidra" : available.ida ? "ida" : available.jadx ? "jadx" : undefined;
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
		const available = { ghidra: await discover("ghidra"), ida: await discover("ida"), jadx: await discover("jadx") };
		if (input.operation === "discover") {
			const capabilities = await installationCapabilities(available);
			return JSON.stringify(
				{
					capabilities,
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
		if (!path.isAbsolute(input.target)) throw new Error("target must be an absolute path");
		if (input.operation === "script" && !input.script_path) throw new Error("script_path is required for the script operation");
		const target = path.resolve(input.target);
		const stat = await fs.stat(target);
		if (!stat.isFile()) throw new Error(`Target is not a file: ${target}`);
		const hash = await sha256(target);
			const zip = await isZip(target);
			if (input.operation === "inspect") {
				if (!zip) {
					return JSON.stringify(
						{ target, sha256: hash, size: stat.size, format: "binary" },
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
										dexFiles: names.filter((name) => /^classes\d*\.dex$/i.test(name)),
										nativeLibraries: names.filter((name) =>
											/^lib\/[^/]+\/[^/]+\.so$/i.test(name),
										).length,
									}
								: undefined,
					},
					null,
					2,
				);
			}
			if (input.operation === "extract") {
				if (!zip) throw new Error("extract currently supports ZIP, APK, AAB, and JAR containers");
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
		const engine = input.engine === "auto" ? chooseAuto(target, available) : input.engine;
		if (!engine) throw new Error("No compatible reverse-engineering engine was found. Configure GHIDRA_HOME, IDA_HOME/IDADIR, or JADX_HOME.");
		const gui = input.operation === "open_gui";
		const command = gui ? await discover(engine, true) : available[engine];
		if (!command) throw new Error(`${engine} executable was not found`);
			const outputDir = path.resolve(input.output_directory ?? await fs.mkdtemp(path.join(os.tmpdir(), "cline-re-")));
			await fs.mkdir(outputDir, { recursive: true, mode: 0o700 });
		let args: string[];
		if (engine === "ghidra") {
			if (gui) args = [target];
			else {
					const projectName = `cline-${hash.slice(0, 16)}`;
					args = [outputDir, projectName, "-import", target, "-overwrite", "-analysisTimeoutPerFile", String(Math.max(1, Math.floor((input.timeout_ms ?? 300_000) / 1000)))];
					if (input.script_path) {
						args.push(
							"-scriptPath",
							path.dirname(input.script_path),
							"-postScript",
							path.basename(input.script_path),
							...(input.script_args ?? []),
						);
					}
			}
		} else if (engine === "ida") {
			args = gui ? [target] : ["-A", `-L${path.join(outputDir, "ida.log")}`, `-o${path.join(outputDir, "analysis.i64")}`];
				if (!gui && input.operation === "decompile") {
					args.push(`-Ohexrays:-nosave:${path.join(outputDir, "decompiled.c")}`);
				}
				if (!gui && input.script_path) {
					args.push(
						`-S${[input.script_path, ...(input.script_args ?? [])]
							.map(shellLikeQuote)
							.join(" ")}`,
					);
				}
			args.push(target);
		} else args = gui ? [target] : ["-d", outputDir, target];
			if (gui) {
				return JSON.stringify(
					{
						engine,
						operation: input.operation,
						target,
						sha256: hash,
						command,
						...launchGui(command, args),
					},
					null,
					2,
				);
			}
		const result = await runSupervised(command, args, input.timeout_ms ?? 300_000, context.signal);
		return JSON.stringify({ engine, operation: input.operation, target, sha256: hash, outputDirectory: outputDir, command, durationMs: Date.now() - started, ...result }, null, 2);
	};
}
