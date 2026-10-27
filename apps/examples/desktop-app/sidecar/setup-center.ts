import {
	GHIDRA_ACCEPTANCE_ARCHITECTURES,
	ghidraAcceptanceFixture,
	type GhidraAcceptanceArchitecture,
} from "./ghidra-fixtures";
import { emulationConfigurationStatus } from "./emulation-client";
import { createSetupFixtureDirectory } from "./setup-fixture-directory";
import { getSetupJob } from "./setup-jobs";
import { createReadStream } from "node:fs";
import { execFile } from "node:child_process";
import { createHash, createPublicKey } from "node:crypto";
import {
	lstat,
	realpath,
	mkdir,
	readFile,
	readdir,
	rename,
	writeFile,
} from "node:fs/promises";
import { isAbsolute, join, relative } from "node:path";
import { promisify } from "node:util";
import {
	ADVANCED_ANALYSIS_WORKER,
	RE_SPECIALIST_WORKER,
	SETUP_ENGINE_ROUTES,
	setupCapabilityCatalog,
	createReverseEngineeringExecutor,
	getAnalysisRuntimeIdentity,
	runAdvancedAnalysis,
} from "@cline/core";
import { readFileStrippingUtf8Bom } from "@cline/shared/node";
import { resolveClineDataDir } from "@cline/shared/storage";
import { z } from "zod";
import { version as desktopVersion } from "../package.json";
import ownedArm64Elf from "../../../../scripts/fixtures/owned-arm64-elf.json";
import ownedElf from "../../../../scripts/fixtures/owned-native-elf.json";
import {
	analysisSandboxConfigurationStatus,
	probeAnalysisSandbox,
} from "./analysis-sandbox-client";
import {
	activateBundledCapabilityPack,
	installedCapabilityPackRoot,
	verifyRuntime,
} from "./bundled-analysis-runtime";
import { privateUpdateReadiness } from "./trusted-update";

const execute = promisify(execFile);
const Preferences = z
	.object({
		schemaVersion: z.literal(1),
		idaHome: z.string().max(4096).default(""),
		ghidraHome: z.string().max(4096).default(""),
		adbPath: z.string().max(4096).default(""),
		deviceSerial: z
			.string()
			.regex(/^[A-Za-z0-9._:-]{1,120}$/)
			.or(z.literal(""))
			.default(""),
		deviceKind: z.enum(["physical", "emulator"]).default("physical"),
		acceptedPlatformToolsLicense: z.boolean().default(false),
		workerEndpoint: z.string().max(4096).default(""),
		workerPublicKey: z.string().max(4096).default(""),
	})
	.strict();
export type SetupPreferences = z.infer<typeof Preferences>;
const directory = () => join(resolveClineDataDir(), "setup-center");
async function readOwnedJson(name: string, limit = 131072): Promise<unknown> {
	const path = join(directory(), name);
	const info = await lstat(path);
	if (!info.isFile() || info.isSymbolicLink() || info.size > limit)
		throw new Error("Invalid setup record");
	return JSON.parse(await readFileStrippingUtf8Bom(path));
}
async function saveOwnedJson(name: string, value: unknown) {
	await mkdir(directory(), { recursive: true, mode: 0o700 });
	if ((await lstat(directory())).isSymbolicLink())
		throw new Error("Linked setup directory forbidden");
	const path = join(directory(), name),
		temporary = `${path}.${process.pid}.tmp`;
	await writeFile(temporary, JSON.stringify(value, null, 2), { mode: 0o600 });
	await rename(temporary, path);
}
export async function readSetupPreferences(): Promise<SetupPreferences> {
	try {
		return Preferences.parse(await readOwnedJson("preferences.json", 16384));
	} catch {
		return Preferences.parse({ schemaVersion: 1 });
	}
}
export function validateSetupPreferences(input: unknown) {
	const value = Preferences.parse(input);
	for (const path of [value.idaHome, value.ghidraHome, value.adbPath])
		if (path && (!isAbsolute(path) || /[\0\r\n]/.test(path)))
			throw new Error("Absolute installation path required");
	if (Boolean(value.workerEndpoint) !== Boolean(value.workerPublicKey))
		throw new Error(
			"Worker URL and pinned public key must be supplied together",
		);
	if (value.workerEndpoint) {
		const url = new URL(value.workerEndpoint);
		if (
			url.protocol !== "https:" ||
			url.username ||
			url.password ||
			url.search ||
			url.hash ||
			url.pathname !== "/"
		)
			throw new Error("Credential-free root HTTPS worker URL required");
		if (
			!value.workerPublicKey.trim().startsWith("-----BEGIN PUBLIC KEY-----") ||
			/PRIVATE KEY/.test(value.workerPublicKey) ||
			createPublicKey(value.workerPublicKey).asymmetricKeyType !== "ed25519"
		)
			throw new Error(
				"Pinned Ed25519 public key required; never paste a private key",
			);
	}
	return value;
}
function applyPreferences(value: SetupPreferences, explicit = false) {
	if (value.adbPath) process.env.ADB_PATH = value.adbPath;
	else if (explicit) delete process.env.ADB_PATH;
	if (value.idaHome) {
		process.env.IDA_HOME = value.idaHome;
		process.env.CLINE_IDA_SELECTED_HOME = value.idaHome;
	} else if (explicit) {
		delete process.env.IDA_HOME;
		delete process.env.CLINE_IDA_SELECTED_HOME;
	}
	if (value.ghidraHome) {
		process.env.GHIDRA_HOME = value.ghidraHome;
		process.env.CLINE_GHIDRA_SELECTED_HOME = value.ghidraHome;
	} else if (explicit) {
		delete process.env.GHIDRA_HOME;
		delete process.env.CLINE_GHIDRA_SELECTED_HOME;
	}
	if (value.workerEndpoint) {
		process.env.CLINE_ANALYSIS_SANDBOX_WORKER = value.workerEndpoint;
		process.env.CLINE_ANALYSIS_SANDBOX_PUBLIC_KEY = value.workerPublicKey;
	} else if (explicit) {
		delete process.env.CLINE_ANALYSIS_SANDBOX_WORKER;
		delete process.env.CLINE_ANALYSIS_SANDBOX_PUBLIC_KEY;
	}
}
export async function loadSetupPreferences() {
	applyPreferences(await readSetupPreferences());
}
export async function saveSetupPreferences(input: unknown) {
	const value = validateSetupPreferences(input);
	if (value.idaHome) {
		const info = await lstat(value.idaHome);
		if (!info.isDirectory() || info.isSymbolicLink())
			throw new Error("Non-linked IDA installation directory required");
	}
	if (value.ghidraHome) {
		const info = await lstat(value.ghidraHome);
		if (!info.isDirectory() || info.isSymbolicLink())
			throw new Error("Non-linked Ghidra installation directory required");
	}
	if (value.adbPath) {
		const info = await lstat(value.adbPath);
		if (!info.isFile() || info.isSymbolicLink())
			throw new Error("Non-linked ADB executable required");
	}
	const previous = await readSetupPreferences();
	await saveOwnedJson("preferences.previous.json", previous);
	await saveOwnedJson("preferences.json", value);
	applyPreferences(value, true);
	return {
		saved: true,
		restartRequired: true,
		message:
			"Saved. Restart an existing shared backend before using changed IDA, Ghidra or worker settings; running jobs were not interrupted.",
	};
}
export const FULL_ENGINE_IDS = [
	"lief",
	"capstone",
	"z3",
	"triton",
	"qbindiff",
	"androguard",
	"miasm",
	"unicorn",
	"angr",
	"qbdi",
	"cryptography",
] as const;
export type SetupCheck = {
	engine: string;
	status: string;
	executionVerified?: boolean;
	version?: string;
	reason?: string;
	scope?: string;
};
export function fullReceiptPassed(checks: SetupCheck[]) {
	return (
		checks.length === FULL_ENGINE_IDS.length &&
		FULL_ENGINE_IDS.every(
			(id) =>
				checks.filter(
					(c) =>
						c.engine === id &&
						c.status === "completed" &&
						c.executionVerified === true,
				).length === 1,
		)
	);
}
function receiptIdentity() {
	const identity = getAnalysisRuntimeIdentity();
	return `${identity.runtimeId ?? identity.source}:${identity.manifestHash ?? "external"}:${process.env.CLINE_ANGR_RUNTIME_ID ?? "no-angr-pack"}:${createHash("sha256").update(ADVANCED_ANALYSIS_WORKER).digest("hex")}`;
}
async function requireSetupWorkerTermination(
	result: {
		diagnostics?: { pid?: number | null; terminationConfirmed?: boolean };
	},
	identity: string,
) {
	if (
		result.diagnostics?.pid != null &&
		result.diagnostics.terminationConfirmed === false
	) {
		await saveOwnedJson("full-receipt.json", {
			schemaVersion: 1,
			identity,
			checkedAt: new Date().toISOString(),
			status: "failed",
			checks: [],
			reason: "Worker termination unconfirmed; setup admission retained",
		});
		throw Object.assign(
			new Error(
				"Setup worker termination unconfirmed; inspect Diagnostics before operator recovery",
			),
			{ terminationUnconfirmed: true },
		);
	}
}
let checking: Promise<unknown> | undefined;
export function testFullCapabilityPack(
	phase: (value: string) => void = () => {},
) {
	if (checking) return checking;
	checking = (async () => {
		const identity = receiptIdentity();
		phase("Testing full-pack owned engine fixtures");
		const primary = await runAdvancedAnalysis({
			action: "full_readiness",
			timeoutMs: 120000,
		});
		await requireSetupWorkerTermination(primary, identity);
		phase("Testing isolated angr static VEX fixture");
		const secondary = await runAdvancedAnalysis({
			action: "angr_readiness",
			timeoutMs: 120000,
		});
		await requireSetupWorkerTermination(secondary, identity);
		const checks = (
			Array.isArray(primary.evidence.checks) ? primary.evidence.checks : []
		) as SetupCheck[];
		checks.push({
			engine: "angr",
			status: secondary.status,
			executionVerified:
				secondary.status === "completed" &&
				secondary.evidence.hostExecution === false,
			version: secondary.engineVersion ?? undefined,
			reason:
				typeof secondary.evidence.reason === "string"
					? secondary.evidence.reason
					: undefined,
			scope: "fixed-owned-static-VEX-lift",
		});
		const receipt = {
			schemaVersion: 1,
			identity,
			checkedAt: new Date().toISOString(),
			status:
				identity === receiptIdentity() && fullReceiptPassed(checks)
					? "passed"
					: "failed",
			checks,
			limits: [
				"Owned fixture proof only; not target-wide correctness, VM isolation, licensing or real-device acceptance.",
			],
		};
		await saveOwnedJson("full-receipt.json", receipt);
		return receipt;
	})().finally(() => {
		checking = undefined;
	});
	return checking;
}
export async function bundledPlatformTools() {
	const core = installedCapabilityPackRoot("core");
	if (!core) throw new Error("Installed platform-tools resources unavailable");
	const root = join(core, "..", "android-platform-tools");
	await verifyRuntime(root, undefined, ["adb.exe", "NOTICE.txt"]);
	return {
		root,
		executable: join(root, "adb.exe"),
		notice: join(root, "NOTICE.txt"),
	};
}
export async function platformToolsNotices() {
	const tools = await bundledPlatformTools();
	const info = await lstat(tools.notice);
	if (!info.isFile() || info.size > 2 * 1024 * 1024)
		throw new Error("Platform-tools notice budget exceeded");
	return {
		notice: await readFile(tools.notice, "utf8"),
		source:
			"Official Android platform-tools 37.0.1. Included third-party notices must be reviewed.",
	};
}
export async function installFullCapabilityPack(
	phase: (value: string) => void = () => {},
) {
	phase("Verifying bundled platform-tools integrity");
	const tools = await bundledPlatformTools();
	phase("Verifying and activating immutable full capability packs");
	const activation = await activateBundledCapabilityPack("full");
	const preferences = await readSetupPreferences();
	if (!preferences.adbPath)
		await saveSetupPreferences({
			...preferences,
			adbPath: tools.executable,
			acceptedPlatformToolsLicense: true,
		});
	const receipt = await testFullCapabilityPack(phase);
	return { activation, receipt };
}
export async function rollbackToCorePack(
	phase: (value: string) => void = () => {},
) {
	phase("Verifying and selecting core runtime; prior packs are preserved");
	return await activateBundledCapabilityPack("core");
}
export async function detectInstalledTools() {
	const preferences = await readSetupPreferences();
	const candidates: string[] = [];
	if (preferences.idaHome) candidates.push(preferences.idaHome);
	if (process.env.IDA_HOME) candidates.push(process.env.IDA_HOME);
	for (const root of [
		process.env.ProgramFiles,
		process.env["ProgramFiles(x86)"],
	].filter((p): p is string => Boolean(p))) {
		const { readdir } = await import("node:fs/promises");
		for (const entry of (
			await readdir(root, { withFileTypes: true }).catch(() => [])
		).slice(0, 256))
			if (
				entry.isDirectory() &&
				!entry.isSymbolicLink() &&
				/^IDA(?:\s|$)/i.test(entry.name)
			)
				candidates.push(join(root, entry.name));
	}
	return { idaCandidates: [...new Set(candidates)].slice(0, 12), preferences };
}
export async function listSetupDevices() {
	const value = await readSetupPreferences();
	if (!value.adbPath)
		return {
			devices: [],
			reason: "Select an installed ADB executable. No phone is modified.",
		};
	const result = await execute(value.adbPath, ["devices", "-l"], {
		timeout: 5000,
		maxBuffer: 65536,
		windowsHide: true,
		env: process.env,
	});
	const devices = result.stdout
		.split(/\r?\n/)
		.slice(1)
		.map((line) => line.trim().split(/\s+/))
		.filter(
			(parts) => parts.length >= 2 && /^[A-Za-z0-9._:-]{1,120}$/.test(parts[0]),
		)
		.slice(0, 32)
		.map((parts) => ({ serial: parts[0], state: parts[1] }));
	return {
		devices,
		reason:
			"Discovery only; no install, root, flash, unlock or capture is performed.",
	};
}
export async function testSetupDevice() {
	const p = await readSetupPreferences();
	if (!p.adbPath || !p.deviceSerial)
		throw new Error(
			"Select the exact installed ADB executable and device serial first",
		);
	const listed = await listSetupDevices();
	if (
		!listed.devices.some(
			(d) => d.serial === p.deviceSerial && d.state === "device",
		)
	)
		throw new Error(
			"Selected device is offline or not authorized; approve debugging on your own device",
		);
	const args = ["-s", p.deviceSerial, "shell", "getprop", "ro.kernel.qemu"];
	const probe = await execute(p.adbPath, args, {
		timeout: 5000,
		maxBuffer: 4096,
		windowsHide: true,
		env: process.env,
	});
	const kind = probe.stdout.trim() === "1" ? "emulator" : "physical";
	if (kind !== p.deviceKind)
		throw new Error(
			"Selected device kind does not match the actual read-only probe",
		);
	const receipt = {
		status: "passed",
		kind,
		adbPath: p.adbPath,
		deviceSerialSha256: createHash("sha256")
			.update(p.deviceSerial)
			.digest("hex"),
		checkedAt: new Date().toISOString(),
		scope:
			"ADB connectivity only; not Frida/root/capture or hardware attestation",
	};
	await saveOwnedJson("device-receipt.json", receipt);
	return receipt;
}
export async function hashIdaExecutable(file: string, home: string) {
	return hashSetupExecutable(file, home, "IDA");
}
async function hashSetupExecutable(file: string, home: string, label: string) {
	if (!isAbsolute(file))
		throw new Error(
			`${label} acceptance requires an absolute executable identity`,
		);
	const [root, executable] = await Promise.all([
		realpath(home),
		realpath(file),
	]);
	const child = relative(root, executable);
	if (
		!child ||
		child === ".." ||
		child.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) ||
		isAbsolute(child)
	)
		throw new Error(
			`${label} acceptance executable is outside the selected installation`,
		);
	const info = await lstat(file);
	if (!info.isFile() || info.isSymbolicLink() || info.size > 512 * 1024 * 1024)
		throw new Error(`Invalid ${label} acceptance executable`);
	const hash = createHash("sha256");
	for await (const chunk of createReadStream(file, {
		highWaterMark: 64 * 1024,
	}))
		hash.update(chunk);
	return hash.digest("hex");
}
export async function currentIdaAcceptance(
	receipt: Record<string, unknown> | null,
	home: string,
	expectedArchitecture?: "x86_64" | "arm64",
) {
	const architecture = expectedArchitecture ?? receipt?.architecture;
	if (architecture !== "x86_64" && architecture !== "arm64") return false;
	const fixture = architecture === "arm64" ? ownedArm64Elf : ownedElf;
	if (
		receipt?.architecture !== architecture ||
		receipt.fixtureSha256 !== fixture.sha256
	)
		return false;
	if (
		!home ||
		receipt?.status !== "passed" ||
		receipt.idaHome !== home ||
		typeof receipt.executable !== "string" ||
		typeof receipt.executableSha256 !== "string"
	)
		return false;
	try {
		return (
			(await hashIdaExecutable(receipt.executable, home)) ===
			receipt.executableSha256
		);
	} catch {
		return false;
	}
}
export async function testLicensedIda(
	architecture: "x86_64" | "arm64" = "x86_64",
) {
	if (!["x86_64", "arm64"].includes(architecture))
		throw new Error("Unsupported IDA acceptance architecture");
	const fixture = architecture === "arm64" ? ownedArm64Elf : ownedElf;
	const preferences = await readSetupPreferences();
	if (!preferences.idaHome)
		throw new Error("Choose your authorized IDA installation first");
	applyPreferences(preferences);
	await mkdir(directory(), { recursive: true, mode: 0o700 });
	const root = await createSetupFixtureDirectory("ida");
	const bytes = Buffer.from(fixture.base64, "base64");
	if (createHash("sha256").update(bytes).digest("hex") !== fixture.sha256)
		throw new Error("Owned ELF identity mismatch");
	const target = join(root, "owned.so");
	await writeFile(target, bytes, { flag: "wx", mode: 0o600 });
	const raw = await createReverseEngineeringExecutor()(
		{
			engine: "ida",
			operation: "decompile",
			target,
			function_selector: { address: fixture.functionAddress },
			output_directory: join(root, "analysis"),
			timeout_ms: 120000,
		},
		{} as never,
	);
	const result = JSON.parse(raw);
	const executable = result.engineExecutable?.path;
	const executableSha256 = result.engineExecutable?.sha256;
	const identityMatches =
		typeof executable === "string" &&
		typeof executableSha256 === "string" &&
		(await hashIdaExecutable(executable, preferences.idaHome)) ===
			executableSha256;
	const receipt = {
		status:
			result.succeeded &&
			result.artifactVerified &&
			result.sha256 === fixture.sha256 &&
			identityMatches
				? "passed"
				: "failed",
		architecture,
		executable,
		executableSha256,
		checkedAt: new Date().toISOString(),
		idaHome: preferences.idaHome,
		fixtureSha256: fixture.sha256,
		scope: `Owned selected ${architecture} function only; not all processor licenses or target compatibility`,
		result,
	};
	await saveOwnedJson(`ida-receipt-${architecture}.json`, receipt);
	if (architecture === "x86_64")
		await saveOwnedJson("ida-receipt.json", receipt);
	return receipt;
}
// Status reads do not launch Java. Only explicit owned acceptance establishes readiness.
async function ghidraIdentity(home: string, includeEnvironment = true) {
	const executable = join(
		home,
		"support",
		process.platform === "win32" ? "analyzeHeadless.bat" : "analyzeHeadless",
	);
	const hash = createHash("sha256");
	for (const file of [
		executable,
		join(
			home,
			"support",
			process.platform === "win32" ? "launch.bat" : "launch.sh",
		),
		join(home, "support", "LaunchSupport.jar"),
		join(home, "Ghidra", "application.properties"),
		join(home, "support", "launch.properties"),
	]) {
		const stat = await lstat(file);
		if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024 * 1024)
			throw new Error("Invalid Ghidra launcher/configuration");
		hash.update(file);
		hash.update(await readFile(file));
	}
	if (includeEnvironment) {
		// These inputs affect Java discovery, JVM startup and headless execution.
		// Length-delimited JSON prevents adjacent values from sharing a fingerprint.
		hash.update(
			JSON.stringify(
				[
					"JAVA_HOME",
					"PATH",
					"GHIDRA_JAVA_OPTIONS",
					"GHIDRA_HEADLESS_JAVA_OPTIONS",
					"GHIDRA_HEADLESS_MAXMEM",
					"JAVA_TOOL_OPTIONS",
					"JDK_JAVA_OPTIONS",
					"_JAVA_OPTIONS",
				].map((name) => [name, process.env[name] ?? null]),
			),
		);
	}
	return hash.digest("hex");
}
/** Binds acceptance to the installed processor definitions and native decompiler.
 * This is not a seal of the complete Ghidra/JDK/OS distribution. No process launch. */
async function ghidraProfileIdentity(
	home: string,
	architecture: GhidraAcceptanceArchitecture,
) {
	const processor = { x86_64: "x86", arm32: "ARM", arm64: "AARCH64" }[
		architecture
	];
	const hash = createHash("sha256");
	let files = 0,
		total = 0,
		directories = 0;
	async function add(file: string, label: string) {
		const info = await lstat(file);
		if (
			!info.isFile() ||
			info.isSymbolicLink() ||
			++files > 512 ||
			(total += info.size) > 128 * 1024 * 1024
		)
			throw new Error("Ghidra profile identity budget/link");
		hash.update(JSON.stringify([label, info.size]));
		for await (const block of createReadStream(file)) hash.update(block);
	}
	async function walk(directory: string, prefix = "", depth = 0) {
		if (++directories > 512 || depth > 16)
			throw new Error("Ghidra processor directory budget");
		const info = await lstat(directory);
		if (!info.isDirectory() || info.isSymbolicLink())
			throw new Error("Linked Ghidra processor directory forbidden");
		const names = (await readdir(directory)).sort();
		if (names.length > 512)
			throw new Error("Ghidra processor inventory budget");
		for (const name of names) {
			const file = join(directory, name),
				stat = await lstat(file);
			if (stat.isSymbolicLink())
				throw new Error("Linked Ghidra processor member forbidden");
			if (stat.isDirectory()) await walk(file, prefix + name + "/", depth + 1);
			else await add(file, prefix + name);
		}
	}
	await walk(
		join(home, "Ghidra", "Processors", processor, "data", "languages"),
	);
	if (!files) throw new Error("Ghidra processor definitions missing");
	const os =
		process.platform === "win32"
			? "win"
			: process.platform === "darwin"
				? "mac"
				: "linux";
	const cpu = process.arch === "arm64" ? "arm_64" : "x86_64";
	await add(
		join(
			home,
			"Ghidra",
			"Features",
			"Decompiler",
			"os",
			`${os}_${cpu}`,
			process.platform === "win32" ? "decompile.exe" : "decompile",
		),
		"native-decompiler",
	);
	return hash.digest("hex");
}
export async function currentGhidraAcceptance(
	receipt: Record<string, unknown> | null,
	home: string,
	expectedArchitecture?: GhidraAcceptanceArchitecture,
) {
	try {
		const fixture = ghidraAcceptanceFixture(
			expectedArchitecture ?? String(receipt?.architecture ?? ""),
		);
		if (
			!home ||
			receipt?.schemaVersion !== 2 ||
			receipt.architecture !== fixture.architecture ||
			typeof receipt.languageId !== "string" ||
			!receipt.languageId.startsWith(fixture.languagePrefix) ||
			receipt.status !== "passed" ||
			receipt.ghidraHome !== home ||
			receipt.fixtureSha256 !== fixture.sha256 ||
			typeof receipt.javaHome !== "string" ||
			!isAbsolute(receipt.javaHome)
		)
			return false;
		const java = join(
			receipt.javaHome,
			"bin",
			process.platform === "win32" ? "java.exe" : "java",
		);
		return (
			receipt.identity === (await ghidraIdentity(home)) &&
			receipt.profileIdentity ===
				(await ghidraProfileIdentity(
					home,
					fixture.architecture as GhidraAcceptanceArchitecture,
				)) &&
			receipt.javaSha256 ===
				(await hashSetupExecutable(java, receipt.javaHome, "Ghidra Java"))
		);
	} catch {
		return false;
	}
}
export async function testGhidraIntegration(
	architecture: GhidraAcceptanceArchitecture = "x86_64",
) {
	const fixture = ghidraAcceptanceFixture(architecture);
	const preferences = await readSetupPreferences();
	if (!preferences.ghidraHome)
		throw new Error("Select your Ghidra installation first");
	applyPreferences(preferences);
	const identity = await ghidraIdentity(preferences.ghidraHome);
	const configIdentity = await ghidraIdentity(preferences.ghidraHome, false);
	const profileIdentity = await ghidraProfileIdentity(
		preferences.ghidraHome,
		architecture,
	);
	await mkdir(directory(), { recursive: true, mode: 0o700 });
	const root = await createSetupFixtureDirectory("ghidra");
	const bytes = Buffer.from(fixture.base64, "base64");
	if (createHash("sha256").update(bytes).digest("hex") !== fixture.sha256)
		throw new Error("Owned Ghidra fixture identity mismatch");
	const target = join(root, "owned.so");
	await writeFile(target, bytes, { flag: "wx", mode: 0o600 });
	let receipt: Record<string, unknown> = {
		schemaVersion: 2,
		architecture,
		profileIdentity,
		status: "failed",
		ghidraHome: preferences.ghidraHome,
		identity,
		fixtureSha256: fixture.sha256,
		checkedAt: new Date().toISOString(),
		scope: `Owned ${architecture} selected function and compatible Java only; no target execution`,
	};
	try {
		const result = JSON.parse(
			await createReverseEngineeringExecutor()(
				{
					engine: "ghidra",
					operation: "decompile",
					target,
					function_selector: { address: fixture.functionAddress },
					output_directory: join(root, "analysis"),
					timeout_ms: 120000,
					max_cpu: 2,
				},
				{} as never,
			),
		);
		if (
			!result.succeeded ||
			!result.artifactVerified ||
			!result.databaseVerified ||
			result.sha256 !== fixture.sha256
		)
			throw new Error(
				String(
					result.stderr ||
						result.stdout ||
						"Ghidra project/decompilation verification failed",
				).slice(-4000),
			);
		const info = await lstat(
			join(root, "analysis", "ghidra-analysis-receipt.json"),
		);
		if (!info.isFile() || info.isSymbolicLink() || info.size > 16384)
			throw new Error("Invalid Ghidra receipt");
		const actual = JSON.parse(
			await readFile(
				join(root, "analysis", "ghidra-analysis-receipt.json"),
				"utf8",
			),
		);
		if (
			typeof actual.javaHome !== "string" ||
			!isAbsolute(actual.javaHome) ||
			typeof actual.javaVersion !== "string" ||
			typeof actual.languageId !== "string" ||
			!actual.languageId.startsWith(fixture.languagePrefix)
		)
			throw new Error("Ghidra Java runtime identity missing");
		const java = join(
			actual.javaHome,
			"bin",
			process.platform === "win32" ? "java.exe" : "java",
		);
		receipt = {
			...receipt,
			status:
				configIdentity ===
					(await ghidraIdentity(preferences.ghidraHome, false)) &&
				profileIdentity ===
					(await ghidraProfileIdentity(preferences.ghidraHome, architecture))
					? "passed"
					: "failed",
			identity: await ghidraIdentity(preferences.ghidraHome),
			languageId: actual.languageId,
			javaHome: actual.javaHome,
			javaVersion: actual.javaVersion,
			javaSha256: await hashSetupExecutable(
				java,
				actual.javaHome,
				"Ghidra Java",
			),
			engineVersion: result.engineVersion,
		};
	} catch (error) {
		receipt = {
			...receipt,
			error:
				error instanceof Error ? error.message : "Ghidra acceptance failed",
		};
	}
	await saveOwnedJson(`ghidra-receipt-${architecture}.json`, receipt);
	if (architecture === "x86_64")
		await saveOwnedJson("ghidra-receipt.json", receipt);
	if (receipt.status !== "passed")
		throw new Error(
			String(receipt.error ?? "Ghidra installation changed during acceptance"),
		);
	return receipt;
}
export async function testAllGhidraIntegrations(
	phase: (value: string) => void = () => {},
) {
	const failures: string[] = [];
	const receipts: Record<string, unknown>[] = [];
	for (const architecture of GHIDRA_ACCEPTANCE_ARCHITECTURES) {
		phase(
			`Testing Ghidra ${architecture} owned selected function and Java; no target execution`,
		);
		try {
			receipts.push(await testGhidraIntegration(architecture));
		} catch {
			failures.push(architecture);
		}
	}
	if (failures.length)
		throw new Error(
			`Ghidra owned tests failed for ${failures.join(", ")}; inspect per-architecture results. Successful siblings are retained.`,
		);
	return {
		status: "passed",
		scope: "Owned selected functions only; not arbitrary target compatibility",
		receipts,
	};
}
/** Read-only receipt projection. Does not launch Java, Ghidra, fixtures or providers. */
export async function getGhidraReadiness() {
	const preferences = await readSetupPreferences();
	const profiles = await Promise.all(
		GHIDRA_ACCEPTANCE_ARCHITECTURES.map(async (architecture) => {
			const receipt = (await readOwnedJson(
				`ghidra-receipt-${architecture}.json`,
			).catch(() =>
				architecture === "x86_64"
					? readOwnedJson("ghidra-receipt.json").catch(() => null)
					: null,
			)) as Record<string, unknown> | null;
			const passed = await currentGhidraAcceptance(
				receipt,
				preferences.ghidraHome,
				architecture,
			);
			const sameHome = Boolean(
				receipt && receipt.ghidraHome === preferences.ghidraHome,
			);
			return {
				architecture,
				status: passed
					? "passed"
					: sameHome && receipt?.status === "failed"
						? "failed"
						: receipt
							? "stale"
							: "not-tested",
				checkedAt:
					typeof receipt?.checkedAt === "string"
						? receipt.checkedAt
						: undefined,
				javaVersion: passed ? String(receipt?.javaVersion) : undefined,
				reason: passed
					? "Owned selected-function decompilation passed; arbitrary target compatibility remains separate"
					: sameHome && typeof receipt?.error === "string"
						? receipt.error
						: "Run this architecture's explicit owned test",
			};
		}),
	);
	const passed = profiles.filter((p) => p.status === "passed");
	return {
		status:
			passed.length === profiles.length
				? "Ready for tested profiles"
				: passed.length
					? "Partially tested"
					: profiles.some((p) => p.status === "failed")
						? "Test failed"
						: preferences.ghidraHome
							? "Not tested or stale"
							: "Setup needed",
		javaStatus: passed.length
			? "Verified by current owned analysis"
			: "Not verified by a current owned analysis",
		javaVersion: passed[0]?.javaVersion,
		reason: passed.length
			? `Owned profiles passed: ${passed.map((p) => p.architecture).join(", ")}. Other profiles and arbitrary targets are not certified.`
			: (profiles.find((p) => p.status === "failed")?.reason ??
				"Select Ghidra and run explicit owned profile tests; a compatible JDK is required."),
		profiles,
		scope:
			"Owned selected functions only; not a gate for direct analysis or permission to execute targets",
	};
}
export async function testSetupWorker() {
	const value = await readSetupPreferences();
	applyPreferences(value);
	const result = await probeAnalysisSandbox();
	await saveOwnedJson("worker-receipt.json", {
		checkedAt: new Date().toISOString(),
		endpoint: value.workerEndpoint,
		publicKeySha256: createHash("sha256")
			.update(value.workerPublicKey)
			.digest("hex"),
		...result,
	});
	return result;
}
export async function getSetupCenterStatus() {
	const preferences = await readSetupPreferences();
	const [idaReceipt, deviceReceipt, workerReceipt, arm64Receipt] =
		(await Promise.all(
			[
				"ida-receipt.json",
				"device-receipt.json",
				"worker-receipt.json",
				"ida-receipt-arm64.json",
			].map((name) => readOwnedJson(name).catch(() => null)),
		)) as Array<Record<string, unknown> | null>;
	const ghidraReadiness = await getGhidraReadiness();
	const licensedArchitectures = [];
	if (await currentIdaAcceptance(idaReceipt, preferences.idaHome, "x86_64"))
		licensedArchitectures.push("x86_64");
	if (await currentIdaAcceptance(arm64Receipt, preferences.idaHome, "arm64"))
		licensedArchitectures.push("arm64");
	const deviceCurrent =
		deviceReceipt?.adbPath === preferences.adbPath &&
		deviceReceipt?.deviceSerialSha256 ===
			createHash("sha256").update(preferences.deviceSerial).digest("hex") &&
		deviceReceipt?.kind === preferences.deviceKind;
	const workerCurrent =
		workerReceipt?.endpoint === preferences.workerEndpoint &&
		workerReceipt?.publicKeySha256 ===
			createHash("sha256").update(preferences.workerPublicKey).digest("hex");
	const runtime = getAnalysisRuntimeIdentity();
	const receipt = (await readOwnedJson("full-receipt.json").catch(
		() => null,
	)) as {
		identity?: string;
		status?: string;
		checks?: SetupCheck[];
		checkedAt?: string;
	} | null;
	const current =
		receipt?.identity === receiptIdentity() && runtime.integrity !== "failed";
	const fullInstalled =
		runtime.integrity === "verified" &&
		runtime.runtimeId?.includes("-full-") === true;
	const features = FULL_ENGINE_IDS.map((engine) => {
		const check = current
			? receipt?.checks?.find((c) => c.engine === engine)
			: undefined;
		return {
			id: engine,
			label: engine,
			aiRoute:
				SETUP_ENGINE_ROUTES.find((r) => r.id === engine)?.action ??
				"full_readiness (owned fixture only)",
			state:
				runtime.integrity === "failed"
					? "failed"
					: receipt && !current
						? "stale"
						: check?.status === "completed" && check.executionVerified === true
							? "ready"
							: check?.status === "failed"
								? "failed"
								: check?.status === "blocked"
									? "blocked"
									: fullInstalled
										? "installed_not_tested"
										: "setup_required",
			status:
				runtime.integrity === "failed"
					? "Integrity failed"
					: receipt && !current
						? "Stale"
						: check?.status === "completed" && check.executionVerified === true
							? "Ready"
							: check?.status === "failed"
								? "Test failed"
								: check?.status === "blocked"
									? "Blocked"
									: fullInstalled
										? "Installed, not tested"
										: "Setup needed",
			reason:
				runtime.integrity === "failed"
					? "Repair or roll back the runtime before testing"
					: receipt && !current
						? "Runtime or worker identity changed; retest actual execution"
						: (check?.reason ??
							(check
								? "Owned fixture tested"
								: "Install the full pack, then test actual execution")),
			version: check?.version,
		};
	});
	const packs = await Promise.all(
		(["core", "full", "angr"] as const).map(async (pack) => {
			const root = installedCapabilityPackRoot(pack);
			return {
				id: pack,
				available: Boolean(
					root &&
						(await lstat(join(root, "runtime-manifest.json")).catch(
							() => undefined,
						)),
				),
				selected:
					pack === "full"
						? runtime.runtimeId?.includes("-full-") === true
						: pack === "core"
							? !runtime.runtimeId?.includes("-full-")
							: Boolean(process.env.CLINE_ANGR_PYTHON),
			};
		}),
	);
	return {
		preferences,
		aiCapabilities: setupCapabilityCatalog(),
		optionalFrameworks: ["qiling", "unidbg", "rnidbg", "speakeasy"].map(
			(id) => ({
				id,
				configuration:
					id === "speakeasy"
						? analysisSandboxConfigurationStatus()
						: emulationConfigurationStatus(
								id as "qiling" | "unidbg" | "rnidbg",
							),
				installation: "not-bundled-or-managed" as const,
				readiness: "not-established" as const,
			}),
		),
		specialistProfiles: await specialistProfileHistory(),
		setupJob: getSetupJob(),
		runtime,
		packs,
		features,
		fullStatus:
			current &&
			receipt?.status === "passed" &&
			fullReceiptPassed(receipt.checks ?? [])
				? "Ready"
				: "Setup needed",
		checkedAt: current ? receipt?.checkedAt : undefined,
		lastCheckedAt: receipt?.checkedAt,
		desktopBuild: {
			version: desktopVersion,
			sourceCommit: process.env.CLINE_DESKTOP_BUILD_COMMIT ?? "development",
			capabilitySchema: "setup-center/processor-acceptance-v3",
		},
		selectedRuntime: {
			runtimeId: runtime.runtimeId,
			source: runtime.source,
			integrity: runtime.integrity,
		},
		ghidra: ghidraReadiness,
		licensedArchitectures,
		licensedStatus: licensedArchitectures.length
			? `Owned IDA acceptance passed for ${licensedArchitectures.join(", ")}; other processors and target compatibility remain untested`
			: preferences.idaHome
				? "IDA installation selected; optional integration test has not established processor readiness. Analysis may run directly and report actual runtime/plugin errors."
				: "Select your installed IDA folder to use IDA analysis. The integration test is optional.",
		deviceStatus:
			deviceCurrent && deviceReceipt?.status === "passed"
				? "Last selected device connectivity test passed; reconnect and retest before device work"
				: "Device needed until an exact device connectivity test passes",
		workerStatus:
			workerCurrent && workerReceipt?.ready === true
				? "Last signed worker capability probe passed; submission rechecks identity"
				: "Configure and explicitly test a signed isolated worker",
		updates: privateUpdateReadiness(),
		limitations: [
			"The Python pack test does not test Ghidra, IDA, devices or workers; use their separate explicit tests.",
			"Install all covers bundled local engine packs only; it does not install Qiling, unidbg, rnidbg or Speakeasy workers. Device authorization remains separate.",
			"Unicorn emulates bounded bytes; angr performs static VEX lifting. QBDI target tracing still requires an approved signed isolated worker.",
			"Pack activation and rollback preserve old runtime files and project data; existing shared Hub processes require a separate backend restart.",
		],
	};
}

function specialistProfileIdentity(engine: "angr" | "joern") {
	return createHash("sha256")
		.update(
			JSON.stringify({
				base: receiptIdentity(),
				engine,
				worker: RE_SPECIALIST_WORKER,
				python:
					engine === "angr"
						? (process.env.CLINE_ANGR_PYTHON ??
							process.env.CLINE_RE_PYTHON ??
							"PATH-default")
						: (process.env.CLINE_RE_PYTHON ?? "PATH-default"),
				joernHome:
					engine === "joern" ? (process.env.CLINE_JOERN_HOME ?? null) : null,
				joernManifest:
					engine === "joern"
						? (process.env.CLINE_JOERN_MANIFEST_SHA256 ?? null)
						: null,
			}),
		)
		.digest("hex");
}

/** Optional profiles never contribute to the existing eleven-engine full receipt. */
export async function testSpecialistProfile(engine: "angr" | "joern") {
	if (!["angr", "joern"].includes(engine))
		throw new Error("Unsupported specialist engine");
	const identity = specialistProfileIdentity(engine);
	const result = await runAdvancedAnalysis({
		action: "specialist_readiness",
		options: { specialist_readiness: { engine } },
		timeoutMs: 240000,
		limit: 20,
	});
	await requireSetupWorkerTermination(result, identity);
	const passed =
		identity === specialistProfileIdentity(engine) &&
		result.status === "completed" &&
		result.evidence.ownedFixturePassed === true;
	const receipt = {
		engine,
		identity,
		joernManifest: process.env.CLINE_JOERN_MANIFEST_SHA256 ?? null,
		checkedAt: new Date().toISOString(),
		status: passed
			? "passed"
			: result.status === "completed"
				? "failed"
				: result.status,
		result,
	};
	await saveOwnedJson(`specialist-${engine}.json`, receipt);
	return receipt;
}
async function specialistProfileHistory() {
	return await Promise.all(
		(["angr", "joern"] as const).map(async (engine) => {
			let receipt:
				| {
						identity?: string;
						joernManifest?: string | null;
						status?: string;
						checkedAt?: string;
				  }
				| undefined;
			try {
				receipt = (await readOwnedJson(
					`specialist-${engine}.json`,
				)) as typeof receipt;
			} catch {
				/* No receipt, no readiness claim. */
			}
			const current =
				receipt?.identity === specialistProfileIdentity(engine) &&
				(engine !== "joern" ||
					receipt?.joernManifest ===
						(process.env.CLINE_JOERN_MANIFEST_SHA256 ?? null));
			return {
				id: engine,
				status: receipt ? (current ? receipt.status : "stale") : "not-tested",
				checkedAt: receipt?.checkedAt,
				scope:
					"Last owned-fixture result only; runtime integrity and target support rechecked at execution",
			};
		}),
	);
}
