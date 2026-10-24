import { privateProcessGroupGone } from "../../runtime/private-process-group";
/** Fixed OS-bounded native parser adapter; not yet a public execution route. Never runs target code. */
import { constants, realpathSync } from "node:fs";
import { lstat, mkdtemp, open, opendir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { z } from "zod";
import { byteDigest } from "../contracts";
import { windowsJobInvocation } from "../../runtime/windows-job-launcher";
import { runSupervised } from "../../extensions/tools/executors/supervised-process";
import {
	GeneralRecoveryReportSchema,
	WAKARU_PINS,
	WAKARU_REVISION,
	type GeneralRecoveryReport,
} from "./contracts";
export class GeneralRecoveryTerminationUnconfirmedError extends Error {
	constructor() {
		super(
			"Recovery descendant termination was not confirmed; private scratch retained",
		);
		this.name = "GeneralRecoveryTerminationUnconfirmedError";
	}
}
const MAX_FILE = 1024 * 1024;
const MAX_TOTAL = 2 * 1024 * 1024;
const MAX_ENTRIES = 512;
const Entry = z.object({
	filename: z.string().max(512),
	kind: z.literal("javascript"),
	status: z.string().max(100),
});
const Report = z.object({
	detected_formats: z.array(z.string().max(100)).max(32),
	safety: z.string().max(100),
	modules: z.array(Entry).max(128),
	warnings: z
		.array(
			z.object({
				filename: z.string().max(512).optional(),
				kind: z.string().max(100),
				is_error: z.boolean(),
				message: z.string().max(4000),
			}),
		)
		.max(128),
	total: z.number().int().nonnegative().max(128),
	failed: z.number().int().nonnegative().max(128),
});
const Pair = z.tuple([
	z.number().int().nonnegative(),
	z.number().int().positive(),
]);
const Provenance = z.object({
	format: z.string().max(100),
	strategy: z.string().max(100),
	modules: z.record(
		z.string().max(512),
		z.object({
			input: z.string().max(4096),
			ranges: z.array(Pair).min(1).max(256),
			context_ranges: z.array(Pair).max(256).optional(),
			extraction: z.string().max(100),
		}),
	),
});
export function safeRecoveryName(value: string) {
	if (
		!value ||
		value.length > 512 ||
		/[\\\0\r\n:]/.test(value) ||
		path.posix.isAbsolute(value) ||
		value
			.split("/")
			.some(
				(p) =>
					!p ||
					p === "." ||
					p === ".." ||
					/[. ]$/.test(p) ||
					/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(p),
			)
	)
		throw new Error("Unsafe recovered output name");
	return value;
}
async function readStable(file: string, max: number) {
	const beforeName = await lstat(file);
	if (
		!beforeName.isFile() ||
		beforeName.isSymbolicLink() ||
		beforeName.nlink !== 1 ||
		beforeName.size > max
	)
		throw new Error("Invalid fixed recovery file");
	const handle = await open(
		file,
		constants.O_RDONLY |
			(process.platform === "win32" ? 0 : constants.O_NOFOLLOW),
	);
	try {
		const before = await handle.stat();
		if (!before.isFile() || before.size > max)
			throw new Error("Recovery file budget changed before read");
		const bytes = Buffer.alloc(before.size + 1);
		let count = 0;
		while (count < bytes.length) {
			const part = await handle.read(bytes, count, bytes.length - count, count);
			if (!part.bytesRead) break;
			count += part.bytesRead;
		}
		const after = await handle.stat(),
			named = await lstat(file);
		if (
			count !== before.size ||
			!after.isFile() ||
			!named.isFile() ||
			named.isSymbolicLink() ||
			[beforeName, after, named].some((s) =>
				["dev", "ino", "size", "mtimeMs", "ctimeMs", "nlink"].some(
					(k) => s[k as keyof typeof s] !== before[k as keyof typeof before],
				),
			)
		)
			throw new Error("Recovery file changed during read");
		return bytes.subarray(0, count);
	} finally {
		await handle.close();
	}
}
async function inventory(root: string) {
	const files = new Map<string, number>();
	let entries = 0,
		total = 0;
	async function walk(dir: string, prefix: string, depth: number) {
		if (depth > 8) throw new Error("Recovery directory depth exceeded");
		const children = await opendir(dir);
		for await (const item of children) {
			if (++entries > MAX_ENTRIES)
				throw new Error("Recovery entry budget exceeded");
			const name = safeRecoveryName(prefix + item.name),
				full = path.join(dir, item.name);
			const info = await lstat(full);
			if (info.isSymbolicLink())
				throw new Error("Recovery output links forbidden");
			if (info.isDirectory()) await walk(full, name + "/", depth + 1);
			else if (info.isFile() && info.nlink === 1) {
				total += info.size;
				if (info.size > MAX_FILE || total > MAX_TOTAL)
					throw new Error("Recovery output byte budget exceeded");
				files.set(name, info.size);
			} else
				throw new Error("Recovery output must contain ordinary private files");
		}
	}
	try {
		await walk(root, "", 0);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
	}
	return files;
}
/** Input is an already hash-admitted immutable copy. Root is host configuration, not model input. */
export async function runPinnedGeneralRecovery(
	bytes: Buffer,
	sourceSha256: string,
	signal?: AbortSignal,
): Promise<GeneralRecoveryReport> {
	if (
		bytes.length > MAX_FILE ||
		byteDigest(bytes) !== sourceSha256 ||
		!Buffer.from(bytes.toString("utf8")).equals(bytes)
	)
		throw new Error("Recovery needs exact bounded UTF-8 source");
	signal?.throwIfAborted();
	const platform = process.platform;
	if ((platform !== "linux" && platform !== "win32") || process.arch !== "x64")
		throw new Error("Pinned recovery supports Linux/Windows x64 only");
	const configuredRoot = process.env.CLINE_BUNDLED_ANALYSIS_ROOT;
	if (!configuredRoot || !path.isAbsolute(configuredRoot))
		throw new Error("Packaged general recovery engine unavailable");
	const root = realpathSync.native(configuredRoot),
		pin = WAKARU_PINS[platform];
	const engine = path.join(root, "wakaru", pin.file);
	if (
		realpathSync.native(engine) !== engine ||
		byteDigest(await readStable(engine, 64 * MAX_FILE)) !== pin.sha256
	)
		throw new Error("Pinned recovery executable identity mismatch");
	const scratch = await mkdtemp(path.join(tmpdir(), "cline-general-recovery-"));
	const abort = new AbortController();
	const stop = () => abort.abort();
	signal?.addEventListener("abort", stop, { once: true });
	let cleanupConfirmed = true;
	let monitor: ReturnType<typeof setInterval> | undefined,
		checking = false,
		budgetError: unknown;
	try {
		const input = path.join(scratch, "input.js"),
			output = path.join(scratch, "output");
		await writeFile(input, bytes, { flag: "wx", mode: 0o600 });
		const env: Record<string, string> = {
			HOME: scratch,
			USERPROFILE: scratch,
			TEMP: scratch,
			TMP: scratch,
			TMPDIR: scratch,
		};
		for (const key of ["SystemRoot", "SYSTEMROOT", "WINDIR"])
			if (process.env[key]) env[key] = process.env[key]!;
		if (signal?.aborted) abort.abort();
		monitor = setInterval(() => {
			if (checking || budgetError) return;
			checking = true;
			void inventory(output)
				.catch((error) => {
					budgetError = error;
					abort.abort();
				})
				.finally(() => {
					checking = false;
				});
		}, 100);
		const args = [
			input,
			"--unpack=strict",
			"--level=minimal",
			"--provenance",
			"--emit-source-map",
			"--json",
			"-o",
			output,
		];
		// This parser never launches the target. These OS limits contain the
		// fixed recovery executable; they are not a filesystem/network sandbox.
		const launch =
			platform === "win32"
				? windowsJobInvocation(engine, args, scratch, 2048, 4, 45000)
				: {
						executable: "/usr/bin/prlimit",
						args: [
							"--as=2147483648:2147483648",
							"--cpu=45:46",
							"--fsize=67108864:67108864",
							"--core=0:0",
							"--",
							engine,
							...args,
						],
					};
		const result = await runSupervised(
			launch.executable,
			launch.args,
			50000,
			abort.signal,
			undefined,
			env,
			true,
			scratch,
		);
		clearInterval(monitor);
		monitor = undefined;
		if (
			result.outputDrainTimedOut ||
			(platform === "linux" &&
				result.pid &&
				!privateProcessGroupGone(result.pid))
		)
			cleanupConfirmed = false;
		if (!cleanupConfirmed)
			throw new GeneralRecoveryTerminationUnconfirmedError();
		if (budgetError) throw budgetError;
		if (
			result.exitCode !== 0 ||
			result.cancelled ||
			result.timedOut ||
			result.truncated ||
			result.outputDrainTimedOut
		)
			throw new Error(
				"General recovery failed, exceeded deadline/output limits or did not confirm process drainage",
			);
		const report = Report.parse(JSON.parse(result.stdout));
		if (report.failed || report.total !== report.modules.length)
			throw new Error("Incomplete general recovery report");
		const files = await inventory(output);
		const provenance = Provenance.parse(
			JSON.parse(
				(
					await readStable(path.join(output, "provenance.json"), MAX_FILE)
				).toString("utf8"),
			),
		);
		if (Object.keys(provenance.modules).length !== report.modules.length)
			throw new Error("Recovery module/provenance set mismatch");
		const consumed = new Set(["provenance.json"]),
			names = new Set<string>();
		const ranges = (pairs: Array<[number, number]>) =>
			pairs.map(([startByte, endByte]) => {
				if (startByte >= endByte || endByte > bytes.length)
					throw new Error("Recovery original byte range outside input");
				return {
					startByte,
					endByte,
					sha256: byteDigest(bytes.subarray(startByte, endByte)),
				};
			});
		const modules: GeneralRecoveryReport["modules"] = [];
		for (const entry of report.modules) {
			const filename = safeRecoveryName(entry.filename),
				folded = filename.toLowerCase();
			if (
				!filename.endsWith(".js") ||
				names.has(folded) ||
				!files.has(filename)
			)
				throw new Error("Invalid/duplicate recovery module");
			names.add(folded);
			consumed.add(filename);
			const p = provenance.modules[filename];
			if (!p || path.resolve(p.input) !== input)
				throw new Error("Recovery provenance input mismatch");
			const content = await readStable(path.join(output, filename), MAX_FILE);
			if (!Buffer.from(content.toString("utf8")).equals(content))
				throw new Error("Recovered module is not UTF-8");
			let sourceMap: GeneralRecoveryReport["modules"][number]["sourceMap"];
			const mapName = filename + ".map";
			if (files.has(mapName)) {
				const encoded = await readStable(path.join(output, mapName), MAX_FILE);
				// Maps are retained as inert bytes, not interpreted as file/network references.
				sourceMap = {
					sha256: byteDigest(encoded),
					contentBase64: encoded.toString("base64"),
				};
				consumed.add(mapName);
			}
			modules.push({
				filename,
				status: entry.status,
				sha256: byteDigest(content),
				sourceBase64: content.toString("base64"),
				ranges: ranges(p.ranges),
				contextRanges: ranges(p.context_ranges ?? []),
				extraction: p.extraction,
				...(sourceMap ? { sourceMap } : {}),
			});
		}
		if ([...files.keys()].some((f) => !consumed.has(f)))
			throw new Error("Unreported recovery output file");
		return GeneralRecoveryReportSchema.parse({
			protocol: "cline-general-recovery/1",
			engine: "wakaru/1.14.0",
			upstreamRevision: WAKARU_REVISION,
			engineSha256: pin.sha256,
			resourceBoundary:
				platform === "win32"
					? {
							kind: "windows-job-object-suspended-launch",
							memoryBytes: 2147483648,
							maxProcesses: 4,
							supervisorDeadlineMs: 45000,
						}
					: {
							kind: "linux-prlimit-process-group",
							addressSpaceBytes: 2147483648,
							cpuSoftSeconds: 45,
							cpuHardSeconds: 46,
							fileBytes: 67108864,
							hostDeadlineMs: 50000,
						},
			sourceSha256,
			detectedFormats: report.detected_formats,
			safety: report.safety,
			strategy: provenance.strategy,
			modules,
			warnings: report.warnings.map((w) => ({
				filename: w.filename,
				kind: w.kind,
				isError: w.is_error,
				message: w.message,
			})),
			targetExecuted: false,
			verifiedBehavior: false,
			limitations: [
				"Structural single-input recovery with minimal rewrites only. No claim of original names, full recovery or runtime equivalence; transformed source hashes are separate from original input-range hashes.",
				"Recovered modules and maps are inert data. No import, target execution, source-map fetch, package installation or automatic publication occurs.",
				"Fixed 1 MiB input, 128 modules, 2 MiB admitted file output, entry/depth and 45-second process budgets. Windows job commit and Linux per-process address/CPU/file limits apply. Output polling is not a hard disk quota or a filesystem/network sandbox.",
			],
		});
	} finally {
		if (monitor) clearInterval(monitor);
		signal?.removeEventListener("abort", stop);
		if (cleanupConfirmed) await rm(scratch, { recursive: true, force: true });
		// Unconfirmed drainage retains private scratch; never delete a tree
		// a possibly live owned process could still be writing.
	}
}
