import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import {
	cp,
	lstat,
	mkdir,
	readFile,
	readdir,
	realpath,
	rename,
	rm,
	writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { resolveClineDataDir } from "@cline/shared/storage";
import { configureAnalysisRuntime } from "@cline/core";
import { z } from "zod";
const Manifest = z.object({
	schemaVersion: z.literal(1),
	runtimeId: z.string().regex(/^[a-z0-9][a-z0-9.-]{0,99}$/),
	pythonVersion: z.string(),
	fixtureVersion: z.string(),
	files: z.record(z.string(), z.string().regex(/^[a-f0-9]{64}$/)),
});
let installedCoreRoot: string | undefined;
let configuredRoot: string | undefined;
let selectedPack: "core" | "full" = "core";
let manifestHash: string | undefined;
let repairing: Promise<unknown> | undefined;
export async function verifyRuntime(
	root: string,
	expectedManifestHash?: string,
  requiredFiles: readonly string[] = ["python.exe", "python313._pth"],
) {
	if (!isAbsolute(root) || (await lstat(root)).isSymbolicLink())
		throw new Error("Absolute non-linked runtime root required");
	const canonical = await realpath(root);
	const bytes = await readFile(join(canonical, "runtime-manifest.json"));
  if (bytes.length > 8 * 1024 * 1024)
		throw new Error("Runtime manifest budget exceeded");
	const digest = createHash("sha256").update(bytes).digest("hex");
	if (expectedManifestHash && digest !== expectedManifestHash)
		throw new Error(
			"Installed runtime manifest changed; reinstall from trusted installer",
		);
	const manifest = Manifest.parse(JSON.parse(bytes.toString("utf8")));
	const entries = Object.entries(manifest.files);
	if (
    entries.length > 60000 ||
    requiredFiles.some((name) => !manifest.files[name])
	)
		throw new Error("Invalid runtime file inventory");
	const expectedPaths = new Set(entries.map(([name]) => name));
	let walked = 0;
	let totalBytes = 0;
	async function inspect(directory: string, prefix = "") {
		for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (++walked > 80000)
				throw new Error("Runtime directory budget exceeded");
			if (entry.isSymbolicLink())
				throw new Error("Runtime directory link forbidden");
			const name = prefix + entry.name;
			if (entry.isDirectory())
				await inspect(join(directory, entry.name), `${name}/`);
			else if (
				entry.isFile() &&
				name !== "runtime-manifest.json" &&
				!expectedPaths.has(name)
			)
				throw new Error("Untracked runtime file; reinstall trusted installer");
		}
	}
	await inspect(canonical);
	for (const [name, hash] of entries) {
		if (
			!name ||
			name.includes("\\") ||
			name.split("/").some((p) => p === ".." || !p) ||
			isAbsolute(name)
		)
			throw new Error("Unsafe runtime member");
		const path = join(canonical, name);
		const canonicalPath = await realpath(path);
		const rel = relative(canonical, canonicalPath);
		const info = await lstat(path);
		totalBytes += info.size;
    if (totalBytes > 2 * 1024 * 1024 * 1024)
			throw new Error("Runtime total byte budget exceeded");
		if (
			rel.startsWith(`..${sep}`) ||
			isAbsolute(rel) ||
			info.isSymbolicLink() ||
			!info.isFile() ||
			info.size > 128 * 1024 * 1024
		)
			throw new Error("Redirected or oversized runtime member");
		// Hash with bounded stream buffers instead of allocating a whole native
		// library (up to 128 MiB) during every backend startup.
		const hasher = createHash("sha256");
		for await (const chunk of createReadStream(path, { highWaterMark: 64 * 1024 }))
			hasher.update(chunk);
		if (hasher.digest("hex") !== hash)
			throw new Error(
				"Runtime integrity check failed; reinstall from trusted installer",
			);
	}
	return { manifest, digest };
}
export async function initializeBundledAnalysisRuntime(
	platform: NodeJS.Platform = process.platform,
) {
	if (platform !== "win32") return;
	const root =
		process.env.CLINE_BUNDLED_ANALYSIS_ROOT ||
		join(dirname(process.execPath), "resources", "analysis-runtime");
	if (
		!process.env.CLINE_BUNDLED_ANALYSIS_ROOT &&
		!(await lstat(join(root, "runtime-manifest.json")).catch(() => undefined))
	)
		return;
  installedCoreRoot = resolve(root);
  configuredRoot = installedCoreRoot;
  selectedPack = "core";
	// Installed resource integrity is checked once per backend start, not per tool call.
	let verified: Awaited<ReturnType<typeof verifyRuntime>>;
	try {
		verified = await verifyRuntime(configuredRoot);
	} catch {
		process.env.CLINE_RE_PYTHON = join(configuredRoot, "blocked-runtime.exe");
		configureAnalysisRuntime({
			source: "bundled",
			integrity: "failed",
			reason:
				"Installed analysis runtime integrity failed. Reinstall the app from the trusted installer; coding remains available.",
		});
		return;
	}
	manifestHash = verified.digest;
	let preferBundled = false;
	try {
		const preference = join(
			resolveClineDataDir(),
			"analysis-runtime",
			"preference.json",
		);
		const info = await lstat(preference);
    if (info.isFile() && !info.isSymbolicLink() && info.size <= 1024) {
      const saved = JSON.parse(await readFile(preference, "utf8"));
      preferBundled = saved.preferBundled === true;
      if (preferBundled && saved.pack === "full") selectedPack = "full";
    }
	} catch {
		/* No saved selection; explicit external developer overrides remain intact. */
  }
  if (selectedPack === "full") {
    try {
      configuredRoot = join(
        dirname(installedCoreRoot),
        "analysis-runtime-full",
      );
      verified = await verifyRuntime(configuredRoot);
      manifestHash = verified.digest;
      const angrRoot = join(
        dirname(installedCoreRoot),
        "analysis-runtime-angr",
      );
      const angr = await verifyRuntime(angrRoot);
      const cache = join(
        resolveClineDataDir(),
        "analysis-runtime",
        `${angr.manifest.runtimeId}-${angr.digest.slice(0, 16)}`,
      );
      let chosen = angrRoot;
      try {
        await verifyRuntime(cache, angr.digest);
        chosen = await realpath(cache);
      } catch {
        /* Independently verified resources remain the only fallback. */
      }
      process.env.CLINE_ANGR_PYTHON = join(chosen, "python.exe");
      process.env.CLINE_ANGR_RUNTIME_ID = `${angr.manifest.runtimeId}:${angr.digest}`;
    } catch {
      process.env.CLINE_RE_PYTHON = join(configuredRoot, "blocked-runtime.exe");
      configureAnalysisRuntime({
        source: "bundled",
        integrity: "failed",
        reason:
          "Selected full capability pack failed integrity; choose core rollback or reinstall the trusted installer. Coding remains available.",
      });
      return;
    }
	}
	let selectedRoot = configuredRoot;
	if (preferBundled) {
		const cached = join(
			resolveClineDataDir(),
			"analysis-runtime",
			`${verified.manifest.runtimeId}-${verified.digest.slice(0, 16)}`,
		);
		try {
			await verifyRuntime(cached, verified.digest);
			selectedRoot = await realpath(cached);
		} catch {
			/* Only the independently verified installed resources are a safe fallback. */
		}
	}
	if (!process.env.CLINE_RE_PYTHON?.trim() || preferBundled) {
		process.env.CLINE_RE_PYTHON = join(selectedRoot, "python.exe");
		process.env.CLINE_ANALYSIS_RUNTIME_ID = `${verified.manifest.runtimeId}:${verified.digest}`;
		configureAnalysisRuntime({
			source: "bundled",
			runtimeId: verified.manifest.runtimeId,
			manifestHash: verified.digest,
			integrity: "verified",
		});
	}
}

export function installedCapabilityPackRoot(pack: "core" | "full" | "angr") {
  if (!installedCoreRoot) return undefined;
  return pack === "core"
    ? installedCoreRoot
    : join(dirname(installedCoreRoot), `analysis-runtime-${pack}`);
}
export async function activateBundledCapabilityPack(pack: "core" | "full") {
  if (repairing)
    throw new Error("A capability pack operation is already running");
	repairing = (async () => {
    const root = installedCapabilityPackRoot(pack);
    if (!root)
			throw new Error(
				"Trusted bundled runtime unavailable. Reinstall the app; no pip or scripts are required.",
			);
    const source = await verifyRuntime(
      root,
      pack === selectedPack ? manifestHash : undefined,
    );
		const parent = join(resolveClineDataDir(), "analysis-runtime");
		await mkdir(parent, { recursive: true, mode: 0o700 });
		if ((await lstat(parent)).isSymbolicLink())
			throw new Error("Runtime repair directory link forbidden");
    async function stage(
      sourceRoot: string,
      verified: Awaited<ReturnType<typeof verifyRuntime>>,
    ) {
		const destination = join(
			await realpath(parent),
        `${verified.manifest.runtimeId}-${verified.digest.slice(0, 16)}`,
		);
		const temporary = `${destination}.${process.pid}.repair`;
		await rm(temporary, { recursive: true, force: true });
		try {
        await cp(sourceRoot, temporary, {
				recursive: true,
				dereference: false,
			});
        await verifyRuntime(temporary, verified.digest);
			try {
				await lstat(destination);
          await verifyRuntime(destination, verified.digest);
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
				await rename(temporary, destination);
        }
        return destination;
      } finally {
        await rm(temporary, { recursive: true, force: true });
      }
    }
    const destination = await stage(root, source);
    let angrDestination: string | undefined;
    let angrIdentity: string | undefined;
    if (pack === "full") {
      const angrRoot = installedCapabilityPackRoot("angr");
      if (!angrRoot) throw new Error("Trusted angr pack unavailable");
      const angr = await verifyRuntime(angrRoot);
      angrDestination = await stage(angrRoot, angr);
      angrIdentity = `${angr.manifest.runtimeId}:${angr.digest}`;
			}
			const preference = join(await realpath(parent), "preference.json");
			const stagedPreference = `${preference}.${process.pid}.tmp`;
			await writeFile(
				stagedPreference,
      JSON.stringify({ schemaVersion: 1, preferBundled: true, pack }),
				{ mode: 0o600 },
			);
			await rename(stagedPreference, preference);
    configuredRoot = root;
    manifestHash = source.digest;
    selectedPack = pack;
			process.env.CLINE_RE_PYTHON = join(destination, "python.exe");
    if (angrDestination) {
      process.env.CLINE_ANGR_PYTHON = join(angrDestination, "python.exe");
      process.env.CLINE_ANGR_RUNTIME_ID = angrIdentity;
    } else {
      delete process.env.CLINE_ANGR_PYTHON;
      delete process.env.CLINE_ANGR_RUNTIME_ID;
    }
    process.env.CLINE_ANALYSIS_RUNTIME_ID = `${source.manifest.runtimeId}:${source.digest}`;
			configureAnalysisRuntime({
				source: "bundled",
				runtimeId: source.manifest.runtimeId,
      manifestHash: source.digest,
      integrity: "verified",
			});
			return {
				status: "repaired",
      pack,
				restartRequired: true,
				message:
					"Bundled runtime restored and its selection saved without network access. Existing shared Hub workers retain their interpreter until the backend restarts; running tasks were not interrupted.",
			};
	})().finally(() => {
		repairing = undefined;
	});
	return repairing;
}
export async function repairBundledAnalysisRuntime() {
  return activateBundledCapabilityPack(selectedPack);
}
