import { createHash } from "node:crypto";
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
	runtimeId: z.string().regex(/^[a-z0-9-]{1,100}$/),
	pythonVersion: z.string(),
	fixtureVersion: z.string(),
	files: z.record(z.string(), z.string().regex(/^[a-f0-9]{64}$/)),
});
let configuredRoot: string | undefined;
let manifestHash: string | undefined;
let repairing: Promise<unknown> | undefined;
export async function verifyRuntime(
	root: string,
	expectedManifestHash?: string,
) {
	if (!isAbsolute(root) || (await lstat(root)).isSymbolicLink())
		throw new Error("Absolute non-linked runtime root required");
	const canonical = await realpath(root);
	const bytes = await readFile(join(canonical, "runtime-manifest.json"));
	if (bytes.length > 4 * 1024 * 1024)
		throw new Error("Runtime manifest budget exceeded");
	const digest = createHash("sha256").update(bytes).digest("hex");
	if (expectedManifestHash && digest !== expectedManifestHash)
		throw new Error(
			"Installed runtime manifest changed; reinstall from trusted installer",
		);
	const manifest = Manifest.parse(JSON.parse(bytes.toString("utf8")));
	const entries = Object.entries(manifest.files);
	if (
		entries.length > 30000 ||
		!manifest.files["python.exe"] ||
		!manifest.files["python313._pth"]
	)
		throw new Error("Invalid runtime file inventory");
	const expectedPaths = new Set(entries.map(([name]) => name));
	let walked = 0;
	let totalBytes = 0;
	async function inspect(directory: string, prefix = "") {
		for (const entry of await readdir(directory, { withFileTypes: true })) {
			if (++walked > 40000)
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
		if (totalBytes > 512 * 1024 * 1024)
			throw new Error("Runtime total byte budget exceeded");
		if (
			rel.startsWith(`..${sep}`) ||
			isAbsolute(rel) ||
			info.isSymbolicLink() ||
			!info.isFile() ||
			info.size > 128 * 1024 * 1024
		)
			throw new Error("Redirected or oversized runtime member");
		if (
			createHash("sha256")
				.update(await readFile(path))
				.digest("hex") !== hash
		)
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
	configuredRoot = resolve(root);
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
		if (info.isFile() && !info.isSymbolicLink() && info.size <= 1024)
			preferBundled =
				JSON.parse(await readFile(preference, "utf8")).preferBundled === true;
	} catch {
		/* No saved selection; explicit external developer overrides remain intact. */
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
			selectedRoot = cached;
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
export async function repairBundledAnalysisRuntime() {
	if (repairing) return repairing;
	repairing = (async () => {
		if (!configuredRoot || !manifestHash)
			throw new Error(
				"Trusted bundled runtime unavailable. Reinstall the app; no pip or scripts are required.",
			);
		const source = await verifyRuntime(configuredRoot, manifestHash);
		const parent = join(resolveClineDataDir(), "analysis-runtime");
		await mkdir(parent, { recursive: true, mode: 0o700 });
		if ((await lstat(parent)).isSymbolicLink())
			throw new Error("Runtime repair directory link forbidden");
		const destination = join(
			await realpath(parent),
			`${source.manifest.runtimeId}-${manifestHash.slice(0, 16)}`,
		);
		const temporary = `${destination}.${process.pid}.repair`;
		await rm(temporary, { recursive: true, force: true });
		try {
			await cp(configuredRoot, temporary, {
				recursive: true,
				dereference: false,
			});
			await verifyRuntime(temporary, manifestHash);
			// Keep old runtime files intact while a worker may own them. First repair only;
			// an existing validated version is reused, never overwritten under active work.
			try {
				await lstat(destination);
				await verifyRuntime(destination, manifestHash);
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
				await rename(temporary, destination);
			}
			const preference = join(await realpath(parent), "preference.json");
			const stagedPreference = `${preference}.${process.pid}.tmp`;
			await writeFile(
				stagedPreference,
				JSON.stringify({ schemaVersion: 1, preferBundled: true }),
				{ mode: 0o600 },
			);
			await rename(stagedPreference, preference);
			process.env.CLINE_RE_PYTHON = join(destination, "python.exe");
			process.env.CLINE_ANALYSIS_RUNTIME_ID = `${source.manifest.runtimeId}:${manifestHash}`;
			configureAnalysisRuntime({
				source: "bundled",
				runtimeId: source.manifest.runtimeId,
				manifestHash,
			});
			return {
				status: "repaired",
				restartRequired: true,
				message:
					"Bundled runtime restored and its selection saved without network access. Existing shared Hub workers retain their interpreter until the backend restarts; running tasks were not interrupted.",
			};
		} finally {
			await rm(temporary, { recursive: true, force: true });
		}
	})().finally(() => {
		repairing = undefined;
	});
	return repairing;
}
