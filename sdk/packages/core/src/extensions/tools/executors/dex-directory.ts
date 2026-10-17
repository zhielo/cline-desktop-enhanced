import * as fs from "node:fs/promises";
import * as path from "node:path";

type ChildResult = {
	succeeded?: boolean;
	reusedAnalysis?: boolean;
	sha256?: string;
	outputDirectory?: string;
	timedOut?: boolean;
	cancelled?: boolean;
};
/** Flat, bounded, read-only-input batch. Child outputs remain in the existing managed cache. */
export async function disassembleDexDirectory(
	input: {
		target?: string;
		output_directory?: string;
		timeout_ms?: number;
		smali_api_level?: number;
		reuse_analysis?: boolean;
	},
	run: (
		request: {
			operation: "disassemble_smali";
			engine: "auto";
			target: string;
			timeout_ms: number;
			smali_api_level?: number;
			reuse_analysis?: boolean;
		},
		signal: AbortSignal,
	) => Promise<ChildResult>,
	signal?: AbortSignal,
) {
	if (!input.target || !path.isAbsolute(input.target))
		throw new Error("baksmali_dir requires an absolute directory target");
	if (input.output_directory)
		throw new Error(
			"baksmali_dir uses managed content-addressed outputs only; no external output directory",
		);
	const root = input.target;
	const stat = await fs.lstat(root);
	if (!stat.isDirectory() || stat.isSymbolicLink())
		throw new Error("baksmali_dir requires a real directory, not a symlink");
	const deadline = Date.now() + Math.min(input.timeout_ms ?? 120000, 600000);
	const combined = AbortSignal.any([
		...(signal ? [signal] : []),
		AbortSignal.timeout(Math.min(input.timeout_ms ?? 120000, 600000)),
	]);
	const files: string[] = [];
	const sizes = new Map<string, number>();
	let entries = 0;
	let bytes = 0;
	const directory = await fs.opendir(root);
	for await (const entry of directory) {
		combined.throwIfAborted();
		if (++entries > 256)
			throw new Error(
				"DEX directory exceeds 256-entry budget; select a narrower directory",
			);
		if (entry.isSymbolicLink())
			throw new Error("Symlink entries are not accepted in DEX batches");
		if (!entry.isFile() || !entry.name.toLowerCase().endsWith(".dex")) continue;
		const file = path.join(root, entry.name);
		const current = await fs.lstat(file);
		if (!current.isFile() || current.isSymbolicLink())
			throw new Error("DEX entry changed during inventory");
		bytes += current.size;
		if (bytes > 512 * 1024 * 1024 || files.length >= 32)
			throw new Error("DEX batch exceeds 32-file or 512 MiB budget");
		files.push(file);
		sizes.set(file, current.size);
	}
	files.sort();
	if (!files.length)
		throw new Error(
			"No top-level .dex files found; nested directories are not traversed",
		);
	const results: {
		file: string;
		status: string;
		sha256?: string;
		outputDirectory?: string;
		reused?: boolean;
		reason?: string;
	}[] = [];
	let status = "completed";
	for (const file of files) {
		if (combined.aborted) {
			status = signal?.aborted ? "cancelled" : "partial";
			break;
		}
		try {
			const current = await fs.lstat(file);
			if (
				!current.isFile() ||
				current.isSymbolicLink() ||
				current.size !== sizes.get(file)
			)
				throw new Error("DEX entry changed since inventory");
			const result = await run(
				{
					operation: "disassemble_smali",
					engine: "auto",
					target: file,
					timeout_ms: Math.max(1, deadline - Date.now()),
					smali_api_level: input.smali_api_level,
					reuse_analysis: input.reuse_analysis,
				},
				combined,
			);
			const succeeded =
				!combined.aborted &&
				(result.succeeded === true || result.reusedAnalysis === true);
			results.push({
				file: path.basename(file),
				status: succeeded ? "completed" : "failed",
				sha256: result.sha256,
				outputDirectory: result.outputDirectory,
				reused: result.reusedAnalysis === true,
			});
			if (!succeeded) {
				status = result.cancelled || signal?.aborted ? "cancelled" : "partial";
				break;
			}
		} catch {
			results.push({
				file: path.basename(file),
				status: combined.aborted ? "cancelled" : "failed",
				reason: combined.aborted
					? "Cancelled or deadline reached"
					: "Disassembly failed; inspect the child tool readiness and input",
			});
			status = signal?.aborted ? "cancelled" : "partial";
			break;
		}
	}
	return {
		operation: "baksmali_dir",
		status,
		target: root,
		inventoryBytes: bytes,
		results,
		skipped: files.slice(results.length).map((file) => path.basename(file)),
		coverage:
			"Top-level .dex files from a bounded inventory; not a recursive or live-directory completeness guarantee",
		limitations: [
			"Stops after first failed stage; completed content-addressed outputs are reusable, failed writes are not blindly replayed.",
			"No APK rebuild, target execution, external output routing, or approval expansion.",
		],
	};
}
