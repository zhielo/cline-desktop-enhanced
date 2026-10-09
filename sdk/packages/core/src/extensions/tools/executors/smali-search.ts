import { constants } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { setImmediate as yieldTurn } from "node:timers/promises";

const activeScans = new Set<string>();
export type SmaliSearchOptions = {
	target: string;
	queries: string[];
	regex?: RegExp;
	contextLines: number;
	maxResults: number;
	excludeDirs?: string[];
	maxBytes?: number;
	timeoutMs?: number;
	signal?: AbortSignal;
	owner?: string;
	onProgress?: (text: string) => void;
};

/** Fixed read-only single-pass scan. No subprocess, target execution or cached outputs. */
export async function scanSmali(options: SmaliSearchOptions) {
	const queries = [...new Set(options.queries.map((q) => q.toLowerCase()))];
	if (
		!queries.length ||
		queries.length > 32 ||
		queries.some((q) => !q || q.length > 4096)
	)
		throw new Error(
			"Provide 1 to 32 nonempty Smali queries, each at most 4096 characters",
		);
	const maxBytes = options.maxBytes ?? 512 * 1024 * 1024;
	const timeoutMs = options.timeoutMs ?? 300_000;
	if (
		!Number.isInteger(maxBytes) ||
		maxBytes < 1 ||
		maxBytes > 2 * 1024 * 1024 * 1024 ||
		!Number.isInteger(timeoutMs) ||
		timeoutMs < 1 ||
		timeoutMs > 3_600_000
	)
		throw new Error("Invalid Smali scan byte or time budget");
	if (options.excludeDirs?.some((n) => !n || n.length > 128 || /[\\/]/.test(n)))
		throw new Error("Exclude directory basenames only");
	const excluded = new Set([
		".git",
		"node_modules",
		...(options.excludeDirs ?? []),
	]);
	const target = await fs.realpath(options.target);
	const key = JSON.stringify([
		options.owner ?? "local",
		target,
		[...queries].sort(),
		options.regex?.source,
		[...excluded].sort(),
		options.contextLines,
		options.maxResults,
		maxBytes,
	]);
	if (activeScans.has(key))
		throw new Error(
			"An identical Smali scan is already running in this host; observe it instead of starting duplicate work",
		);
	activeScans.add(key);
	const budget = new AbortController();
	const timer = setTimeout(
		() =>
			budget.abort(
				new Error("Smali scan lifetime deadline exceeded; no automatic retry"),
			),
		timeoutMs,
	);
	timer.unref();
	const signal = options.signal
		? AbortSignal.any([options.signal, budget.signal])
		: budget.signal;
	let entriesVisited = 0,
		discoveredFiles = 0,
		scannedFiles = 0,
		bytesRead = 0,
		skippedFiles = 0,
		excludedDirectories = 0,
		lastProgress = 0;
	const matches: Array<{
		path: string;
		line: number;
		method: string | null;
		text: string;
		context: string;
	}> = [];
	let stopReason: string | null = null;
	let outputChars = 0;
	function progress(stage: string, force = false) {
		if (!force && Date.now() - lastProgress < 1000) return;
		lastProgress = Date.now();
		options.onProgress?.(
			`[Smali scan] stage=${stage}; entries=${entriesVisited}; discovered_files=${discoveredFiles}; scanned_files=${scannedFiles}; bytes_read=${bytesRead}; matches=${matches.length}; skipped_files=${skippedFiles}. No percentage or completion inferred.\n`,
		);
	}
	try {
		signal.throwIfAborted();
		const initial = await fs.lstat(options.target);
		if (initial.isSymbolicLink())
			throw new Error("Smali scan root must not be a symbolic link");
		const stack = [target];
		progress("enumerating", true);
		while (stack.length && !stopReason) {
			signal.throwIfAborted();
			const current = stack.pop()!;
			const stat = await fs.lstat(current);
			if (stat.isSymbolicLink()) {
				skippedFiles++;
				continue;
			}
			if (stat.isDirectory()) {
				const dir = await fs.opendir(current);
				for await (const entry of dir) {
					signal.throwIfAborted();
					if (++entriesVisited > 100_000) {
						stopReason = "entry_limit";
						break;
					}
					if (entry.isDirectory()) {
						if (excluded.has(entry.name)) excludedDirectories++;
						else stack.push(path.join(current, entry.name));
					} else if (
						entry.isFile() &&
						entry.name.toLowerCase().endsWith(".smali")
					) {
						discoveredFiles++;
						stack.push(path.join(current, entry.name));
					} else if (entry.isSymbolicLink()) skippedFiles++;
					progress("enumerating");
				}
				continue;
			}
			if (!stat.isFile()) {
				skippedFiles++;
				continue;
			}
			if (current === target) discoveredFiles++;
			if (stat.size > 20 * 1024 * 1024) {
				skippedFiles++;
				continue;
			}
			if (bytesRead + stat.size > maxBytes) {
				stopReason = "byte_limit";
				break;
			}
			const handle = await fs.open(
				current,
				constants.O_RDONLY |
					(process.platform === "win32" ? 0 : constants.O_NOFOLLOW),
			);
			let text: string;
			try {
				const actual = await handle.stat();
				if (!actual.isFile() || actual.size > 20 * 1024 * 1024) {
					skippedFiles++;
					continue;
				}
				if (bytesRead + actual.size > maxBytes) {
					stopReason = "byte_limit";
					break;
				}
				// Bounded positional read: a concurrently growing file cannot bypass the byte ceiling.
				const buffer = Buffer.alloc(actual.size);
				let offset = 0;
				while (offset < buffer.length) {
					signal.throwIfAborted();
					const read = await handle.read(
						buffer,
						offset,
						Math.min(64 * 1024, buffer.length - offset),
						offset,
					);
					if (!read.bytesRead) break;
					offset += read.bytesRead;
				}
				bytesRead += offset;
				text = buffer.subarray(0, offset).toString("utf8");
			} finally {
				await handle.close();
			}
			scannedFiles++;
			progress("scanning");
			// Common miss path: avoid constructing tens of thousands of line/context arrays.
			const lowerText = options.regex ? "" : text.toLowerCase();
			if (!options.regex && !queries.some((q) => lowerText.includes(q)))
				continue;
			const lines = text.split(/\r?\n/);
			let method: string | null = null;
			for (let i = 0; i < lines.length; i++) {
				if (i % 1024 === 0) {
					await yieldTurn();
					signal.throwIfAborted();
				}
				const line = lines[i] ?? "",
					trimmed = line.trim();
				if (trimmed.startsWith(".method ")) method = trimmed.slice(8);
				else if (trimmed === ".end method") method = null;
				const lower = line.toLowerCase();
				if (
					!(options.regex
						? options.regex.test(line)
						: queries.some((q) => lower.includes(q)))
				)
					continue;
				const from = Math.max(0, i - options.contextLines),
					to = Math.min(lines.length, i + options.contextLines + 1);
				const result = {
					path: current,
					line: i + 1,
					method,
					text: line.slice(0, 4096),
					context: lines
						.slice(from, to)
						.map((l, n) => `${from + n + 1}: ${l.slice(0, 4096)}`)
						.join("\n")
						.slice(0, 16384),
				};
				const cost = JSON.stringify(result).length;
				if (outputChars + cost > 200_000) {
					stopReason = "output_limit";
					break;
				}
				outputChars += cost;
				matches.push(result);
				if (matches.length >= options.maxResults) {
					stopReason = "result_limit";
					break;
				}
			}
		}
		signal.throwIfAborted();
		progress(stopReason ? "partial" : "complete", true);
		return {
			queries: options.queries,
			regex: Boolean(options.regex),
			discoveredFiles,
			scannedFiles,
			bytesRead,
			skippedFiles,
			excludedDirectories,
			entriesVisited,
			matches,
			truncated: Boolean(stopReason),
			coverage: stopReason || skippedFiles ? "partial" : "completed",
			stopReason,
			hint: "Narrow target/exclusions for unresolved scope. Use read_smali_method with a returned path and signature. Skipped/limited scope is not whole-project absence evidence.",
		};
	} finally {
		clearTimeout(timer);
		activeScans.delete(key);
	}
}
