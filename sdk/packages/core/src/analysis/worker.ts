import { constants } from "node:fs";
import { lstat, open, opendir, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import {
	AnalysisInputSchema,
	type AnalysisResult,
	byteDigest,
	LIMITS,
	ResultSchema,
} from "./contracts";
import { analyzeSources, type SourceArtifact } from "./parser";

const sourceName = (p: string, extended = false) =>
	/\.(?:[cm]?[jt]s|[jt]sx)$/i.test(p) ||
	p.endsWith(".map") ||
	(extended && /\.(?:json|html?|node)$/i.test(p)) ||
	/\.(?:dll|exe)$/i.test(p) ||
	path.basename(p) === "package.json";
export function within(root: string, target: string) {
	const child = path.relative(root, target);
	return (
		child === "" ||
		(!path.isAbsolute(child) &&
			child !== ".." &&
			!child.startsWith(`..${path.sep}`))
	);
}
export async function confinedTarget(root: string, target: string) {
	if (/[\0\r\n]/.test(target)) throw new Error("Invalid target path");
	const lexical = path.resolve(root, target);
	if (!within(root, lexical))
		throw new Error("Target must remain in this session workspace");
	const actual = await realpath(lexical);
	if (!within(root, actual)) throw new Error("Linked target escapes workspace");
	if ((await lstat(lexical)).isSymbolicLink())
		throw new Error("Linked targets are not supported");
	return actual;
}
export async function readSources(
	root: string,
	target: string,
	budget = { entries: 0, bytes: 0, files: 0 },
	extended = false,
) {
	const sources: SourceArtifact[] = [],
		limitations: string[] = [];
	const note = (s: string) => {
		if (limitations.length < 80) limitations.push(s.slice(0, 1000));
	};
	const read = async (p: string, limit: number) => {
		const actual = await confinedTarget(root, p);
		const f = await open(
			actual,
			constants.O_RDONLY |
				(process.platform === "win32" ? 0 : constants.O_NOFOLLOW),
		);
		try {
			const before = await f.stat();
			if (!before.isFile() || before.size > limit)
				throw new Error("File exceeds supported byte budget");
			const bytes = Buffer.alloc(before.size + 1);
			let count = 0;
			while (count < bytes.length) {
				const r = await f.read(bytes, count, bytes.length - count, count);
				if (!r.bytesRead) break;
				count += r.bytesRead;
			}
			const after = await f.stat();
			if (
				count !== before.size ||
				after.size !== before.size ||
				after.mtimeMs !== before.mtimeMs ||
				(await realpath(actual)) !== actual
			)
				throw new Error("Artifact changed during read");
			return bytes.subarray(0, count);
		} finally {
			await f.close();
		}
	};
	const add = (name: string, data: Buffer) => {
		if (
			budget.files >= LIMITS.files ||
			data.length > LIMITS.sourceBytes ||
			budget.bytes + data.length > LIMITS.totalBytes
		) {
			note("Source file/byte budget reached; inventory is incomplete.");
			return;
		}
		budget.files++;
		budget.bytes += data.length;
		sources.push({
			path: name,
			bytes: data.length,
			sha256: byteDigest(data),
			source: /\.(?:dll|exe|node)$/i.test(name) ? "" : data.toString("utf8"),
			...(!Buffer.from(data.toString("utf8")).equals(data)
				? { rawBytes: data }
				: {}),
			...(/\.(?:dll|exe|node)$/i.test(name) ? { binary: data } : {}),
		});
	};
	const asar = async (p: string) => {
		const bytes = await read(p, LIMITS.archiveBytes);
		if (bytes.length < 16 || bytes.readUInt32LE(0) !== 4)
			throw new Error("Invalid ASAR pickle header");
		const headerSize = bytes.readUInt32LE(4),
			jsonSize = bytes.readUInt32LE(12),
			dataStart = 8 + headerSize;
		if (
			headerSize > LIMITS.sourceBytes ||
			headerSize < 8 ||
			jsonSize > headerSize - 8 ||
			dataStart > bytes.length
		)
			throw new Error("Invalid or oversized ASAR header");
		const header = JSON.parse(
			bytes.subarray(16, 16 + jsonSize).toString("utf8"),
		);
		const walk = (entries: unknown, prefix: string, depth: number) => {
			if (depth > LIMITS.depth) {
				note("ASAR depth budget reached.");
				return;
			}
			if (!entries || typeof entries !== "object" || Array.isArray(entries))
				throw new Error("Invalid ASAR directory");
			for (const [name, raw] of Object.entries(entries)) {
				if (++budget.entries > LIMITS.entries) {
					note("Inventory entry budget reached.");
					return;
				}
				if (
					!name ||
					/[/\\\0]/.test(name) ||
					name === "." ||
					name === ".." ||
					!raw ||
					typeof raw !== "object"
				)
					throw new Error("Unsafe ASAR entry");
				const e = raw as Record<string, unknown>,
					label = `${prefix}/${name}`;
				if (e.link || e.unpacked) {
					note(`Skipped linked/unpacked ASAR entry: ${label}`);
					continue;
				}
				if (e.files) {
					walk(e.files, label, depth + 1);
					continue;
				}
				if (!sourceName(name, extended)) continue;
				const offset =
					typeof e.offset === "string" && /^\d+$/.test(e.offset)
						? Number(e.offset)
						: NaN;
				const size = e.size;
				if (
					!Number.isSafeInteger(offset) ||
					typeof size !== "number" ||
					!Number.isSafeInteger(size) ||
					offset < 0 ||
					size < 0 ||
					dataStart + offset + size > bytes.length
				)
					throw new Error("Invalid ASAR source range");
				add(
					label,
					bytes.subarray(dataStart + offset, dataStart + offset + size),
				);
			}
		};
		walk(
			header.files,
			path.relative(root, p).split(path.sep).join("/") + "!",
			0,
		);
		note(
			"ASAR source hashes identify payload bytes; archive integrity metadata is not authenticated.",
		);
	};
	const visit = async (p: string, depth: number): Promise<void> => {
		if (
			budget.entries >= LIMITS.entries ||
			budget.files >= LIMITS.files ||
			budget.bytes >= LIMITS.totalBytes
		) {
			note("Inventory budget reached; remaining entries were not inspected.");
			return;
		}
		budget.entries++;
		const info = await lstat(p);
		if (info.isSymbolicLink()) {
			note("Skipped filesystem link.");
			return;
		}
		if (info.isDirectory()) {
			if (depth >= LIMITS.depth) {
				note("Directory depth budget reached.");
				return;
			}
			// Streaming directory enumeration is bounded even for huge directories.
			const dir = await opendir(p);
			for await (const entry of dir) {
				if ([".git", "node_modules", ".next", "target"].includes(entry.name)) {
					note(`Excluded ${entry.name} dependency/build directory.`);
					continue;
				}
				await visit(path.join(p, entry.name), depth + 1);
				if (
					budget.entries >= LIMITS.entries ||
					budget.files >= LIMITS.files ||
					budget.bytes >= LIMITS.totalBytes
				) {
					note("Inventory budget reached.");
					break;
				}
			}
		} else if (info.isFile()) {
			const name = path.relative(root, p).split(path.sep).join("/");
			try {
				if (p.endsWith(".asar")) await asar(p);
				else if (sourceName(p, extended))
					add(name, await read(p, LIMITS.sourceBytes));
			} catch (e) {
				note(
					`Unreadable/unsupported ${name}: ${e instanceof Error ? e.message : "read failure"}`,
				);
			}
		} else note("Skipped non-regular filesystem entry.");
	};
	await visit(await confinedTarget(root, target), 0);
	if (!sources.length)
		note(
			"No supported JavaScript/TypeScript/package metadata sources were inspected.",
		);
	sources.sort((a, b) => a.path.localeCompare(b.path));
	return { sources, limitations };
}
export async function analyzeTarget(
	workspace: string,
	value: unknown,
	semanticOutput?: string,
): Promise<AnalysisResult> {
	const input = AnalysisInputSchema.parse(value),
		root = await realpath(workspace);
	const budget = { entries: 0, bytes: 0, files: 0 };
	const current = await readSources(
		root,
		input.target,
		budget,
		!!input.applicationGraph,
	);
	const result = analyzeSources(current.sources, current.limitations);
	result.counters.entries = budget.entries;
	if (input.semanticGraph) {
		if (!semanticOutput || !path.isAbsolute(semanticOutput))
			throw new Error("Owned semantic output required");
		if (input.compareTarget)
			throw new Error(
				"Semantic graph comparison is not implemented; analyze each target separately",
			);
		const { analyzeSemanticSources, semanticSummary, SEMANTIC_MAX_BYTES } =
			await import("./semantic-engine/engine");
		let application: unknown;
		let graph: Awaited<ReturnType<typeof analyzeSemanticSources>>;
		if (input.applicationGraph) {
			const { analyzeApplicationSources, applicationSummary } = await import(
				"./semantic-engine/application"
			);
			const target = await confinedTarget(root, input.target);
			const prefix = path.relative(root, target).split(path.sep).join("/");
			const normalized = current.sources.map((s) => ({
				...s,
				path:
					s.path === prefix
						? path.posix.basename(prefix)
						: prefix && s.path.startsWith(prefix + "/")
							? s.path.slice(prefix.length + 1)
							: prefix && s.path.startsWith(prefix + "!/")
								? s.path.slice(prefix.length + 2)
								: s.path,
			}));
			const graphs = await analyzeApplicationSources(normalized);
			graph = graphs.semantic;
			application = graphs.application;
			result.applicationGraph = applicationSummary(
				graphs.application,
				graph,
				graphs.manifest,
			);
		} else graph = await analyzeSemanticSources(current.sources);
		const output = JSON.stringify(
			application ? { semantic: graph, application } : graph,
		);
		if (Buffer.byteLength(output) > SEMANTIC_MAX_BYTES)
			throw new Error("Semantic graph transfer budget exceeded");
		await writeFile(semanticOutput, output, { flag: "wx", mode: 0o600 });
		result.semanticGraph = semanticSummary(graph, !!input.applicationGraph);
		if (
			input.applicationGraph ||
			current.limitations.length ||
			graph.coverage.status !== "complete"
		)
			result.status = "partial";
	}
	if (input.compareTarget) {
		const previous = await readSources(root, input.compareTarget, budget);
		const baseCurrent = await confinedTarget(root, input.target),
			basePrevious = await confinedTarget(root, input.compareTarget);
		const normalized = (sources: SourceArtifact[], base: string) => {
			const name = path.relative(root, base).split(path.sep).join("/");
			return new Map(
				sources.map((s) => [
					s.path === name
						? path.posix.basename(s.path)
						: s.path.slice(name.length + 1),
					s.sha256,
				]),
			);
		};
		const earlier = analyzeSources(previous.sources, previous.limitations);
		const relativeFinding = (
			fact: AnalysisResult["facts"][number],
			base: string,
		) => {
			const prefix = path.relative(root, base).split(path.sep).join("/");
			const name =
				fact.location.path === prefix
					? path.posix.basename(fact.location.path)
					: fact.location.path.slice(prefix.length + 1);
			return JSON.stringify([
				name,
				fact.kind,
				fact.kind === "module" ? name : fact.value,
				fact.confidence,
			]);
		};
		const currentFindings = new Map(
			result.facts.map((f) => [relativeFinding(f, baseCurrent), f]),
		);
		const previousFindings = new Map(
			earlier.facts.map((f) => [relativeFinding(f, basePrevious), f]),
		);
		const changedFindings = [
			...result.facts
				.filter((f) => !previousFindings.has(relativeFinding(f, baseCurrent)))
				.map((f) => ({ ...f, change: "added" as const })),
			...earlier.facts
				.filter((f) => !currentFindings.has(relativeFinding(f, basePrevious)))
				.map((f) => ({ ...f, change: "removed" as const })),
		];
		if (changedFindings.length > LIMITS.facts) result.status = "partial";
		const a = normalized(current.sources, baseCurrent),
			b = normalized(previous.sources, basePrevious);
		result.comparison = {
			added: [...a.keys()].filter((k) => !b.has(k)),
			removed: [...b.keys()].filter((k) => !a.has(k)),
			changed: [...a.keys()].filter((k) => b.has(k) && a.get(k) !== b.get(k)),
			findings: changedFindings.slice(0, LIMITS.facts),
			limitations: [
				"Byte and relative-path finding comparison; changed candidates are not proof of changed runtime behavior. Renames, behavior equivalence and original symbols are not inferred.",
				...earlier.limitations,
				...(changedFindings.length > LIMITS.facts
					? ["Finding comparison budget reached."]
					: []),
			],
		};
		if (earlier.status === "partial") result.status = "partial";
	}
	return ResultSchema.parse(result);
}
export async function runAnalysisWorkerEntrypoint() {
	let bytes = 0,
		text = "";
	for await (const chunk of process.stdin) {
		bytes += Buffer.byteLength(chunk);
		if (bytes > 16_384) throw new Error("Worker request byte limit exceeded");
		text += chunk.toString();
	}
	const request = JSON.parse(text);
	if (!request || typeof request.workspace !== "string")
		throw new Error("Worker workspace required");
	if (
		request.semanticOutput !== undefined &&
		(typeof request.semanticOutput !== "string" ||
			!path.isAbsolute(request.semanticOutput))
	)
		throw new Error("Invalid owned semantic output");
	const result = await analyzeTarget(
		request.workspace,
		request.input,
		request.semanticOutput,
	);
	const output = JSON.stringify(result);
	if (Buffer.byteLength(output) > LIMITS.outputBytes)
		throw new Error("Evidence output budget exceeded");
	process.stdout.write(output);
}
