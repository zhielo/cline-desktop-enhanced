import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import {
	open,
	mkdir,
	realpath,
	stat,
	writeFile,
	rename,
	rm,
} from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep, join } from "node:path";
import { z } from "zod";
import type { AdvancedRequest, AdvancedResult } from "./advanced-analysis";
const VERSION = "static-notebook/v1";
const hash = (value: string) =>
	createHash("sha256").update(value).digest("hex");
const Options = z
	.object({
		discovery: z
			.object({
				max_depth: z.number().int().min(0).max(4).optional(),
				max_artifacts: z.number().int().min(1).max(500).optional(),
				inspect_native: z.boolean().optional(),
			})
			.strict()
			.optional(),
		method: z
			.object({
				class_descriptor: z.string().min(3).max(4096),
				name: z.string().min(1).max(4096),
				descriptor: z.string().min(3).max(4096),
			})
			.strict()
			.optional(),
		function: z
			.object({
				symbol: z.string().min(1).max(4096).optional(),
				address: z
					.string()
					.regex(/^0x[0-9a-fA-F]{1,16}$/)
					.optional(),
				max_bytes: z.number().int().min(1).max(65536).optional(),
			})
			.strict()
			.refine((v) => Boolean(v.symbol) !== Boolean(v.address))
			.optional(),
		architecture: z.enum(["arm64", "arm", "thumb", "x86", "x86_64"]).optional(),
		offset: z
			.number()
			.int()
			.nonnegative()
			.max(Number.MAX_SAFE_INTEGER)
			.optional(),
		address: z
			.number()
			.int()
			.nonnegative()
			.max(Number.MAX_SAFE_INTEGER)
			.optional(),
		bytes: z.number().int().min(1).max(65536).optional(),
		steps: z
			.array(z.enum(["base64", "hex", "zlib", "gzip"]))
			.min(1)
			.max(8)
			.optional(),
	})
	.strict();
const Cell = z
	.object({
		id: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/),
		action: z.enum([
			"artifact_discovery",
			"android_relationships",
			"android_method",
			"android_method_code",
			"native_function",
			"triage",
			"apk_inventory",
			"dex_index",
			"native_inventory",
			"native_disassemble",
			"simplify_expression",
			"compare_expressions",
			"triton_expression",
			"match_native_functions",
			"transform_blob",
			"lift_native_ir",
			"deobfuscation_pass",
		]),
		target: z.string().min(1).max(4096),
		compareTarget: z.string().min(1).max(4096).optional(),
		dependsOn: z.array(z.string().max(64)).max(20).default([]),
		options: Options.optional(),
	})
	.strict();
export const AnalysisNotebookSchema = z
	.object({
		schemaVersion: z.literal(1),
		title: z.string().min(1).max(200),
		cells: z.array(Cell).min(1).max(20),
	})
	.strict();
export type NotebookRunner = (
	request: AdvancedRequest,
	signal?: AbortSignal,
) => Promise<AdvancedResult>;
const Result = z.object({
	protocol: z.literal("cline-advanced-analysis/v1"),
	status: z.enum(["completed", "partial", "blocked", "failed", "cancelled"]),
	engine: z.string().max(100),
	engineVersion: z.string().nullable(),
	evidence: z.record(z.string(), z.unknown()),
	limitations: z.array(z.string()).max(100),
	input: z
		.object({
			sha256: z.string().regex(/^[a-f0-9]{64}$/),
			bytes: z.number().nonnegative(),
			format: z.string(),
		})
		.optional(),
});
const Receipt = z
	.object({
		id: z.string().max(64),
		status: z.enum([
			"running",
			"completed",
			"partial",
			"blocked",
			"failed",
			"cancelled",
		]),
		cacheKey: z.string().max(64),
		result: Result.optional(),
		resultHash: z.string().max(64).optional(),
		reused: z.boolean().optional(),
		reason: z.string().max(200).optional(),
	})
	.strict();
const State = z
	.object({
		schemaVersion: z.literal(1),
		adapterVersion: z.string(),
		notebookHash: z.string(),
		runId: z.string(),
		status: z.string(),
		cells: z.array(Receipt).max(20),
	})
	.strict();
type NotebookState = z.infer<typeof State>;
const active = new Set<string>();
export async function readAnalysisJson(
	path: string,
	maxBytes = 1024 * 1024,
): Promise<unknown> {
	const file = await open(path, "r");
	try {
		const buffer = Buffer.alloc(maxBytes + 1);
		let total = 0;
		while (total < buffer.length) {
			const { bytesRead } = await file.read(
				buffer,
				total,
				buffer.length - total,
				total,
			);
			if (!bytesRead) break;
			total += bytesRead;
		}
		if (total > maxBytes)
			throw new Error("Analysis document exceeds byte budget");
		return JSON.parse(buffer.subarray(0, total).toString("utf8"));
	} finally {
		await file.close();
	}
}
function contained(root: string, path: string) {
	const child = relative(root, path);
	return (
		child === "" ||
		(child !== ".." && !child.startsWith(`..${sep}`) && !isAbsolute(child))
	);
}
export async function notebookInput(root: string, value: string) {
	if (
		isAbsolute(value) ||
		value.includes("\\") ||
		value.split("/").includes("..")
	)
		throw new Error(
			"Notebook paths must be confined forward-slash relative paths",
		);
	const path = await realpath(resolve(root, value));
	if (!contained(root, path))
		throw new Error("Notebook input escapes approved folder");
	const info = await stat(path);
	if (!info.isFile() || info.size > 128 * 1024 * 1024)
		throw new Error("Notebook artifact budget exceeded");
	return path;
}
async function hashFile(path: string, signal?: AbortSignal) {
	const digest = createHash("sha256");
	const stream = createReadStream(path);
	let bytes = 0;
	const abort = () => stream.destroy(new Error("Notebook cancelled"));
	signal?.addEventListener("abort", abort, { once: true });
	if (signal?.aborted) abort();
	try {
		for await (const chunk of stream) {
			bytes += chunk.length;
			if (bytes > 128 * 1024 * 1024)
				throw new Error("Input grew beyond budget");
			digest.update(chunk);
		}
		return digest.digest("hex");
	} finally {
		signal?.removeEventListener("abort", abort);
		stream.destroy();
	}
}
export function validateNotebook(document: unknown) {
	const notebook = AnalysisNotebookSchema.parse(document);
	const cells = new Map(notebook.cells.map((cell) => [cell.id, cell]));
	if (cells.size !== notebook.cells.length)
		throw new Error("Duplicate cell IDs");
	const visited = new Set<string>(),
		visiting = new Set<string>();
	const visit = (id: string) => {
		if (visiting.has(id)) throw new Error("Dependency cycle");
		if (visited.has(id)) return;
		const cell = cells.get(id);
		if (!cell) throw new Error("Unknown dependency");
		visiting.add(id);
		for (const dependency of cell.dependsOn) visit(dependency);
		visiting.delete(id);
		visited.add(id);
	};
	for (const cell of notebook.cells) {
		if (new Set(cell.dependsOn).size !== cell.dependsOn.length)
			throw new Error("Duplicate dependency");
		if (cell.action === "match_native_functions" && !cell.compareTarget)
			throw new Error("Matching requires compareTarget");
		visit(cell.id);
	}
	return notebook;
}
export async function prepareNotebook(target: string) {
	const canonical = await realpath(target);
	const root = await realpath(dirname(canonical));
	const notebook = validateNotebook(await readAnalysisJson(canonical));
	const paths = new Map<string, { target: string; compareTarget?: string }>();
	let totalBytes = 0;
	for (const cell of notebook.cells) {
		const input = await notebookInput(root, cell.target);
		const compare = cell.compareTarget
			? await notebookInput(root, cell.compareTarget)
			: undefined;
		for (const path of [input, ...(compare ? [compare] : [])])
			totalBytes += (await stat(path)).size;
		paths.set(cell.id, { target: input, compareTarget: compare });
	}
	if (totalBytes > 512 * 1024 * 1024)
		throw new Error("Aggregate notebook artifact budget exceeded");
	return {
		canonical,
		notebook,
		paths,
		totalBytes,
		notebookHash: hash(JSON.stringify(notebook)),
	};
}
async function persist(path: string, state: NotebookState) {
	const content = JSON.stringify(state, null, 2);
	if (Buffer.byteLength(content) > 8 * 1024 * 1024)
		throw new Error("Checkpoint budget exceeded");
	const temporary = `${path}.${randomUUID()}.tmp`;
	try {
		await writeFile(temporary, content, { mode: 0o600, flag: "wx" });
		await rename(temporary, path);
	} finally {
		await rm(temporary, { force: true });
	}
}
export async function runAnalysisNotebook(
	target: string,
	cacheRoot: string,
	runner: NotebookRunner,
	signal?: AbortSignal,
	timeoutMs = 300000,
): Promise<AdvancedResult> {
	const prepared = await prepareNotebook(target);
	const { notebook, paths, notebookHash } = prepared;
	const identity = hash(prepared.canonical);
	const lock = `${cacheRoot}:${identity}`;
	if (active.has(lock)) throw new Error("Notebook already running");
	active.add(lock);
	const started = Date.now();
	let checkpoint: string | undefined;
	const state: NotebookState = {
		schemaVersion: 1,
		adapterVersion: VERSION,
		notebookHash,
		runId: randomUUID(),
		status: "running",
		cells: [],
	};
	try {
		await mkdir(cacheRoot, { recursive: true, mode: 0o700 });
		const canonicalCache = await realpath(cacheRoot);
		const directory = join(canonicalCache, identity);
		await mkdir(directory, { recursive: true, mode: 0o700 });
		if (!contained(canonicalCache, await realpath(directory)))
			throw new Error("Managed cache escapes its root");
		checkpoint = join(directory, "state.json");
		let previous: NotebookState | undefined;
		try {
			const saved = State.parse(
				await readAnalysisJson(checkpoint, 8 * 1024 * 1024),
			);
			if (saved.adapterVersion === VERSION) previous = saved;
		} catch {
			/* Corrupt or absent checkpoints never bypass fresh analysis. */
		}
		const toolchain = await runner(
			{ action: "toolchain", timeoutMs: Math.min(timeoutMs, 10000) },
			signal,
		);
		if (toolchain.status !== "completed")
			return {
				...toolchain,
				limitations: [
					...toolchain.limitations,
					"Notebook could not establish an engine fingerprint.",
				],
			};
		const fingerprint = hash(JSON.stringify(toolchain));
		const done = new Map<string, z.infer<typeof Receipt>>();
		const pending = new Set(notebook.cells.map((cell) => cell.id));
		await persist(checkpoint, state);
		while (pending.size) {
			const cell = notebook.cells.find(
				(candidate) =>
					pending.has(candidate.id) &&
					candidate.dependsOn.every((id) => done.has(id)),
			);
			if (!cell) throw new Error("No dependency-ready cell");
			pending.delete(cell.id);
			const receipt: z.infer<typeof Receipt> = {
				id: cell.id,
				status: "running",
				cacheKey: "",
			};
			state.cells.push(receipt);
			done.set(cell.id, receipt);
			if (signal?.aborted || Date.now() - started >= timeoutMs) {
				receipt.status = signal?.aborted ? "cancelled" : "failed";
				receipt.reason = "Cancelled or total notebook deadline reached";
				await persist(checkpoint, state);
				continue;
			}
			if (
				cell.dependsOn.some(
					(id) =>
						!["completed", "partial"].includes(
							done.get(id)?.status ?? "failed",
						),
				)
			) {
				receipt.status = "blocked";
				receipt.reason = "Dependency failed or blocked";
				await persist(checkpoint, state);
				continue;
			}
			const input = paths.get(cell.id);
			if (!input) throw new Error("Missing preflight path");
			const before = await hashFile(input.target, signal);
			const compareBefore = input.compareTarget
				? await hashFile(input.compareTarget, signal)
				: undefined;
			receipt.cacheKey = hash(
				JSON.stringify({
					adapter: VERSION,
					fingerprint,
					cell,
					inputHash: before,
					compareHash: compareBefore,
					dependencies: cell.dependsOn.map((id) => done.get(id)?.resultHash),
				}),
			);
			const cached = previous?.cells.find(
				(candidate) =>
					candidate.id === cell.id &&
					candidate.cacheKey === receipt.cacheKey &&
					candidate.status === "completed" &&
					candidate.result?.status === "completed" &&
					candidate.resultHash === hash(JSON.stringify(candidate.result)),
			);
			if (cached) {
				receipt.status = "completed";
				receipt.result = cached.result;
				receipt.resultHash = cached.resultHash;
				receipt.reused = true;
				await persist(checkpoint, state);
				continue;
			}
			await persist(checkpoint, state);
			try {
				const result = Result.parse(
					await runner(
						{
							action: cell.action,
							...input,
							options: cell.options,
							timeoutMs: Math.max(
								1,
								Math.min(120000, timeoutMs - (Date.now() - started)),
							),
						},
						signal,
					),
				);
				if (
					before !== (await hashFile(input.target, signal)) ||
					(input.compareTarget &&
						compareBefore !== (await hashFile(input.compareTarget, signal)))
				)
					throw new Error("Input changed during analysis");
				if (result.input && result.input.sha256 !== before)
					throw new Error("Worker input identity mismatch");
				receipt.status = result.status;
				receipt.result = result;
				receipt.resultHash = hash(JSON.stringify(result));
			} catch {
				receipt.status = signal?.aborted ? "cancelled" : "failed";
				receipt.reason = "Cell execution or input verification failed";
			}
			await persist(checkpoint, state);
		}
		state.status = state.cells.some((cell) => cell.status === "cancelled")
			? "cancelled"
			: state.cells.every((cell) => cell.status === "completed")
				? "completed"
				: state.cells.some((cell) =>
							["completed", "partial"].includes(cell.status),
						)
					? "partial"
					: state.cells.every((cell) => cell.status === "blocked")
						? "blocked"
						: "failed";
		await persist(checkpoint, state);
		return {
			protocol: "cline-advanced-analysis/v1",
			status: state.status as AdvancedResult["status"],
			engine: "static-notebook",
			engineVersion: VERSION,
			evidence: {
				notebookHash,
				runId: state.runId,
				checkpoint,
				cellReceipts: state.cells,
			},
			limitations: [
				"Static allowlisted cells only. No scripts, target execution, external paths or network writes.",
				"Checkpoint hashes detect accidental corruption, not privileged local tampering.",
				"Changed inputs, engine metadata, options or dependency results invalidate reuse. Partial results rerun.",
			],
		};
	} catch {
		state.status = signal?.aborted ? "cancelled" : "failed";
		for (const cell of state.cells)
			if (cell.status === "running")
				cell.status = state.status as "cancelled" | "failed";
		if (checkpoint)
			try {
				await persist(checkpoint, state);
			} catch {
				/* Preserve failure without exposing parser contents. */
			}
		return {
			protocol: "cline-advanced-analysis/v1",
			status: state.status as "cancelled" | "failed",
			engine: "static-notebook",
			engineVersion: VERSION,
			evidence: {
				notebookHash,
				runId: state.runId,
				checkpoint,
				cellReceipts: state.cells,
				reason: "Notebook execution or persistence failed",
			},
			limitations: [
				"An interrupted static cell may be safely rerun after restart.",
			],
		};
	} finally {
		active.delete(lock);
	}
}
