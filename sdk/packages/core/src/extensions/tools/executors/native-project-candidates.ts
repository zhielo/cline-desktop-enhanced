import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
	copyFile,
	lstat,
	mkdir,
	open,
	opendir,
	realpath,
	rename,
	writeFile,
} from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import {
	NativeFunctionStateSchema,
	NativeProjectEditSchema,
	type NativeProjectEdit,
} from "../native-project-edits-schema";
import { withProjectLease } from "./analysis-project-lease";
import type { FunctionSelector } from "./targeted-decompiler-scripts";
const digest = (value: string | Buffer) =>
	createHash("sha256").update(value).digest("hex");
const HASH = /^[a-f0-9]{64}$/;
type FileEvidence = { path: string; sha256: string; bytes: number };
type State = ReturnType<typeof NativeFunctionStateSchema.parse>;
export type EditEngineRequest = {
	mode: "preview" | "candidate" | "verify";
	requestId: string;
	requestHash: string;
	kind: "symbol" | "address";
	value64: string;
	expected?: State;
	changes?: NativeProjectEdit["changes"];
};
export type CandidateOptions = {
	root: string;
	engine: "ghidra" | "ida";
	artifactSha256: string;
	engineSha256: string;
	selector?: FunctionSelector;
	edit: NativeProjectEdit;
	signal?: AbortSignal;
	leaseRoot?: string;
	prepareInput: (stage: string) => Promise<void>;
	verifyTarget: () => Promise<void>;
	run: (stage: string, request: EditEngineRequest) => Promise<unknown>;
};
async function bytes(file: string, limit: number) {
	const before = await lstat(file);
	if (
		!before.isFile() ||
		before.isSymbolicLink() ||
		before.size > limit ||
		(await realpath(file)) !== file
	)
		throw new Error("Unsafe candidate metadata file");
	const handle = await open(
		file,
		constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
	);
	try {
		const info = await handle.stat();
		if (
			info.size !== before.size ||
			info.ino !== before.ino ||
			info.dev !== before.dev
		)
			throw new Error("Candidate metadata identity changed");
		const buffer = Buffer.alloc(info.size + 1);
		let size = 0;
		while (size < buffer.length) {
			const r = await handle.read(buffer, size, buffer.length - size, size);
			if (!r.bytesRead) break;
			size += r.bytesRead;
		}
		if (size !== info.size || (await handle.stat()).size !== info.size)
			throw new Error("Candidate metadata changed during read");
		return buffer.subarray(0, size);
	} finally {
		await handle.close();
	}
}
export async function readNativeCandidateReceipt(file: string) {
	return JSON.parse((await bytes(file, 65536)).toString("utf8")) as unknown;
}
async function hashFile(file: string) {
	const before = await lstat(file);
	if (
		!before.isFile() ||
		before.isSymbolicLink() ||
		before.size > 512 * 1024 * 1024 ||
		(await realpath(file)) !== file
	)
		throw new Error("Unsafe candidate project file");
	const handle = await open(
		file,
		constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
	);
	try {
		const start = await handle.stat();
		if (
			start.ino !== before.ino ||
			start.dev !== before.dev ||
			start.size !== before.size
		)
			throw new Error("Candidate project identity changed");
		const buffer = Buffer.alloc(128 * 1024),
			hash = createHash("sha256");
		let size = 0;
		for (;;) {
			const r = await handle.read(buffer, 0, buffer.length, size);
			if (!r.bytesRead) break;
			size += r.bytesRead;
			if (size > 512 * 1024 * 1024)
				throw new Error("Candidate project byte budget exceeded");
			hash.update(buffer.subarray(0, r.bytesRead));
		}
		const end = await handle.stat();
		if (
			size !== start.size ||
			end.size !== start.size ||
			end.mtimeMs !== start.mtimeMs ||
			end.ino !== start.ino
		)
			throw new Error("Candidate project changed during hash");
		return { bytes: size, sha256: hash.digest("hex") };
	} finally {
		await handle.close();
	}
}
async function inventory(root: string, engine: "ida" | "ghidra") {
	const files: FileEvidence[] = [];
	let total = 0,
		visited = 0;
	async function visit(file: string, depth = 0) {
		if (++visited > 8192 || depth > 32)
			throw new Error("Candidate directory traversal budget exceeded");
		const st = await lstat(file);
		if (st.isSymbolicLink() || (await realpath(file)) !== file)
			throw new Error("Candidate project links not permitted");
		if (st.isDirectory()) {
			for await (const entry of await opendir(file))
				await visit(join(file, entry.name), depth + 1);
		} else {
			if (files.length >= 4096)
				throw new Error("Candidate project file budget exceeded");
			const item = await hashFile(file);
			total += item.bytes;
			if (total > 1024 * 1024 * 1024)
				throw new Error("Candidate project total byte budget exceeded");
			files.push({ path: relative(root, file).replaceAll("\\", "/"), ...item });
		}
	}
	await visit(join(root, "input.bin"));
	await visit(join(root, engine === "ida" ? "candidate.i64" : "candidate.gpr"));
	if (engine === "ghidra") await visit(join(root, "candidate.rep"));
	return files.sort((a, b) => a.path.localeCompare(b.path));
}
export function assertNativeManifestBudget(raw: string) {
	if (Buffer.byteLength(raw) > 1024 * 1024)
		throw new Error(
			"Candidate manifest byte budget exceeded; pointer unchanged",
		);
}
async function publishHead(
	root: string,
	manifestSha256: string | null,
	signal?: AbortSignal,
) {
	signal?.throwIfAborted();
	const stage = join(root, `${randomUUID()}.head.stage`),
		file = await open(stage, "wx", 0o600);
	try {
		await file.writeFile(JSON.stringify({ manifestSha256 }));
		await file.sync();
	} finally {
		await file.close();
	}
	signal?.throwIfAborted();
	await rename(stage, join(root, "HEAD.json"));
	try {
		const actual = JSON.parse(
			(await bytes(join(root, "HEAD.json"), 1024)).toString("utf8"),
		);
		if (actual.manifestSha256 !== manifestSha256)
			throw new Error("Head differs");
	} catch {
		throw new Error(
			"Publication outcome uncertain; inspect HEAD before any new request",
		);
	}
}
export async function runNativeProjectCandidate(options: CandidateOptions) {
	const { engine, artifactSha256, engineSha256, signal } = options,
		edit = NativeProjectEditSchema.parse(options.edit);
	if (!HASH.test(artifactSha256) || !HASH.test(engineSha256))
		throw new Error("Exact artifact/engine hashes required");
	await mkdir(options.root, { recursive: true, mode: 0o700 });
	const cacheInfo = await lstat(options.root);
	if (!cacheInfo.isDirectory() || cacheInfo.isSymbolicLink())
		throw new Error("Candidate root must be a non-link directory");
	const root = await realpath(options.root);
	await mkdir(join(root, "manifests"), { mode: 0o700, recursive: true });
	const manifests = join(root, "manifests");
	if (
		(await lstat(manifests)).isSymbolicLink() ||
		(await realpath(manifests)) !== manifests
	)
		throw new Error("Candidate manifest directory links not permitted");
	return withProjectLease(
		root,
		async () => {
			signal?.throwIfAborted();
			await options.verifyTarget();
			let head: string | null = null;
			try {
				const value = JSON.parse(
					(await bytes(join(root, "HEAD.json"), 1024)).toString("utf8"),
				);
				if (value.manifestSha256 !== null && !HASH.test(value.manifestSha256))
					throw new Error("Invalid candidate head");
				head = value.manifestSha256;
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
			}
			async function load(hash: string) {
				if (!HASH.test(hash)) throw new Error("Invalid manifest hash");
				const raw = await bytes(join(manifests, `${hash}.json`), 1024 * 1024);
				if (digest(raw) !== hash)
					throw new Error("Candidate manifest integrity mismatch");
				const m = JSON.parse(raw.toString("utf8"));
				if (
					m.schemaVersion !== 1 ||
					m.engine !== engine ||
					m.artifactSha256 !== artifactSha256 ||
					m.engineSha256 !== engineSha256 ||
					!/^stage-[a-f0-9-]{36}$/.test(m.stage) ||
					!(m.previousManifest === null || HASH.test(m.previousManifest))
				)
					throw new Error("Candidate manifest scope/engine mismatch");
				const path = join(root, m.stage);
				if (
					(await lstat(path)).isSymbolicLink() ||
					(await realpath(path)) !== path
				)
					throw new Error("Candidate stage links not permitted");
				const actual = await inventory(path, engine);
				if (
					JSON.stringify(actual) !== JSON.stringify(m.files) ||
					actual.find((x) => x.path === "input.bin")?.sha256 !== artifactSha256
				)
					throw new Error("Candidate project integrity mismatch");
				return { manifest: m, path };
			}
			const prior = head ? await load(head) : null;
			if (edit.mode !== "preview" && edit.expected_head_sha256 !== head)
				throw new Error("Candidate head changed since review");
			if (edit.mode === "rollback") {
				if (!head || !prior)
					throw new Error("No current candidate to roll back");
				const previous = prior.manifest.previousManifest as string | null;
				if (previous) await load(previous);
				signal?.throwIfAborted();
				await options.verifyTarget();
				await publishHead(root, previous, signal);
				return {
					status: "pointer-rolled-back" as const,
					previousHead: head,
					headSha256: previous,
					pointerOnly: true,
					notice:
						"Only the active candidate pointer changed; no GUI database, target binary or device was restored",
				};
			}
			const selector = options.selector;
			if (!selector || Boolean(selector.symbol) === Boolean(selector.address))
				throw new Error("Exactly one function selector required");
			const stageId = `stage-${randomUUID()}`,
				stage = join(root, stageId);
			await mkdir(stage, { mode: 0o700 });
			if (prior) {
				for (const item of prior.manifest.files as FileEvidence[]) {
					const out = join(stage, item.path);
					await mkdir(dirname(out), { recursive: true, mode: 0o700 });
					await copyFile(
						join(prior.path, item.path),
						out,
						constants.COPYFILE_EXCL,
					);
				}
				if (
					JSON.stringify(await inventory(stage, engine)) !==
					JSON.stringify(prior.manifest.files)
				)
					throw new Error("Candidate clone identity mismatch");
			} else {
				await options.prepareInput(stage);
				if (
					(await hashFile(join(stage, "input.bin"))).sha256 !== artifactSha256
				)
					throw new Error("Candidate input snapshot mismatch");
			}
			const requestId = randomUUID(),
				requestHash = digest(
					JSON.stringify({
						engine,
						artifactSha256,
						engineSha256,
						selector,
						edit,
						head,
					}),
				);
			const request: EditEngineRequest = {
				mode: edit.mode,
				requestId,
				requestHash,
				kind: selector.symbol ? "symbol" : "address",
				value64: Buffer.from(selector.symbol ?? selector.address!).toString(
					"base64",
				),
				...(edit.expected_state ? { expected: edit.expected_state } : {}),
				...(edit.changes ? { changes: edit.changes } : {}),
			};
			function validate(
				value: unknown,
				expectedStatus: string,
				expectedRequest: EditEngineRequest,
			) {
				const r = value as Record<string, unknown>;
				if (
					!r ||
					r.status !== expectedStatus ||
					r.requestId !== expectedRequest.requestId ||
					r.requestHash !== requestHash ||
					typeof r.entry !== "string" ||
					!/^(?:0x)?[a-fA-F0-9]{1,16}$/.test(r.entry)
				)
					throw new Error("Native edit receipt binding/status mismatch");
				const before = NativeFunctionStateSchema.parse(r.before),
					after = NativeFunctionStateSchema.parse(r.after);
				if (
					expectedRequest.expected &&
					JSON.stringify(before) !== JSON.stringify(expectedRequest.expected)
				)
					throw new Error("Native function before-state changed");
				return { entry: r.entry, before, after };
			}
			signal?.throwIfAborted();
			const result = validate(
				await options.run(stage, request),
				edit.mode === "preview" ? "preview" : "candidate-ready",
				request,
			);
			if (edit.mode === "preview") {
				await options.verifyTarget();
				return {
					status: "preview" as const,
					headSha256: head,
					stagePath: stage,
					...result,
					notice:
						"Engine-normalized before-state; no active candidate pointer changed",
				};
			}
			for (const field of ["name", "comment"] as const)
				if (
					result.after[field] !==
					(edit.changes?.[field] ?? result.before[field])
				)
					throw new Error("Native edit after-state mismatch");
			if (
				edit.changes?.prototype === undefined &&
				edit.changes?.name === undefined &&
				result.after.prototype !== result.before.prototype
			)
				throw new Error("Unrequested native function type changed");

			const verify: EditEngineRequest = {
				mode: "verify",
				requestId: randomUUID(),
				requestHash,
				kind: "address",
				value64: Buffer.from(
					result.entry.startsWith("0x") ? result.entry : `0x${result.entry}`,
				).toString("base64"),
				expected: result.after,
			};
			signal?.throwIfAborted();
			const persisted = validate(
				await options.run(stage, verify),
				"verified",
				verify,
			);
			if (JSON.stringify(persisted.after) !== JSON.stringify(result.after))
				throw new Error("Persisted candidate read-back mismatch");
			const files = await inventory(stage, engine);
			if (files.find((x) => x.path === "input.bin")?.sha256 !== artifactSha256)
				throw new Error("Candidate input changed");
			const manifest = {
				schemaVersion: 1,
				stage: stageId,
				engine,
				artifactSha256,
				engineSha256,
				requestHash,
				previousManifest: head,
				entry: result.entry,
				before: result.before,
				after: result.after,
				files,
				rollbackContract:
					engine === "ghidra"
						? "native-transaction-plus-isolated-candidate"
						: "isolated-candidate-no-native-undo-claim",
			};
			const raw = JSON.stringify(manifest);
			assertNativeManifestBudget(raw);
			const manifestSha256 = digest(raw);
			await writeFile(join(manifests, `${manifestSha256}.json`), raw, {
				flag: "wx",
				mode: 0o600,
			});
			signal?.throwIfAborted();
			await options.verifyTarget();
			await publishHead(root, manifestSha256, signal);
			return {
				status: "candidate-published" as const,
				headSha256: manifestSha256,
				previousHead: head,
				projectPath: join(
					stage,
					engine === "ida" ? "candidate.i64" : "candidate.gpr",
				),
				manifestPath: join(manifests, `${manifestSha256}.json`),
				...result,
				rollbackContract: manifest.rollbackContract,
				notice:
					"Reviewed isolated analysis-project candidate, not a target-binary patch, automatic GUI replacement or device fix",
			};
		},
		signal,
		{ root: options.leaseRoot },
	);
}
