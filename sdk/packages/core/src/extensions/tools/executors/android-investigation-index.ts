import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
	link,
	lstat,
	mkdir,
	mkdtemp,
	open,
	realpath,
	rm,
	writeFile,
} from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { z } from "zod";
import type { AdvancedResult } from "./advanced-analysis";

const MAX_BYTES = 1024 * 1024;
const Manifest = z
	.object({
		protocol: z.literal("cline-android-investigation/v1"),
		id: z.string().regex(/^[a-f0-9]{64}$/),
		result: z
			.object({
				protocol: z.literal("cline-advanced-analysis/v1"),
				engine: z.literal("android-static"),
				engineVersion: z.string().max(80),
				status: z.enum(["completed", "partial"]),
				input: z
					.object({
						sha256: z.string().regex(/^[a-f0-9]{64}$/),
						bytes: z.number().int().nonnegative(),
						format: z.string().max(32),
					})
					.strict(),
				evidence: z.record(z.string(), z.unknown()),
				limitations: z.array(z.string().max(2048)).max(32),
			})
			.strict(),
	})
	.strict();
export type InvestigationQuery = {
	kind?: "artifact" | "method" | "loader-reference" | "jni-name-candidate";
	text?: string;
	id?: string;
	offset?: number;
	limit?: number;
};
function canonical(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(canonical);
	if (value && typeof value === "object")
		return Object.fromEntries(
			Object.entries(value)
				.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
				.map(([key, item]) => [key, canonical(item)]),
		);
	return value;
}
function digest(result: unknown): string {
	return createHash("sha256")
		.update(JSON.stringify(canonical(result)))
		.digest("hex");
}
async function readManifest(target: string) {
	if (!isAbsolute(target))
		throw new Error("Investigation index path must be absolute");
	// Open once to avoid a stat/read race; reject symlink leaves and non-regular files.
	const leaf = await lstat(target);
	if (leaf.isSymbolicLink())
		throw new Error("Investigation index must not be a symlink");
	if (!leaf.isFile() || leaf.size > MAX_BYTES)
		throw new Error("Investigation index exceeds bounded regular-file limit");
	const handle = await open(
		target,
		constants.O_RDONLY |
			(constants.O_NOFOLLOW ?? 0) |
			(constants.O_NONBLOCK ?? 0),
	);
	try {
		const info = await handle.stat();
		if (!info.isFile() || info.size > MAX_BYTES)
			throw new Error("Investigation index exceeds bounded regular-file limit");
		const buffer = Buffer.alloc(MAX_BYTES + 1);
		let length = 0;
		while (length < buffer.length) {
			const { bytesRead } = await handle.read(
				buffer,
				length,
				buffer.length - length,
				null,
			);
			if (!bytesRead) break;
			length += bytesRead;
		}
		if (length > MAX_BYTES)
			throw new Error("Investigation index grew beyond limit");
		const manifest = Manifest.parse(
			JSON.parse(buffer.subarray(0, length).toString("utf8")),
		);
		if (digest(manifest.result) !== manifest.id)
			throw new Error("Investigation index content hash mismatch");
		return manifest;
	} finally {
		await handle.close();
	}
}
export async function persistInvestigation(
	root: string,
	result: AdvancedResult,
) {
	if (
		result.engine !== "android-static" ||
		!["completed", "partial"].includes(result.status)
	)
		return undefined;
	const id = digest(result);
	const manifest = Manifest.parse({
		protocol: "cline-android-investigation/v1",
		id,
		result,
	});
	const body = JSON.stringify(manifest);
	if (Buffer.byteLength(body) > MAX_BYTES)
		throw new Error("Investigation index exceeds storage limit");
	await mkdir(root, { recursive: true, mode: 0o700 });
	if ((await lstat(root)).isSymbolicLink())
		throw new Error("Investigation cache root must not be a symlink");
	const directory = await realpath(root);
	const file = join(directory, `${id}.json`);
	// Atomic no-overwrite publication: only complete documents become visible.
	const stage = await mkdtemp(join(directory, ".pending-"));
	const stagedFile = join(stage, "index.json");
	try {
		await writeFile(stagedFile, body, { flag: "wx", mode: 0o600 });
		try {
			await link(stagedFile, file);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
			await readManifest(file);
			return { id, file, reused: true };
		}
		return { id, file, reused: false };
	} finally {
		await rm(stage, { recursive: true, force: true });
	}
}
export async function queryInvestigation(
	target: string,
	query: InvestigationQuery = {},
): Promise<AdvancedResult> {
	const manifest = await readManifest(target);
	const evidence = manifest.result.evidence;
	const rows: Record<string, unknown>[] = [];
	const add = (value: unknown, kind: string) => {
		if (!value || typeof value !== "object" || Array.isArray(value))
			throw new Error("Invalid investigation evidence row");
		const row = value as Record<string, unknown>;
		if (typeof row.id !== "string" || !/^[a-f0-9]{32}$/.test(row.id))
			throw new Error("Invalid investigation evidence ID");
		if (rows.length >= 10000)
			throw new Error("Investigation row limit exceeded");
		rows.push({ ...row, kind });
	};
	if (
		!Array.isArray(evidence.artifacts) ||
		!Array.isArray(evidence.relationships)
	)
		throw new Error("Investigation evidence collections missing");
	for (const artifact of evidence.artifacts) {
		const { dex: nestedDex, ...summary } = artifact as Record<string, unknown>;
		const details = nestedDex as Record<string, unknown> | undefined;
		add(
			{
				...summary,
				...(details
					? {
							dexSummary: {
								methodCount: details.methodCount,
								definedMethodCount: details.definedMethodCount,
								methodsTruncated: details.methodsTruncated,
								loaderReferencesTruncated: details.loaderReferencesTruncated,
							},
						}
					: {}),
			},
			"artifact",
		);
		const dex = (
			artifact as {
				dex?: { methods?: unknown[]; loaderReferences?: unknown[] };
			}
		).dex;
		for (const method of dex?.methods ?? []) add(method, "method");
		for (const reference of dex?.loaderReferences ?? [])
			add(reference, "loader-reference");
	}
	for (const method of (evidence.selectedMethods as unknown[] | undefined) ??
		[]) {
		if (
			!rows.some(
				(row) =>
					row.kind === "method" && row.id === (method as { id?: string }).id,
			)
		)
			add(method, "method");
	}
	for (const relationship of evidence.relationships)
		add(relationship, "jni-name-candidate");
	const offset = Math.max(0, Math.min(query.offset ?? 0, 10000));
	const limit = Math.max(1, Math.min(query.limit ?? 50, 200));
	const text = query.text?.toLowerCase();
	const filtered = rows.filter(
		(row) =>
			(!query.kind || row.kind === query.kind) &&
			(!query.id || row.id === query.id) &&
			(!text || JSON.stringify(row).toLowerCase().includes(text)),
	);
	return {
		protocol: "cline-advanced-analysis/v1",
		status: manifest.result.status,
		engine: "android-investigation-index",
		engineVersion: "1",
		input: manifest.result.input,
		evidence: {
			investigationId: manifest.id,
			sourceEngineVersion: manifest.result.engineVersion,
			coverage: evidence.coverage,
			sourceListingCoverage: {
				relationshipCount: evidence.relationshipCount,
				relationshipsTruncated: evidence.relationshipsTruncated,
				selectedMethodCount: evidence.selectedMethodCount,
				selectedMethodsTruncated: evidence.selectedMethodsTruncated,
			},
			totalMatches: filtered.length,
			offset,
			nextOffset: offset + limit < filtered.length ? offset + limit : null,
			rows: filtered.slice(offset, offset + limit),
		},
		limitations: [
			...manifest.result.limitations,
			"Queries only cover indexed evidence; no missing edges or runtime bindings are inferred. The hash detects corruption, not maliciously forged evidence.",
		],
	};
}
