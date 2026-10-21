import {
	mkdtemp,
	realpath,
	writeFile,
	rm,
	symlink,
	truncate,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash, randomUUID } from "node:crypto";
import { beforeEach, afterEach, expect, it } from "vitest";
import { analyzeTarget } from "./worker";
import { AnalysisInputSchema, digest, type AnalysisReceipt } from "./contracts";
import { EvidenceQuerySchema } from "./evidence-query";
import { queryFirstPartyEvidence } from "./index";
import { FirstPartyAnalysisStore } from "./store";
import { ownedFusePe } from "./electron-fuses.fixture";
import { readElectronFuseImage } from "./semantic-engine/upstream/src/electron/ElectronFuseReader";
import { ELECTRON_FUSE_SENTINEL } from "./semantic-engine/upstream/src/domain/electron/electronFuses";
let root: string;
beforeEach(async () => {
	root = await realpath(await mkdtemp(join(tmpdir(), "cline-fuses-")));
});
afterEach(async () => {
	await rm(root, { recursive: true, force: true });
});
it("reads a confined executable as data and retains exact hashed raw wires in session-owned evidence", async () => {
	const bytes = ownedFusePe();
	await writeFile(join(root, "owned.exe"), bytes);
	const r = await analyzeTarget(root, {
		target: "owned.exe",
		electronFuses: true,
	});
	expect(r.status).toBe("partial");
	expect(r.facts).toEqual([]);
	expect(r.artifacts[0].sha256).toBe(
		createHash("sha256").update(bytes).digest("hex"),
	);
	expect(r.counters.bytes).toBe(bytes.length);
	expect(r.electronFuses?.slices[0].sentinels[0].fuses[0]).toEqual({
		index: 0,
		name: "RunAsNode",
		state: "enabled",
		raw_byte: 49,
	});
	expect(r.electronFuses?.runtime_implications).toContainEqual(
		expect.objectContaining({
			subject: "node_cli_inspect_arguments",
			outcome: "not_honored",
		}),
	);
	const db = new FirstPartyAnalysisStore(join(root, "evidence.sqlite"));
	try {
		db.setMode("owner", root, "static");
		const receipt: AnalysisReceipt = {
			id: randomUUID(),
			sessionId: "owner",
			workspace: root,
			profile: r.profile,
			input: { target: "owned.exe", electronFuses: true },
			requestHash: digest("owned"),
			createdAt: new Date().toISOString(),
			status: "running",
		};
		db.start(receipt);
		db.save({
			...receipt,
			status: "partial",
			result: r,
			resultHash: digest(r),
		});
		db.setMode("owner", root, "off");
		const q = { receiptId: receipt.id, view: "electron-fuses", limit: 1 };
		const page = queryFirstPartyEvidence("owner", q, db) as {
			available: boolean;
			items: unknown[];
			providerCalls: number;
			targetExecuted: boolean;
			verifiedBehavior: boolean;
		};
		expect(page.available).toBe(true);
		expect(page.items).toHaveLength(1);
		expect(page.providerCalls).toBe(0);
		expect(page.targetExecuted).toBe(false);
		expect(page.verifiedBehavior).toBe(false);
		const implications = queryFirstPartyEvidence(
			"owner",
			{ ...q, fuseSection: "runtime_implications" },
			db,
		) as { items: { relationship: string }[]; nextOffset: number };
		expect(implications.items[0].relationship).toBe("derivation");
		expect(implications.nextOffset).toBe(1);
		expect(() => queryFirstPartyEvidence("foreign", q, db)).toThrow(
			/not found/,
		);
	} finally {
		db.close();
	}
});
it("finds chunk-boundary sentinels once for every bounded scan window", async () => {
	await writeFile(join(root, "owned.exe"), ownedFusePe());
	for (const chunkBytes of [1, 7, 31, 32, 33, 255, 256, 262144]) {
		const image = await readElectronFuseImage(join(root, "owned.exe"), {
			chunkBytes,
		});
		expect(image.slices[0].sentinel_count).toBe(1);
		expect(image.slices[0].sentinels[0].sentinel_offset).toBe(255);
	}
});
it("does not select among multiple sentinels or interpret missing wires as disabled", async () => {
	const b = ownedFusePe();
	b.write(ELECTRON_FUSE_SENTINEL, 400, "ascii");
	Buffer.from([1, 1, 48]).copy(b, 432);
	await writeFile(join(root, "multiple.exe"), b);
	let r = await analyzeTarget(root, {
		target: "multiple.exe",
		electronFuses: true,
	});
	expect(r.electronFuses?.slices[0].sentinel_count).toBe(2);
	expect(r.electronFuses?.limitations.join(" ")).toMatch(/none is selected/);
	b.fill(0, 255, 298);
	b.fill(0, 400, 435);
	await writeFile(join(root, "missing.exe"), b);
	r = await analyzeTarget(root, { target: "missing.exe", electronFuses: true });
	expect(r.electronFuses?.slices[0].sentinel_count).toBe(0);
	expect(r.electronFuses?.limitations.join(" ")).toMatch(
		/unknown, not disabled/,
	);
});
it("preserves unknown wire versions, raw bytes and truncated state", async () => {
	let b = ownedFusePe([2, 2, 49, 255]);
	await writeFile(join(root, "unknown.exe"), b);
	let r = await analyzeTarget(root, {
		target: "unknown.exe",
		electronFuses: true,
	});
	expect(r.electronFuses?.slices[0].sentinels[0].fuses[0].name).toBeNull();
	expect(r.electronFuses?.slices[0].sentinels[0].fuses[1].state).toBe(
		"unknown",
	);
	b = ownedFusePe([1, 9, 49], 477).subarray(0, 512);
	await writeFile(join(root, "truncated.exe"), b);
	r = await analyzeTarget(root, {
		target: "truncated.exe",
		electronFuses: true,
	});
	expect(r.electronFuses?.slices[0].sentinels[0].complete).toBe(false);
});
it("rejects incompatible options, directories, unsupported data and outside paths", async () => {
	for (const x of [
		{ compareTarget: "old.exe" },
		{ semanticGraph: true },
		{ applicationGraph: true },
	])
		expect(
			AnalysisInputSchema.safeParse({
				target: "owned.exe",
				electronFuses: true,
				...x,
			}).success,
		).toBe(false);
	expect(
		EvidenceQuerySchema.safeParse({
			receiptId: randomUUID(),
			view: "findings",
			fuseSection: "slices",
		}).success,
	).toBe(false);
	await expect(
		analyzeTarget(root, { target: ".", electronFuses: true }),
	).rejects.toThrow();
	await expect(
		analyzeTarget(root, { target: "../outside.exe", electronFuses: true }),
	).rejects.toThrow(/workspace/);
	await writeFile(join(root, "unsupported.txt"), "not an executable");
	await expect(
		analyzeTarget(root, { target: "unsupported.txt", electronFuses: true }),
	).rejects.toThrow(/container/);
});
it("honors abort and the original file-size and sentinel-count budgets", async () => {
	await writeFile(join(root, "owned.exe"), ownedFusePe());
	const abort = new AbortController();
	abort.abort();
	await expect(
		readElectronFuseImage(join(root, "owned.exe"), { signal: abort.signal }),
	).rejects.toThrow();
	await truncate(join(root, "owned.exe"), 1024 * 1024 * 1024 + 1);
	await expect(
		analyzeTarget(root, { target: "owned.exe", electronFuses: true }),
	).rejects.toThrow(/exceeds/);
	const b = Buffer.alloc(4096);
	ownedFusePe().copy(b);
	for (let n = 0; n < 33; n++)
		b.write(ELECTRON_FUSE_SENTINEL, 160 + n * 80, "ascii");
	await writeFile(join(root, "many.exe"), b);
	await expect(readElectronFuseImage(join(root, "many.exe"))).rejects.toThrow(
		/more than 32/,
	);
});
it("rejects a junction or directory-link escape before reading the redirected executable", async () => {
	const outside = await realpath(
		await mkdtemp(join(tmpdir(), "cline-fuses-outside-")),
	);
	try {
		await writeFile(join(outside, "owned.exe"), ownedFusePe());
		await symlink(outside, join(root, "redirect"), "junction");
		await expect(
			analyzeTarget(root, {
				target: "redirect/owned.exe",
				electronFuses: true,
			}),
		).rejects.toThrow(/workspace/);
	} finally {
		await rm(outside, { recursive: true, force: true });
	}
});

it("fails closed when the owned child omits, adds or inconsistently projects requested fuse evidence", async () => {
	const { runFirstPartyAnalysis } = await import("./service");
	const { analyzeSources } = await import("./parser");
	await writeFile(join(root, "owned.exe"), ownedFusePe());
	const valid = await analyzeTarget(root, {
		target: "owned.exe",
		electronFuses: true,
	});
	const normal = analyzeSources([]);
	const corrupt = structuredClone(valid);
	corrupt.artifacts[0].sha256 = "0".repeat(64);
	for (const [requested, output] of [
		[true, normal],
		[false, valid],
		[true, corrupt],
	] as const) {
		const db = new FirstPartyAnalysisStore(
			join(
				root,
				`child-${requested}-${output.artifacts[0]?.sha256 ?? "missing"}.sqlite`,
			),
		);
		const entry = join(root, "fixed-child.mjs");
		await writeFile(
			entry,
			`process.stdin.resume();process.stdin.on('end',()=>process.stdout.write(${JSON.stringify(JSON.stringify(output))}));`,
		);
		try {
			db.setMode("owner", root, "static");
			const r = await runFirstPartyAnalysis(
				"owner",
				{ target: "owned.exe", ...(requested ? { electronFuses: true } : {}) },
				undefined,
				db,
				JSON.stringify({ executable: process.execPath, args: [entry] }),
			);
			expect(r.status).toBe("failed");
			expect(r.result).toBeUndefined();
			expect(r.error).toBe("Invalid or oversized parser evidence");
		} finally {
			db.close();
		}
	}
});

it("preserves known ELF byte orders, PE machines and universal Mach-O slices without dropping unknown machines", async () => {
	const {
		elfHeaderFuseImage,
		peHeaderFuseImage,
		thinFuseImage,
		universalFuseImage,
		OBSIDIAN_FUSE_BYTES,
	} = await import(
		"./semantic-engine/upstream/tests/fixtures/electron/fuseImage"
	);
	for (const [machine, bits, architecture] of [
		[3, 32, "x86"],
		[62, 64, "x86_64"],
		[40, 32, "arm"],
		[183, 64, "arm64"],
		[0xfffe, 64, null],
	] as const) {
		for (const byteOrder of ["little", "big"] as const) {
			const image = elfHeaderFuseImage(machine, OBSIDIAN_FUSE_BYTES, {
				bits,
				byteOrder,
			});
			await writeFile(join(root, "elf.bin"), image.bytes);
			const r = await analyzeTarget(root, {
				target: "elf.bin",
				electronFuses: true,
			});
			expect(r.electronFuses?.slices[0].architecture).toBe(architecture);
			expect(r.electronFuses?.slices[0].sentinel_count).toBe(1);
			expect(
				r.electronFuses?.runtime_implications.find(
					(i) => i.subject === "embedded_asar_integrity_validation",
				)?.outcome,
			).toBe("unknown");
		}
	}
	for (const [machine, architecture] of [
		[0x14c, "x86"],
		[0x8664, "x86_64"],
		[0xaa64, "arm64"],
		[0xffff, null],
	] as const) {
		await writeFile(
			join(root, "pe.bin"),
			peHeaderFuseImage(machine, OBSIDIAN_FUSE_BYTES).bytes,
		);
		const r = await analyzeTarget(root, {
			target: "pe.bin",
			electronFuses: true,
		});
		expect(r.electronFuses?.slices[0].architecture).toBe(architecture);
	}
	await writeFile(
		join(root, "thin.bin"),
		thinFuseImage(OBSIDIAN_FUSE_BYTES).bytes,
	);
	expect(
		(await analyzeTarget(root, { target: "thin.bin", electronFuses: true }))
			.electronFuses?.artifact.format,
	).toBe("mach-o");
	await writeFile(join(root, "fat.bin"), universalFuseImage().bytes);
	const fat = await analyzeTarget(root, {
		target: "fat.bin",
		electronFuses: true,
	});
	expect(fat.electronFuses?.artifact.format).toBe("mach-o-universal");
	expect(fat.electronFuses?.slices.map((s) => s.architecture)).toEqual([
		"x86_64",
		"arm64",
	]);
});
