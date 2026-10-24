import { afterEach, beforeEach, expect, it } from "vitest";
import { mkdtemp, realpath, writeFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { createGoBinaryFixture } from "./upstream/tests/fixtures/go/image";
import { createRustImage } from "./upstream/tests/fixtures/rust/image";
import { createIl2cppMetadataFixture } from "./upstream/tests/fixtures/il2cpp/metadata";
import { analyzeTarget } from "../worker";
import {
	AnalysisInputSchema,
	byteDigest,
	digest,
	type AnalysisReceipt,
} from "../contracts";
import { FirstPartyAnalysisStore } from "../store";
import { queryFirstPartyEvidence } from "../index";
import { readPyInstallerInventory } from "./pyinstaller";
let root: string;
beforeEach(async () => {
	root = await realpath(await mkdtemp(join(tmpdir(), "cline-metadata-")));
});
afterEach(async () => {
	await rm(root, { recursive: true, force: true });
});
const pyinstaller = () => {
	const name = Buffer.from("owned.pyc\0"),
		toc = Buffer.alloc(18 + name.length);
	toc.writeUInt32BE(toc.length);
	toc.writeUInt32BE(0, 4);
	toc.writeUInt32BE(3, 8);
	toc.writeUInt32BE(3, 12);
	toc[17] = "s".charCodeAt(0);
	name.copy(toc, 18);
	const cookie = Buffer.alloc(88);
	Buffer.from("MEI\x0c\x0b\x0a\x0b\x0e").copy(cookie);
	cookie.writeUInt32BE(3 + toc.length + 88, 8);
	cookie.writeUInt32BE(3, 12);
	cookie.writeUInt32BE(toc.length, 16);
	cookie.writeUInt32BE(313, 20);
	cookie.write("python313.dll", 24);
	return Buffer.concat([Buffer.from("abc"), toc, cookie]);
};
for (const format of ["elf", "pe", "macho"] as const)
	it(`reads Go and Rust ${format} as data without executing`, async () => {
		for (const reader of ["go", "rust"] as const) {
			const bytes =
				reader === "go"
					? createGoBinaryFixture({ format }).bytes
					: createRustImage({ format });
			await writeFile(join(root, "owned.bin"), bytes);
			const result = await analyzeTarget(root, {
				target: "owned.bin",
				artifactReader: { reader, expectedSha256: byteDigest(bytes) },
			});
			const r = result.artifactMetadata!;
			expect(r.targetExecuted).toBe(false);
			expect(r.inputSha256).toBe(byteDigest(bytes));
			expect(r.truncated).toBe(false);
			const records = JSON.stringify(r.records);
			expect(records).toContain(reader === "go" ? "go1.26.0" : "itoa");
		}
	});
for (const version of [24, 27, 29, 31, 39] as const)
	it(`reads supported IL2CPP v${version} inventories`, async () => {
		const bytes = createIl2cppMetadataFixture({ version }).bytes;
		await writeFile(join(root, "global-metadata.dat"), bytes);
		const r = (
			await analyzeTarget(root, {
				target: "global-metadata.dat",
				artifactReader: { reader: "il2cpp", expectedSha256: byteDigest(bytes) },
			})
		).artifactMetadata!;
		expect(r.truncated).toBe(false);
		expect(JSON.stringify(r.records)).toContain("Assembly-CSharp.dll");
		expect(
			r.records.some(
				(x) =>
					x.path === "/metadata_version" && x.valueJson === String(version),
			),
		).toBe(true);
	});
it("inventories PyInstaller CArchive without extracting or decoding Python", async () => {
	const bytes = pyinstaller();
	expect(readPyInstallerInventory(bytes)).toMatchObject({
		layout: "2.1+",
		entries: [{ name: "owned.pyc", compressedBytes: 3 }],
	});
	await writeFile(join(root, "owned.exe"), bytes);
	const r = await analyzeTarget(root, {
		target: "owned.exe",
		artifactReader: {
			reader: "pyinstaller",
			expectedSha256: byteDigest(bytes),
		},
	});
	expect(JSON.stringify(r.artifactMetadata?.records)).toContain("owned.pyc");
	const bad = Buffer.from(bytes);
	bad.writeUInt32BE(0xffffffff, 7);
	expect(() => readPyInstallerInventory(bad)).toThrow();
});
it("rejects malformed, unsupported, changed, linked or outside artifacts and mixed options", async () => {
	for (const reader of ["go", "rust", "pyinstaller", "il2cpp"] as const) {
		const bytes = Buffer.from("not an executable");
		await writeFile(join(root, "bad"), bytes);
		await expect(
			analyzeTarget(root, {
				target: "bad",
				artifactReader: { reader, expectedSha256: byteDigest(bytes) },
			}),
		).rejects.toThrow();
	}
	const bytes = createGoBinaryFixture().bytes;
	await writeFile(join(root, "owned"), bytes);
	await expect(
		analyzeTarget(root, {
			target: "owned",
			artifactReader: { reader: "go", expectedSha256: "a".repeat(64) },
		}),
	).rejects.toThrow("SHA256");
	expect(() =>
		AnalysisInputSchema.parse({
			target: "owned",
			artifactReader: { reader: "go", expectedSha256: byteDigest(bytes) },
			semanticGraph: true,
		}),
	).toThrow();
	await expect(
		analyzeTarget(root, {
			target: "../elsewhere",
			artifactReader: { reader: "go", expectedSha256: byteDigest(bytes) },
		}),
	).rejects.toThrow();
	if (process.platform !== "win32") {
		await symlink(join(root, "owned"), join(root, "link"));
		await expect(
			analyzeTarget(root, {
				target: "link",
				artifactReader: { reader: "go", expectedSha256: byteDigest(bytes) },
			}),
		).rejects.toThrow("Linked");
	}
	const unsupported = createIl2cppMetadataFixture().bytes;
	unsupported.writeUInt32LE(40, 4);
	await writeFile(join(root, "unsupported"), unsupported);
	await expect(
		analyzeTarget(root, {
			target: "unsupported",
			artifactReader: {
				reader: "il2cpp",
				expectedSha256: byteDigest(unsupported),
			},
		}),
	).rejects.toThrow();
});
it("retains paginated owning-session metadata evidence readable in Off without rerunning", async () => {
	const bytes = createGoBinaryFixture().bytes;
	await writeFile(join(root, "owned"), bytes);
	const input = {
			target: "owned",
			artifactReader: {
				reader: "go" as const,
				expectedSha256: byteDigest(bytes),
			},
		},
		result = await analyzeTarget(root, input),
		store = new FirstPartyAnalysisStore(join(root, "store.sqlite"));
	try {
		store.setMode("owner", root, "static");
		const receipt: AnalysisReceipt = {
			id: randomUUID(),
			sessionId: "owner",
			workspace: root,
			profile: result.profile,
			input,
			requestHash: digest(input),
			createdAt: new Date().toISOString(),
			status: "running",
		};
		store.start(receipt);
		store.save({
			...receipt,
			status: "partial",
			result,
			resultHash: digest(result),
		});
		store.setMode("owner", root, "off");
		const page = queryFirstPartyEvidence(
			"owner",
			{ receiptId: receipt.id, view: "artifact-metadata", limit: 2 },
			store,
		);
		expect(page).toMatchObject({
			available: true,
			providerCalls: 0,
			targetExecuted: false,
			items: expect.any(Array),
		});
		expect((page as { items: unknown[] }).items).toHaveLength(2);
		expect(() =>
			queryFirstPartyEvidence(
				"other",
				{ receiptId: receipt.id, view: "artifact-metadata" },
				store,
			),
		).toThrow();
	} finally {
		store.close();
	}
});
it("preserves the pinned reader source and fixture manifest with MIT attribution", async () => {
	const { readFile } = await import("node:fs/promises"),
		base = new URL("./upstream/", import.meta.url),
		manifest = JSON.parse(
			await readFile(new URL("manifest.json", base), "utf8"),
		) as { files: Record<string, string>; revision: string };
	expect(manifest.revision).toBe("f9fabdfcb2c241b18fec0acb5c3b4a14f76f4805");
	for (const [file, hash] of Object.entries(manifest.files))
		expect(byteDigest(await readFile(new URL(file, base))), file).toBe(hash);
	expect(await readFile(new URL("LICENSE", base), "utf8")).toContain(
		"MIT License",
	);
});
