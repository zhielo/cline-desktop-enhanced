import { mkdtemp, realpath, writeFile, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { expect, it } from "vitest";
import { readElectronFuseImage } from "./upstream/src/electron/ElectronFuseReader";
import { describeElectronFuseFindings } from "./upstream/src/domain/electron/electronFuses";
import {
	thinFuseImage,
	universalFuseImage,
	peHeaderFuseImage,
	elfHeaderFuseImage,
	truncatedFuseImage,
	twoSentinelElf,
	sentinelFreeMacho,
	OBSIDIAN_FUSE_BYTES,
} from "./upstream/tests/fixtures/electron/fuseImage";
const reference = process.env.CLINE_SEMANTIC_REFERENCE_ROOT;
(reference ? it : it.skip)(
	"matches the pinned Electron streaming reader across PE/ELF/Mach-O slices and ambiguous/truncated/unknown wires",
	async () => {
		const base = resolve(reference!);
		const load = (p: string) =>
			import(/* @vite-ignore */ pathToFileURL(join(base, p)).href);
		const original = await load("src/electron/ElectronFuseReader.ts");
		const domain = await load("src/domain/electron/electronFuses.ts");
		const root = await realpath(
			await mkdtemp(join(tmpdir(), "cline-fuse-parity-")),
		);
		const corpus = [
			thinFuseImage(OBSIDIAN_FUSE_BYTES).bytes,
			thinFuseImage([49, 255, 114], 2).bytes,
			universalFuseImage().bytes,
			truncatedFuseImage(),
			twoSentinelElf().bytes,
			sentinelFreeMacho(),
			...[0x14c, 0x8664, 0xaa64, 0xffff].map(
				(m) => peHeaderFuseImage(m, OBSIDIAN_FUSE_BYTES).bytes,
			),
			...[3, 62, 40, 183, 243, 0xffff].flatMap((m) =>
				(["little", "big"] as const).map(
					(byteOrder) =>
						elfHeaderFuseImage(m, OBSIDIAN_FUSE_BYTES, { bits: 64, byteOrder })
							.bytes,
				),
			),
		];
		try {
			for (const [i, b] of corpus.entries()) {
				const file = join(root, `owned-${i}.bin`);
				await writeFile(file, b);
				const actual = await readElectronFuseImage(file, { chunkBytes: 17 });
				const expected = await original.readElectronFuseImage(file, {
					chunkBytes: 17,
				});
				expect(actual).toEqual(expected);
				expect(
					describeElectronFuseFindings(actual.slices, actual.format),
				).toEqual(
					domain.describeElectronFuseFindings(expected.slices, expected.format),
				);
			}
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	},
);
