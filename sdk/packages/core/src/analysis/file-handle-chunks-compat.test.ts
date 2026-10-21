import { mkdtemp, open, rm, writeFile } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buffer } from "node:stream/consumers";
import { expect, it } from "vitest";
import { readFileHandleChunks } from "./semantic-engine/upstream/src/filesystem/readFileHandleChunks";

it("reads an exact BigInt descriptor range on the supported runtime without moving its cursor", async () => {
	const root = await mkdtemp(join(tmpdir(), "cline-bigint-read-"));
	try {
		const path = join(root, "owned.txt");
		await writeFile(path, "abcdef");
		const handle = await open(path, "r");
		try {
			const stream = readFileHandleChunks(handle, { start: 1n, end: 3n });
			expect((await buffer(stream)).toString()).toBe("bcd");
			expect(stream.readCoverage()).toEqual({
				kind: "complete",
				bytes: 3n,
				boundary: "range",
			});
			const cursor = Buffer.alloc(1);
			await handle.read(cursor, 0, 1, null);
			expect(cursor.toString()).toBe("a");
		} finally {
			await handle.close();
		}
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});

it("retains the descriptor receiver and offsets beyond Number.MAX_SAFE_INTEGER without coercion", async () => {
	const start = BigInt(Number.MAX_SAFE_INTEGER) + 31n;
	const positions: bigint[] = [];
	const owner = {
		read: async function (
			this: unknown,
			target: Buffer,
			offset: number,
			length: number,
			position: bigint,
		) {
			expect(this).toBe(owner);
			expect(offset).toBe(0);
			expect(length).toBe(3);
			positions.push(position);
			target.write("xyz");
			return { bytesRead: 3, buffer: target };
		} as FileHandle["read"],
	};
	const stream = readFileHandleChunks(owner, { start, end: start + 2n });
	expect((await buffer(stream)).toString()).toBe("xyz");
	expect(positions).toEqual([start]);
	expect(stream.readCoverage()).toEqual({
		kind: "complete",
		bytes: 3n,
		boundary: "range",
	});
});
