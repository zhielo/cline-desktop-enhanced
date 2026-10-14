import {
	mkdtemp,
	readFile,
	readdir,
	rename,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
const publication = vi.hoisted(() => ({ replace: vi.fn() }));
vi.mock("./publish-file", () => ({
	publishDiscoveryFile: publication.replace,
}));
import { writeHubDiscovery } from "./index";
it("failed publication preserves the incumbent, cleans only its temp, and releases the mutation lock", async () => {
	const root = await mkdtemp(join(tmpdir(), "discovery-publication-owned-"));
	const dest = join(root, "discovery.json");
	const other = join(root, "discovery.json.other-owner.tmp");
	const record = {
		hubId: "replacement",
		protocolVersion: "v1",
		authToken: "fixture-token",
		host: "127.0.0.1",
		port: 25463,
		url: "ws://127.0.0.1:25463/hub",
		startedAt: new Date().toISOString(),
		updatedAt: new Date().toISOString(),
	};
	const failure = Object.assign(new Error("persistent replacement denied"), {
		code: "EPERM",
	});
	try {
		await writeFile(dest, '{"hubId":"incumbent"}');
		await writeFile(other, "other owner's temporary file");
		publication.replace.mockImplementationOnce(
			async (source: string, destination: string) => {
				expect(destination).toBe(dest);
				expect(JSON.parse(await readFile(source, "utf8"))).toEqual(record);
				expect(await readFile(dest, "utf8")).toBe('{"hubId":"incumbent"}');
				throw failure;
			},
		);
		await expect(writeHubDiscovery(dest, record)).rejects.toBe(failure);
		expect(await readFile(dest, "utf8")).toBe('{"hubId":"incumbent"}');
		expect(await readFile(other, "utf8")).toBe("other owner's temporary file");
		expect((await readdir(root)).sort()).toEqual([
			"discovery.json",
			"discovery.json.other-owner.tmp",
		]);
		publication.replace.mockImplementationOnce(rename);
		await writeHubDiscovery(dest, record);
		expect(JSON.parse(await readFile(dest, "utf8"))).toEqual(record);
		expect((await readdir(root)).sort()).toEqual([
			"discovery.json",
			"discovery.json.other-owner.tmp",
		]);
	} finally {
		publication.replace.mockReset();
		await rm(root, { recursive: true, force: true });
	}
});
