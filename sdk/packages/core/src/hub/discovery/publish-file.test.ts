import { mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { publishDiscoveryFile } from "./publish-file";
const denied = (code: string) =>
	Object.assign(new Error("owned publication failure"), { code });
it.each([
	"EPERM",
	"EACCES",
	"EBUSY",
])("retries Windows %s with the same temp/destination and bounded delays", async (code) => {
	const replace = vi
		.fn<typeof rename>()
		.mockRejectedValueOnce(denied(code))
		.mockRejectedValueOnce(denied(code))
		.mockResolvedValue(undefined);
	const wait = vi.fn(async () => {});
	await publishDiscoveryFile("/owned/discovery.tmp", "/owned/discovery.json", {
		platform: "win32",
		rename: replace,
		wait,
	});
	expect(replace.mock.calls).toEqual(
		Array(3).fill(["/owned/discovery.tmp", "/owned/discovery.json"]),
	);
	expect(wait.mock.calls).toEqual([[25], [50]]);
});
it("stops after six attempts and 775ms total backoff, preserving the original error", async () => {
	const error = denied("EPERM"),
		replace = vi.fn<typeof rename>().mockRejectedValue(error),
		wait = vi.fn(async () => {});
	await expect(
		publishDiscoveryFile("/owned/temp", "/owned/dest", {
			platform: "win32",
			rename: replace,
			wait,
		}),
	).rejects.toBe(error);
	expect(replace).toHaveBeenCalledTimes(6);
	expect(wait.mock.calls).toEqual([[25], [50], [100], [200], [400]]);
});
it.each([
	"linux",
	"darwin",
] as const)("never retries non-Windows errors (%s)", async (platform) => {
	const replace = vi.fn<typeof rename>().mockRejectedValue(denied("EPERM")),
		wait = vi.fn(async () => {});
	await expect(
		publishDiscoveryFile("/owned/temp", "/owned/dest", {
			platform,
			rename: replace,
			wait,
		}),
	).rejects.toThrow();
	expect(replace).toHaveBeenCalledTimes(1);
	expect(wait).not.toHaveBeenCalled();
});
it.each([
	"ENOENT",
	"ENOSPC",
	"EXDEV",
	"EINVAL",
])("never retries unrelated Windows errors: %s", async (code) => {
	const replace = vi.fn<typeof rename>().mockRejectedValue(denied(code)),
		wait = vi.fn(async () => {});
	await expect(
		publishDiscoveryFile("/owned/temp", "/owned/dest", {
			platform: "win32",
			rename: replace,
			wait,
		}),
	).rejects.toThrow();
	expect(replace).toHaveBeenCalledTimes(1);
	expect(wait).not.toHaveBeenCalled();
});
it("keeps complete old bytes readable throughout transient failure, then atomically replaces", async () => {
	const root = await mkdtemp(join(tmpdir(), "publication-owned-")),
		source = join(root, "unique.tmp"),
		dest = join(root, "discovery.json");
	try {
		await writeFile(source, '{"id":"new"}');
		await writeFile(dest, '{"id":"old"}');
		let attempt = 0;
		await publishDiscoveryFile(source, dest, {
			platform: "win32",
			rename: async (a, b) => {
				expect(await readFile(dest, "utf8")).toBe('{"id":"old"}');
				expect(await readFile(source, "utf8")).toBe('{"id":"new"}');
				if (attempt++ < 2) throw denied("EPERM");
				await rename(a, b);
			},
			wait: async () => {
				expect(await readFile(dest, "utf8")).toBe('{"id":"old"}');
			},
		});
		expect(await readFile(dest, "utf8")).toBe('{"id":"new"}');
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
it("persistent failure leaves the old record and caller-owned temp untouched", async () => {
	const root = await mkdtemp(join(tmpdir(), "publication-failed-")),
		source = join(root, "unique.tmp"),
		dest = join(root, "discovery.json");
	try {
		await writeFile(source, "new");
		await writeFile(dest, "old");
		await expect(
			publishDiscoveryFile(source, dest, {
				platform: "win32",
				rename: async () => {
					throw denied("EPERM");
				},
				wait: async () => {},
			}),
		).rejects.toThrow();
		expect(await readFile(dest, "utf8")).toBe("old");
		expect(await readFile(source, "utf8")).toBe("new");
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
it("rejects same-file and cross-directory requests before any rename", async () => {
	const replace = vi.fn<typeof rename>(),
		wait = vi.fn(async () => {});
	for (const [a, b] of [
		["/owned/file", "/owned/file"],
		["/one/temp", "/two/dest"],
	] as const)
		await expect(
			publishDiscoveryFile(a, b, {
				platform: "win32",
				rename: replace,
				wait,
			}),
		).rejects.toThrow("same-directory");
	expect(replace).not.toHaveBeenCalled();
});
