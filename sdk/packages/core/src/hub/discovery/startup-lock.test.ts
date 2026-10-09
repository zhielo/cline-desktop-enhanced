import {
	mkdtemp,
	mkdir,
	readFile,
	rm,
	stat,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { withHubStartupLock } from ".";
const roots: string[] = [];
afterEach(async () => {
	vi.restoreAllMocks();
	vi.useRealTimers();
	await Promise.all(
		roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
	);
});
async function fixture() {
	const root = await mkdtemp(join(tmpdir(), "hub-startup-lock-"));
	roots.push(root);
	return join(root, "hub.json");
}
it("serializes simultaneous same-host holders instead of racing stale cleanup and replacement", async () => {
	const file = await fixture();
	let entered = 0,
		active = 0,
		maximum = 0;
	let finish!: () => void;
	const callback = async () => {
		entered++;
		active++;
		maximum = Math.max(maximum, active);
		if (entered === 1)
			await new Promise<void>((resolve) => {
				finish = resolve;
			});
		active--;
		return "owned";
	};
	const all = Array.from({ length: 12 }, () =>
		withHubStartupLock(file, callback),
	);
	await vi.waitFor(() => expect(entered).toBe(1));
	finish();
	expect(await Promise.all(all)).toEqual(Array(12).fill("owned"));
	expect(maximum).toBe(1);
});
it("does not steal a live owner older than 30 seconds or treat an unknown PID probe as death", async () => {
	const file = await fixture();
	await mkdir(`${file}.lock`);
	const owner = {
		pid: process.pid,
		acquiredAt: new Date(Date.now() - 60000).toISOString(),
		nonce: "existing-owner",
	};
	await writeFile(join(`${file}.lock`, "owner.json"), JSON.stringify(owner));
	vi.useFakeTimers();
	const probe = vi.spyOn(process, "kill").mockImplementation(() => {
		throw Object.assign(new Error("platform probe unavailable"), {
			code: "EINVAL",
		});
	});
	const callback = vi.fn(async () => "must not enter");
	const pending = withHubStartupLock(file, callback).catch(
		(error) => error as Error,
	);
	await vi.waitFor(() => expect(probe).toHaveBeenCalled());
	vi.setSystemTime(Date.now() + 120001);
	await vi.advanceTimersByTimeAsync(150);
	const failure = await pending;
	expect(failure).toBeInstanceOf(Error);
	expect(String(failure)).toContain("Timed out waiting");
	expect(callback).not.toHaveBeenCalled();
	expect(
		JSON.parse(await readFile(join(`${file}.lock`, "owner.json"), "utf8")),
	).toEqual(owner);
});
it("reclaims only confirmed-dead ownership and preserves replacement ownership on release", async () => {
	const file = await fixture();
	await mkdir(`${file}.lock`);
	await writeFile(
		join(`${file}.lock`, "owner.json"),
		JSON.stringify({ pid: 42424242, acquiredAt: new Date().toISOString() }),
	);
	vi.spyOn(process, "kill").mockImplementation((pid) => {
		if (pid === 42424242)
			throw Object.assign(new Error("dead"), { code: "ESRCH" });
		return true;
	});
	expect(await withHubStartupLock(file, async () => "recovered")).toBe(
		"recovered",
	);
	await expect(stat(`${file}.lock`)).rejects.toMatchObject({ code: "ENOENT" });
	await withHubStartupLock(file, async () => {
		await writeFile(
			join(`${file}.lock`, "owner.json"),
			JSON.stringify({
				pid: process.pid,
				acquiredAt: new Date().toISOString(),
				nonce: "replacement-owner",
			}),
		);
	});
	expect(
		JSON.parse(await readFile(join(`${file}.lock`, "owner.json"), "utf8"))
			.nonce,
	).toBe("replacement-owner");
});
