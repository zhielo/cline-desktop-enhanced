import { describe, it, expect, vi } from "vitest";
import { ResourceGovernor } from "./resource-governor";
describe("resource admission", () => {
	it("shares concurrency and reserves capacity until exact release", async () => {
		const g = new ResourceGovernor(() => 10000);
		const a = await g.acquire(128),
			b = await g.acquire(128);
		let granted = false;
		const pending = g.acquire(128).then((release) => {
			granted = true;
			return release;
		});
		await Promise.resolve();
		expect(granted).toBe(false);
		expect(g.snapshot()).toMatchObject({ active: 2, queued: 1 });
		a();
		const c = await pending;
		b();
		c();
		c();
		expect(g.snapshot()).toMatchObject({ active: 0, reservedMB: 0, queued: 0 });
	});
	it("cancels queued work before launch without disturbing owners", async () => {
		const g = new ResourceGovernor(() => 10000);
		g.setProfile("economy");
		const release = await g.acquire();
		const c = new AbortController();
		const waiting = g.acquire(128, c.signal);
		c.abort();
		await expect(waiting).rejects.toThrow("cancelled");
		expect(g.snapshot().active).toBe(1);
		release();
	});
	it("fails admission under low memory rather than spawning", async () => {
		vi.useFakeTimers();
		try {
			const g = new ResourceGovernor(() => 100);
			const waiting = g.acquire(128, undefined, 100);
			const check = expect(waiting).rejects.toThrow("no work launched");
			await vi.advanceTimersByTimeAsync(100);
			await check;
			expect(g.snapshot().active).toBe(0);
		} finally {
			vi.useRealTimers();
		}
	});
	it("does not increase existing hard two-worker cap in deep mode", async () => {
		const g = new ResourceGovernor(() => 10000);
		g.setProfile("deep");
		expect(g.snapshot().maxConcurrent).toBe(2);
		expect(() => g.setProfile("unknown" as never)).toThrow();
		await expect(g.acquire(NaN)).rejects.toThrow();
	});
});
it("idle native residency does not consume execution slots", async () => {
	const g = new ResourceGovernor(() => 10000);
	const residentA = await g.acquire(256, undefined, 1000, true),
		residentB = await g.acquire(256, undefined, 1000, true);
	const execution = await g.acquire(128);
	expect(g.snapshot()).toMatchObject({
		active: 1,
		residentNative: 2,
		reservedMB: 640,
	});
	execution();
	residentA();
	residentB();
	expect(g.snapshot().reservedMB).toBe(0);
});
