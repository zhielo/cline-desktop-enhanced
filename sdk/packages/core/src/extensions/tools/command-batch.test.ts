import { afterEach, describe, expect, it, vi } from "vitest";
import { runCommandBatch, waitForCommandResult } from "./command-batch";
import { TimeoutError, withTimeout } from "./helpers";

afterEach(() => vi.useRealTimers());
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

describe("bounded command batches", () => {
	it("executes sequentially by default", async () => {
		let running = 0;
		let peak = 0;
		const order: number[] = [];
		const result = await runCommandBatch([1, 2, 3], async (item) => {
			peak = Math.max(peak, ++running);
			order.push(item);
			await sleep(2);
			running--;
			return item;
		}, { timeoutMs: 1_000, onSkipped: async () => -1 });
		expect(peak).toBe(1);
		expect(order).toEqual([1, 2, 3]);
		expect(result).toEqual([1, 2, 3]);
	});
	it("caps explicitly selected parallelism and preserves result order", async () => {
		let running = 0;
		let peak = 0;
		const result = await runCommandBatch([12, 2, 3, 4], async (item) => {
			peak = Math.max(peak, ++running);
			await sleep(item);
			running--;
			return item;
		}, { timeoutMs: 1_000, concurrency: 2, onSkipped: async () => -1 });
		expect(peak).toBe(2);
		expect(result).toEqual([12, 2, 3, 4]);
	});
	it("never launches queued work after deadline expiry", async () => {
		vi.useFakeTimers();
		const started: number[] = [];
		const execution = runCommandBatch([1, 2, 3], async (item, _index, batch) => {
			started.push(item);
			try { return await waitForCommandResult(new Promise<number>(() => {}), batch.signal); }
			catch { return -1; }
		}, { timeoutMs: 100, onSkipped: async () => -2 });
		await vi.advanceTimersByTimeAsync(100);
		expect(await execution).toEqual([-1, -2, -2]);
		expect(started).toEqual([1]);
	});
	it("does not start a pre-cancelled batch", async () => {
		const controller = new AbortController();
		controller.abort(new Error("user stop"));
		const run = vi.fn(async () => 1);
		expect(await runCommandBatch([1, 2], run, { timeoutMs: 1_000, signal: controller.signal, onSkipped: async () => -1 })).toEqual([-1, -1]);
		expect(run).not.toHaveBeenCalled();
	});
	it("does not reset the batch budget for queued commands", async () => {
		vi.useFakeTimers();
		const budgets: number[] = [];
		const execution = runCommandBatch([1, 2], async (item, _index, batch) => {
			budgets.push(batch.remainingMs());
			if (item === 1) await sleep(40);
			return item;
		}, { timeoutMs: 100, onSkipped: async () => -1 });
		await vi.advanceTimersByTimeAsync(40);
		expect(await execution).toEqual([1, 2]);
		expect(budgets[1]).toBeLessThan(budgets[0]);
	});
	it("rejects invalid concurrency and oversized batches before execution", async () => {
		const run = vi.fn(async () => 1);
		for (const concurrency of [0, 5, 1.5, Number.NaN]) {
			await expect(runCommandBatch([1], run, { timeoutMs: 100, concurrency, onSkipped: async () => -1 })).rejects.toThrow("commandConcurrency");
		}
		await expect(runCommandBatch(new Array(257).fill(1), run, { timeoutMs: 100, onSkipped: async () => -1 })).rejects.toThrow("256");
		expect(run).not.toHaveBeenCalled();
	});
	it("supports empty and zero-budget batches without a launch", async () => {
		const run = vi.fn(async () => 1);
		expect(await runCommandBatch([], run, { timeoutMs: 100, onSkipped: async () => -1 })).toEqual([]);
		expect(await runCommandBatch([1], run, { timeoutMs: 0, onSkipped: async () => -1 })).toEqual([-1]);
		expect(run).not.toHaveBeenCalled();
	});
	it("handles late rejection after cancellation", async () => {
		const controller = new AbortController();
		let rejectUnderlying: (error: Error) => void = () => {};
		const underlying = new Promise<string>((_resolve, reject) => { rejectUnderlying = reject; });
		const waited = waitForCommandResult(underlying, controller.signal);
		controller.abort(new Error("stop"));
		await expect(waited).rejects.toThrow("stop");
		rejectUnderlying(new Error("late failure"));
		await Promise.resolve();
	});
	it("removes timeout timers on resolution and rejection", async () => {
		vi.useFakeTimers();
		expect(await withTimeout(Promise.resolve(1), 10_000, "timeout")).toBe(1);
		expect(vi.getTimerCount()).toBe(0);
		await expect(withTimeout(Promise.reject(new Error("failed")), 10_000, "timeout")).rejects.toThrow("failed");
		expect(vi.getTimerCount()).toBe(0);
	});
	it("retains the typed timeout outcome", async () => {
		vi.useFakeTimers();
		const waited = withTimeout(new Promise<void>(() => {}), 100, "deadline");
		const checked = expect(waited).rejects.toBeInstanceOf(TimeoutError);
		await vi.advanceTimersByTimeAsync(100);
		await checked;
	});
});
