import { TimeoutError } from "./helpers";

export interface CommandBatchContext {
	signal: AbortSignal;
	remainingMs: () => number;
	ensureActive: () => void;
	cancel: (reason: unknown) => void;
}

/** Bounded, ordered results; one monotonic deadline includes all queue waits. */
export async function runCommandBatch<T, R>(
	items: readonly T[],
	run: (item: T, index: number, batch: CommandBatchContext) => Promise<R>,
	options: {
		timeoutMs: number;
		concurrency?: number;
		signal?: AbortSignal;
		onSkipped: (item: T, index: number, batch: CommandBatchContext) => Promise<R>;
	},
): Promise<R[]> {
	const concurrency = options.concurrency ?? 1;
	if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 4) {
		throw new Error("commandConcurrency must be an integer from 1 to 4");
	}
	if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 0 || options.timeoutMs > 2_147_483_647) {
		throw new Error("Invalid command batch timeout");
	}
	if (items.length > 256) throw new Error("Command batches are limited to 256 commands");
	const controller = new AbortController();
	const deadline = performance.now() + options.timeoutMs;
	const cancel = (reason: unknown) => {
		if (!controller.signal.aborted) controller.abort(reason);
	};
	const expire = () => cancel(new TimeoutError(`Command timed out after ${options.timeoutMs}ms (batch deadline)`, options.timeoutMs));
	const onParentAbort = () => cancel(options.signal?.reason ?? new Error("Command batch cancelled"));
	const batch: CommandBatchContext = {
		signal: controller.signal,
		cancel,
		remainingMs: () => Math.max(0, deadline - performance.now()),
		ensureActive: () => {
			if (!controller.signal.aborted && performance.now() >= deadline) expire();
			if (controller.signal.aborted) throw controller.signal.reason;
		},
	};
	options.signal?.addEventListener("abort", onParentAbort, { once: true });
	if (options.signal?.aborted) onParentAbort();
	const timer = setTimeout(expire, options.timeoutMs);
	const results = new Array<R>(items.length);
	let cursor = 0;
	const worker = async () => {
		while (cursor < items.length) {
			const index = cursor++;
			const item = items[index];
			try {
				if (!controller.signal.aborted && batch.remainingMs() <= 0) expire();
				results[index] = await (controller.signal.aborted ? options.onSkipped : run)(item, index, batch);
			} catch (error) {
				cancel(error);
				throw error;
			}
		}
	};
	try {
		await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
		return results;
	} finally {
		clearTimeout(timer);
		options.signal?.removeEventListener("abort", onParentAbort);
	}
}

/** Cancels the caller wait, not proof of physical descendant-process cleanup. */
export function waitForCommandResult<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
	return new Promise<T>((resolve, reject) => {
		const cleanup = () => signal.removeEventListener("abort", onAbort);
		const onAbort = () => {
			cleanup();
			reject(signal.reason ?? new Error("Command batch cancelled"));
		};
		if (signal.aborted) {
			Promise.resolve(promise).catch(() => {});
			onAbort();
			return;
		}
		signal.addEventListener("abort", onAbort, { once: true });
		Promise.resolve(promise).then(
			(value) => { cleanup(); resolve(value); },
			(error: unknown) => { cleanup(); reject(error); },
		);
	});
}
