/** Ordered, bounded workers. Use concurrency > 1 only for independent operations. */
export async function mapBounded<T, R>(
  items: readonly T[],
  run: (item: T, index: number) => Promise<R>,
  concurrency = 1,
): Promise<R[]> {
  if (!Number.isSafeInteger(concurrency) || concurrency < 1 || concurrency > 4) {
    throw new Error("Concurrency must be an integer from 1 to 4");
  }
  const result = new Array<R>(items.length);
  let cursor = 0;
  await Promise.all(
    Array.from({ length: Math.min(concurrency, items.length) }, async () => {
      while (cursor < items.length) {
        const index = cursor++;
        result[index] = await run(items[index]!, index);
      }
    }),
  );
  return result;
}
