import { describe, expect, it } from "vitest";
import { mapBounded } from "./bounded-tool-batch";

describe("bounded tool batches", () => {
  it("defaults to ordered dependent execution", async () => {
    const order: number[] = [];
    await mapBounded([0, 1, 2], async (index) => {
      expect(order).toHaveLength(index);
      await new Promise((resolve) => setTimeout(resolve, 2));
      order.push(index);
    });
    expect(order).toEqual([0, 1, 2]);
  });

  it("caps independent workers and preserves output order", async () => {
    let active = 0;
    let peak = 0;
    const result = await mapBounded([0, 1, 2, 3, 4], async (index) => {
      peak = Math.max(peak, ++active);
      await new Promise((resolve) => setTimeout(resolve, 5 - index));
      active--;
      return index;
    }, 2);
    expect(peak).toBe(2);
    expect(result).toEqual([0, 1, 2, 3, 4]);
  });

  it("rejects invalid bounds", async () => {
    for (const limit of [0, 5, 1.5, NaN]) {
      await expect(mapBounded([], async () => 1, limit)).rejects.toThrow("Concurrency");
    }
  });

  it("handles an empty batch", async () => {
    expect(await mapBounded([], async () => 1)).toEqual([]);
  });
});
