import { test } from "node:test";
import assert from "node:assert/strict";
import { parseParallel, runJobs, runValidation } from "./validate-advanced-build.mjs";
const jobs = [1, 2, 3, 4, 5].map(n => ({ name: String(n) }));
test("parallelism is bounded and rejects malformed values", () => {
  assert.equal(parseParallel(), 2); assert.equal(parseParallel("4"), 4);
  for (const value of [0, -1, 5, 1.5, NaN, "bad"]) assert.throws(() => parseParallel(value));
});
test("independent checks run within the concurrency cap and preserve report order", async () => {
  let active = 0, max = 0;
  const result = await runJobs(jobs, 2, async x => { active++; max = Math.max(max, active); await new Promise(r => setTimeout(r, 8)); active--; return { name: x.name, status: "passed" }; });
  assert.equal(max, 2); assert.deepEqual(result.map(x => x.name), jobs.map(x => x.name));
});
test("a failed check does not hide remaining failures", async () => {
  const result = await runJobs(jobs, 2, async x => ({ name: x.name, status: x.name === "1" ? "failed" : "passed" }));
  assert.equal(result.length, 5); assert.equal(result[0].status, "failed"); assert.equal(result[4].status, "passed");
});
test("rejected checks produce an explicit failed outcome", async () => {
  const result = await runJobs(jobs, 1, async () => { throw new Error("private detail"); });
  assert.equal(result[0].status, "failed"); assert.ok(!JSON.stringify(result).includes("private detail"));
});
test("prerequisites complete before any independent check", async () => {
  const seen = []; await runValidation([{ name: "build" }], jobs, 2, async x => { seen.push(x.name); return { name: x.name, status: "passed" }; }); assert.equal(seen[0], "build");
});
test("a failed prerequisite blocks dependent checks instead of false passing", async () => {
  const seen = []; const result = await runValidation([{ name: "build" }], jobs, 2, async x => { seen.push(x.name); return { name: x.name, status: "failed" }; });
  assert.deepEqual(seen, ["build"]); assert.equal(result.status, "failed"); assert.equal(result.results.filter(x => x.status === "blocked").length, 5);
});
test("the aggregate status fails if any required check fails", async () => {
  const result = await runValidation([], jobs, 2, async x => ({ name: x.name, status: x.name === "3" ? "failed" : "passed" })); assert.equal(result.status, "failed");
});
