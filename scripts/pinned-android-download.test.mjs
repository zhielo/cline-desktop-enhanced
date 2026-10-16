import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { downloadPinnedAndroidAsset } from "./pinned-android-download.mjs";
const bytes = Buffer.from("owned pinned asset");
const digest = createHash("sha256").update(bytes).digest("hex");
async function fixture(fn) {
 const directory = await mkdtemp(path.join(os.tmpdir(), "android-download-"));
 try { await fn(directory); } finally { await rm(directory,{recursive:true,force:true}); }
}
test("retries transient 404 and network failure, then validates and reuses exact cached bytes", () => fixture(async directory => {
 let calls=0, pauses=0;
 const options={fetch:async()=>{calls++;if(calls===1)return new Response("transient",{status:404});if(calls===2)throw new Error("network");return new Response(bytes);},pause:async()=>{pauses++;}};
 const file=await downloadPinnedAndroidAsset("https://example.invalid/owned",digest,"owned.jar",directory,options);
 assert.deepEqual(await readFile(file),bytes);assert.equal(calls,3);assert.equal(pauses,2);
 await downloadPinnedAndroidAsset("https://example.invalid/owned",digest,"owned.jar",directory,options);assert.equal(calls,3);
}));
test("checksum mismatch fails immediately without retry or publishing corrupt bytes", () => fixture(async directory => {
 let calls=0;
 await assert.rejects(downloadPinnedAndroidAsset("https://example.invalid/owned",digest,"owned.jar",directory,{fetch:async()=>{calls++;return new Response("tampered");},pause:async()=>{throw new Error("must not retry");}}),/Pinned digest mismatch/);
 assert.equal(calls,1);await assert.rejects(readFile(path.join(directory,"owned.jar")),/ENOENT/);
}));
test("unavailable dependency stops after four bounded attempts", () => fixture(async directory => {
 let calls=0;
 await assert.rejects(downloadPinnedAndroidAsset("https://example.invalid/owned",digest,"owned.jar",directory,{fetch:async()=>{calls++;return new Response("missing",{status:404});},pause:async()=>{}}),/attempt 4/);
 assert.equal(calls,4);
}));
