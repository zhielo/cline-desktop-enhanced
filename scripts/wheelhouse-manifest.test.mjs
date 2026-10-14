import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { wheelhouseManifest, verifyWheelhouse } from "./wheelhouse-manifest.mjs";
import { runBounded } from "./run-bounded-process.mjs";
test("exact wheel inventory and requirements are verified before reuse", async () => {
 const root=await mkdtemp(join(tmpdir(),"owned-wheels-")); const req=join(tmpdir(),`owned-pins-${process.pid}.txt`);
 try { await writeFile(req,"owned==1\n");await writeFile(join(root,"owned-1-py3-none-any.whl"),"owned");
 await writeFile(join(root,"manifest.json"),JSON.stringify(await wheelhouseManifest(root,req)));
 await verifyWheelhouse(root,req);await writeFile(join(root,"owned-1-py3-none-any.whl"),"changed");await assert.rejects(verifyWheelhouse(root,req),/integrity/);
 await writeFile(join(root,"extra.txt"),"unexpected");await assert.rejects(wheelhouseManifest(root,req),/Unexpected/);
 } finally {await rm(root,{recursive:true,force:true});await rm(req,{force:true});}
});
test("owned process deadline fails rather than hanging or silently passing", async () => {
 const r=await runBounded(process.execPath,["-e","setInterval(()=>{},1000)"],{timeoutMs:50,heartbeatMs:1000});assert.equal(r.code,124);assert.equal(r.timedOut,true);
 const ok=await runBounded(process.execPath,["-e","process.exit(0)"],{timeoutMs:10000});assert.equal(ok.code,0);
});
test("changed requirements invalidate a previously sealed wheel cache",async()=>{const root=await mkdtemp(join(tmpdir(),"owned-cache-"));const req=join(tmpdir(),`owned-cache-pins-${process.pid}.txt`);try{await writeFile(req,"owned==1\n");await writeFile(join(root,"owned-1-py3-none-any.whl"),"owned");await writeFile(join(root,"manifest.json"),JSON.stringify(await wheelhouseManifest(root,req)));await writeFile(req,"owned==2\n");await assert.rejects(verifyWheelhouse(root,req),/requirements changed/);}finally{await rm(root,{recursive:true,force:true});await rm(req,{force:true});}});
