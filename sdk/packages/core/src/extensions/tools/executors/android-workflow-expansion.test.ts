import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, it, vi } from "vitest";
import { ReverseEngineeringInputSchema } from "../schemas";
import { createReverseEngineeringExecutor } from "./reverse-engineering";
import { investigationWorkflow, type InvestigationRunner } from "./investigation-workflows";
import { validateNotebook } from "./analysis-notebook";
const dirs:string[]=[];
afterEach(async()=>{vi.unstubAllEnvs();await Promise.all(dirs.splice(0).map(d=>rm(d,{recursive:true,force:true})));});
const scripts=resolve(dirname(fileURLToPath(import.meta.url)),"../../../../scripts");
async function fixture(){
 const root=await mkdtemp(join(tmpdir(),"android-workflow-"));dirs.push(root);vi.stubEnv("CLINE_DATA_DIR",root);
 const f=JSON.parse(await readFile(join(scripts,"owned-android-entrypoints-fixture.json"),"utf8"));
 const before=join(root,"before.apk"),after=join(root,"after.apk"),ambiguous=join(root,"ambiguous.apk");
 await writeFile(before,Buffer.from(f.base64,"base64"));await writeFile(after,Buffer.from(f.comparisonBase64,"base64"));await writeFile(ambiguous,Buffer.from(f.ambiguousBase64,"base64"));
 return {root,f,before,after,ambiguous};
}
async function execute(request:unknown,signal?:AbortSignal){return JSON.parse(await createReverseEngineeringExecutor()(ReverseEngineeringInputSchema.parse(request),{signal} as never));}
it("routes manifest/DEX callbacks through one static worker with exact budgets",async()=>{
 const run=vi.fn<InvestigationRunner>().mockResolvedValue({status:"partial"});
 const r=await investigationWorkflow(ReverseEngineeringInputSchema.parse({operation:"find_android_entrypoints",target:"/owned.apk",advanced_options:{entrypoints:{max_depth:2,max_components:8,max_dex_files:2}}}),run);
 expect(r).toMatchObject({status:"partial",observedExecution:false});expect(run).toHaveBeenCalledTimes(1);
 expect(run.mock.calls[0][0]).toMatchObject({operation:"advanced_analysis",advanced_action:"android_entrypoints",advanced_options:{entrypoints:{max_depth:2,max_components:8,max_dex_files:2}}});
});
it("finds an exact owned callback through the public executor without executing or modifying the APK",async()=>{
 const {f,before}=await fixture(),raw=await readFile(before);
 const r=await execute({operation:"find_android_entrypoints",target:before});
 const worker=r.stages[0].result.result,e=worker.evidence;
 expect(r).toMatchObject({status:"partial",observedExecution:false});expect(worker.input.sha256).toBe(f.sha256);
 expect(e).toMatchObject({protocol:"cline-android-entrypoints/v1",candidateCount:1,dispatchVerified:false,observedExecution:false});
 expect(e.candidates[0]).toMatchObject({declaredClass:"Lapp/Xxx;",declaringClass:"Lapp/Xxx;",name:"onTerminate",descriptor:"()V",artifactSha256:f.dexSha256,native:false,inheritedDepth:0,dispatchVerified:false,executionObserved:false});
 expect(await readFile(before)).toEqual(raw);
 const attack=await execute({operation:"map_attack_surface",target:before});expect(attack.stages[0].result.result.evidence.candidateCount).toBe(1);
});
it("does not select duplicate multidex classes or imply coverage after budget exclusion",async()=>{
 const {ambiguous}=await fixture();const r=await execute({operation:"find_android_entrypoints",target:ambiguous});const e=r.stages[0].result.result.evidence;
 expect(e.candidateCount).toBe(0);expect(e.components[0].searchStopped).toBe("ambiguous-class");
 const limited=await execute({operation:"find_android_entrypoints",target:ambiguous,advanced_options:{entrypoints:{max_dex_files:1}}});
 expect(limited.status).toBe("partial");expect(limited.stages[0].result.result.evidence.coverage.dexTruncated).toBe(true);
});
it("compares actual member hashes and XML structure through the public command",async()=>{
 const {before,after,f}=await fixture(),a=await readFile(before),b=await readFile(after);
 const r=await execute({operation:"diff_android_resources",target:before,compare_target:after});const worker=r.stages[0].result.result,e=worker.evidence;
 expect(r).toMatchObject({status:"partial",observedExecution:false});expect(worker.input.sha256).toBe(f.sha256);expect(e.compareInput.sha256).toBe(f.comparisonSha256);
 expect(e).toMatchObject({changedFiles:3,categoryCounts:{manifest:1,resources:1,assets:1},published:false,observedExecution:false,changesTruncated:false});
 const xml=e.changes.find((c:{category:string})=>c.category==="resources");expect(xml.parsedXmlStructureEqual).toBe(true);expect(xml.before.sha256).not.toBe(xml.after.sha256);
 expect(await readFile(before)).toEqual(a);expect(await readFile(after)).toEqual(b);
 const limited=await execute({operation:"diff_android_resources",target:before,compare_target:after,max_results:1});expect(limited.stages[0].result.result.evidence).toMatchObject({changedFiles:3,changesTruncated:true});expect(limited.stages[0].result.result.evidence.changes).toHaveLength(1);
});
it("rejects unrelated overrides and missing paired input instead of silently ignoring them",async()=>{
 const {before}=await fixture();await expect(execute({operation:"diff_android_resources",target:before})).rejects.toThrow("compare_target");
 await expect(execute({operation:"find_android_entrypoints",target:before,advanced_options:{method:{class_descriptor:"LX;",name:"x",descriptor:"()V"}}})).rejects.toThrow("unrelated");
 await expect(execute({operation:"inspect",target:before,advanced_options:{entrypoints:{}}})).rejects.toThrow("entrypoints");
 await expect(execute({operation:"map_attack_surface",target:before+".js",advanced_options:{entrypoints:{}}})).rejects.toThrow("APK target");
 expect(()=>ReverseEngineeringInputSchema.parse({operation:"find_android_entrypoints",advanced_options:{entrypoints:{max_components:129}}})).toThrow();
});
it("does not fall back after a worker failure or pre-aborted execution",async()=>{
 const run=vi.fn<InvestigationRunner>().mockResolvedValue({schemaVersion:1,result:{protocol:"cline-advanced-analysis/v1",status:"blocked"}});
 const r=await investigationWorkflow(ReverseEngineeringInputSchema.parse({operation:"find_android_entrypoints",target:"/owned.apk"}),run);expect(r.status).toBe("blocked");expect(run).toHaveBeenCalledTimes(1);
 const {before}=await fixture();const c=new AbortController();c.abort();await expect(execute({operation:"find_android_entrypoints",target:before},c.signal)).rejects.toThrow();
});
it("adds both fixed actions to confined notebooks with required paired hashes and action-specific budgets",()=>{
 const valid={schemaVersion:1,title:"Android static bulk",cells:[{id:"entry",action:"android_entrypoints",target:"before.apk",options:{entrypoints:{max_depth:2}}},{id:"resources",action:"android_resources",target:"before.apk",compareTarget:"after.apk"}]};
 expect(validateNotebook(valid).cells).toHaveLength(2);
 expect(()=>validateNotebook({...valid,cells:[{id:"resources",action:"android_resources",target:"before.apk"}]})).toThrow("compareTarget");
 expect(()=>validateNotebook({...valid,cells:[{id:"resources",action:"android_resources",target:"before.apk",compareTarget:"after.apk",options:{entrypoints:{}}}]})).toThrow("entrypoints");
});
