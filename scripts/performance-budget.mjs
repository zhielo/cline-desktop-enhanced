import { readFile,writeFile } from "node:fs/promises";
export function summarizeSamples(samples) {
 if(!Array.isArray(samples)||samples.length<3||samples.some(v=>!Number.isFinite(v)||v<0)) throw new Error("At least three finite nonnegative samples required");
 const sorted=[...samples].sort((a,b)=>a-b);return {samples:sorted.length,p50:sorted[Math.ceil(sorted.length*.5)-1],p95:sorted[Math.ceil(sorted.length*.95)-1]};
}
export function comparePerformance(candidate,baseline,threshold=.1) {
 if(!Number.isFinite(threshold)||threshold<0||threshold>1)throw new Error("Invalid regression threshold");
 if(!baseline)return {status:"baseline-required",reason:"Candidate measurements are not proof of improvement"};
 if(candidate.environmentId!==baseline.environmentId || candidate.workloadVersion!==baseline.workloadVersion)throw new Error("Comparable environment and workload required");
 const metrics=Object.entries(baseline.metrics).map(([name,samples])=> {if(!candidate.metrics[name])throw new Error(`Missing metric ${name}`);const before=summarizeSamples(samples),after=summarizeSamples(candidate.metrics[name]);return {name,before,after,regressed:after.p95>before.p95*(1+threshold)};});
 if(!metrics.length)throw new Error("No baseline metrics");return {status:metrics.some(m=>m.regressed)?"failed":"passed",threshold,metrics};
}
if(process.argv[1]?.endsWith("performance-budget.mjs")&&process.argv[2]) {
 const candidate=JSON.parse(await readFile(process.argv[2],"utf8"));const baseline=process.argv[3]?JSON.parse(await readFile(process.argv[3],"utf8")):undefined;
 const result=comparePerformance(candidate,baseline);console.log(JSON.stringify(result,null,2));if(result.status==="failed")process.exitCode=1;
}
