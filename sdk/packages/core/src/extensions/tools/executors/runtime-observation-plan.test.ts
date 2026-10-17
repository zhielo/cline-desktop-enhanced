import { spawn } from "node:child_process";
import { mkdtemp, writeFile, rm, stat, readFile, realpath } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { expect, it } from "vitest";
import { probeProcessStartTokenAsync } from "../../../runtime/process-start-token";
import { canonical } from "../../../analysis/contracts";
import { candidateHash } from "./candidate-files";
import { planRuntimeObservation } from "./runtime-observation-plan";
import { ReverseEngineeringInputSchema } from "../schemas";
import { InvestigationSchemas } from "../investigation";
import { createReverseEngineeringExecutor } from "./reverse-engineering";
const endpoint="ws://127.0.0.1:9229/00000000-0000-0000-0000-000000000000";
const observation={backend:"node-inspector",pid:1,processToken:"test",endpoint,durationMs:300,captureConsole:false};
it("runtime planner schemas reject model authority, unsupported backends and budgets",()=>{
 const base={artifactId:"11111111-1111-4111-8111-111111111111",observation};
 expect(InvestigationSchemas.plan_runtime_observation.parse(base)).toEqual(base);
 for(const key of ["executionToken","planId","mode","sessionId","phase","approved"])
  expect(()=>InvestigationSchemas.plan_runtime_observation.parse({...base,[key]:true})).toThrow();
 for(const change of [{backend:"gdb"},{durationMs:5001},{pid:0},{captureConsole:"true"},{script:"evaluate()"}])
  expect(()=>InvestigationSchemas.plan_runtime_observation.parse({...base,observation:{...observation,...change}})).toThrow();
});
it("planner rejects network endpoints, writes, option confusion and pre-cancellation",async()=>{
 const input=ReverseEngineeringInputSchema.parse({operation:"plan_runtime_observation",target:"/never",runtime_observation_plan:{...observation,expected_sha256:"a".repeat(64)}});
 for(const e of ["ws://outside.invalid:9229/00000000-0000-0000-0000-000000000000",endpoint+"?token=x","ws://user@127.0.0.1:9229/00000000-0000-0000-0000-000000000000"])
  await expect(planRuntimeObservation({...input,runtime_observation_plan:{...input.runtime_observation_plan!,endpoint:e}})).rejects.toThrow("loopback");
 await expect(planRuntimeObservation({...input,output_file:"/no-write"})).rejects.toThrow("no writes");
 const abort=new AbortController();abort.abort();
 await expect(planRuntimeObservation(input,abort.signal)).rejects.toThrow();
 await expect(createReverseEngineeringExecutor()({...input,operation:"inspect"},{} as never)).rejects.toThrow("only accepted");
});
it("plans a real owned paused Node listener without connecting or executing; rejects stale identity, source and PID",async()=>{
 if(!["linux","win32"].includes(process.platform))return;
 const root=await realpath(await mkdtemp(join(tmpdir(),"runtime-plan-owned-"))),target=join(root,"owned.js"),marker=join(root,"MUST_NOT_EXECUTE");
 const text='require("node:fs").writeFileSync('+JSON.stringify(marker)+',"executed");';
 await writeFile(target,text);
 const child=spawn(process.execPath,["--inspect-brk=127.0.0.1:0",target],{stdio:["ignore","ignore","pipe"]});
 let stderr="";child.stderr!.setEncoding("utf8").on("data",c=>stderr+=c);
 try{
  const until=Date.now()+10000;while(!/ws:\/\/127\.0\.0\.1:\d+\/[a-f0-9-]+/.test(stderr)&&Date.now()<until)await new Promise(r=>setTimeout(r,25));
  const ownedEndpoint=/ws:\/\/127\.0\.0\.1:\d+\/[a-f0-9-]+/.exec(stderr)?.[0];expect(ownedEndpoint).toBeTruthy();
  const identity=await probeProcessStartTokenAsync(child.pid!);if(identity.status!=="found")throw new Error("Owned identity unavailable");
  const input=ReverseEngineeringInputSchema.parse({operation:"plan_runtime_observation",target,runtime_observation_plan:{...observation,pid:child.pid!,processToken:identity.token,endpoint:ownedEndpoint,expected_sha256:candidateHash(text)}});
  const r=JSON.parse(await createReverseEngineeringExecutor()(input,{} as never));
  expect(r.status).toBe("completed");expect(r.attached).toBe(false);expect(r.approval.granted).toBe(false);expect(r.observedExecution).toBe(false);
  expect(r.nextRequest.operation).toBe("js_inspector_observe");expect(r.nextRequestSha256).toBe(candidateHash(canonical(r.nextRequest)));
  const {receiptSha256,...receipt}=r;expect(receiptSha256).toBe(candidateHash(canonical(receipt)));
  expect(stderr).not.toContain("Debugger attached");await expect(stat(marker)).rejects.toThrow();expect(await readFile(target,"utf8")).toBe(text);
  await expect(planRuntimeObservation({...input,runtime_observation_plan:{...input.runtime_observation_plan!,processToken:"stale"}})).rejects.toThrow("birth identity");
  const self=await probeProcessStartTokenAsync(process.pid);if(self.status!=="found")throw new Error("Self identity unavailable");
  await expect(planRuntimeObservation({...input,runtime_observation_plan:{...input.runtime_observation_plan!,pid:process.pid,processToken:self.token}})).rejects.toThrow("listener");
  await writeFile(target,text+"\n//changed");await expect(planRuntimeObservation(input)).rejects.toThrow("hash changed");
 }finally{child.kill("SIGKILL");await new Promise<void>(resolve=>{if(child.exitCode!==null||child.signalCode!==null)resolve();else child.once("exit",()=>resolve());});await rm(root,{recursive:true,force:true});}
},process.platform==="win32"?90000:30000);

it("runtime metadata commands reject model authority and unsafe resource budgets",()=>{
 const artifactId="11111111-1111-4111-8111-111111111111";
 expect(InvestigationSchemas.capture_process_tree.parse({artifactId,pid:123})).toMatchObject({maxProcesses:64});
 expect(InvestigationSchemas.capture_file_activity.parse({artifactId})).toMatchObject({durationMs:1000,maxEvents:64});
 for(const key of ["executionToken","processToken","owner_session_id","confirmRecord","mode","target"]){
  expect(()=>InvestigationSchemas.capture_process_tree.parse({artifactId,pid:123,[key]:"forged"})).toThrow();
  expect(()=>InvestigationSchemas.capture_file_activity.parse({artifactId,[key]:"forged"})).toThrow();
 }
 expect(()=>InvestigationSchemas.capture_file_activity.parse({artifactId,durationMs:5001})).toThrow();
 expect(()=>InvestigationSchemas.capture_process_tree.parse({artifactId,pid:123,maxProcesses:129})).toThrow();
});
