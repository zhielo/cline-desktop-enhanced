import { spawn, type ChildProcess } from "node:child_process";
import { constants } from "node:fs";
import { mkdtemp, open, realpath, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { z } from "zod";
import { prepareProcessEnvironment } from "./process-environment-policy";
import type { AdvancedResult } from "./advanced-analysis";
const MAX_INPUT=128*1024*1024, MAX_OUTPUT=1048576;
const Hex=z.string().regex(/^[a-f0-9]{1,16}$/);
export const RizinProgramSchema=z.object({schemaVersion:z.literal(1),producer:z.literal("rizin-function-inventory"),engineVersion:z.string().min(1).max(128),imageBase:Hex.nullable(),architecture:z.string().max(128),bits:z.number().int().min(1).max(128),format:z.string().max(128),functions:z.array(z.object({name:z.string().max(512),entry:Hex,size:z.number().int().min(0).max(MAX_INPUT),assemblyBlockCount:z.number().int().min(0).max(1000000).nullable()}).strict()).max(64),coverage:z.object({reportedFunctions:z.number().int().min(0).max(10000),selectedFunctions:z.number().int().min(0).max(10000),truncated:z.boolean()}).strict()}).strict().superRefine((v,c)=>{if(new Set(v.functions.map(f=>f.entry)).size!==v.functions.length)c.addIssue({code:"custom",message:"Duplicate Rizin function entry"});if(v.functions.length>v.coverage.selectedFunctions||v.coverage.selectedFunctions>v.coverage.reportedFunctions)c.addIssue({code:"custom",message:"Invalid function coverage"});});
export type RizinProgram=z.infer<typeof RizinProgramSchema>;
export function safeRizinAddress(value:unknown):string|null{
 if(typeof value==="number")return Number.isSafeInteger(value)&&value>=0?value.toString(16):null;
 if(typeof value==="string"&&/^(?:0x)?[a-fA-F0-9]{1,16}$/.test(value))return value.replace(/^0x/,"").toLowerCase();
 return null;
}
export function parseRizinProgram(stdout:string,version:string,options:{functionName?:string;maxFunctions?:number}={}):RizinProgram{
 if(Buffer.byteLength(stdout)>MAX_OUTPUT)throw Error("Rizin output byte budget exceeded");
 const limit=options.maxFunctions??16;if(!Number.isInteger(limit)||limit<1||limit>64)throw Error("Invalid function budget");
 if(options.functionName!==undefined&&(typeof options.functionName!=="string"||options.functionName.length>512))throw Error("Invalid function selector");
 const lines=stdout.trim().split(/\r?\n/);if(lines.length!==2)throw Error("Expected two bounded Rizin JSON documents");
 const info=z.object({baddr:z.unknown(),arch:z.string().max(128),bits:z.number().int().min(1).max(128),bintype:z.string().max(128)}).parse(JSON.parse(lines[0]));
 const all=z.array(z.object({offset:z.unknown(),name:z.string().max(512),size:z.number().int().min(0).max(MAX_INPUT),nbbs:z.number().int().min(0).max(1000000).optional()})).max(10000).parse(JSON.parse(lines[1]));
 const selected=all.filter(f=>!options.functionName||f.name===options.functionName||f.name===`dbg.${options.functionName}`||f.name===`sym.${options.functionName}`);
 const functions=selected.slice(0,limit).map(f=>{const entry=safeRizinAddress(f.offset);if(entry===null)throw Error("Function address lost precision or is invalid");return {name:f.name,entry,size:f.size,assemblyBlockCount:f.nbbs??null};});
 return RizinProgramSchema.parse({schemaVersion:1,producer:"rizin-function-inventory",engineVersion:version,imageBase:safeRizinAddress(info.baddr),architecture:info.arch,bits:info.bits,format:info.bintype,functions,coverage:{reportedFunctions:all.length,selectedFunctions:selected.length,truncated:selected.length>limit}});
}
function killTree(child:ChildProcess){if(!child.pid)return;if(process.platform==="win32"){const killer=spawn(join(process.env.SystemRoot??"C:\\Windows","System32","taskkill.exe"),["/pid",String(child.pid),"/t","/f"],{stdio:"ignore",windowsHide:true});killer.on("error",()=>child.kill());killer.unref();}else{try{process.kill(-child.pid,"SIGKILL");}catch{child.kill();}}}
async function invoke(engine:string,args:string[],cwd:string,deadline:number,signal?:AbortSignal):Promise<string>{
 if(signal?.aborted)throw Error("cancelled");
 const env={...prepareProcessEnvironment({}).environment};for(const k of Object.keys(env))if(/^(?:RZ_|RIZIN_)/i.test(k))delete env[k];
 return new Promise((resolve,reject)=>{const remaining=deadline-Date.now();if(remaining<=0){reject(Error("deadline exceeded"));return;}const child=spawn(engine,args,{cwd,env,stdio:["ignore","pipe","pipe"],detached:process.platform!=="win32",windowsHide:true});let total=0,done=false;const chunks:Buffer[]=[];
 const finish=(error?:Error)=>{if(done)return;done=true;clearTimeout(timer);signal?.removeEventListener("abort",abort);if(error){killTree(child);reject(error);}else resolve(Buffer.concat(chunks,total).toString("utf8"));};
 const abort=()=>finish(Error("cancelled"));const timer=setTimeout(()=>finish(Error("deadline exceeded")),remaining);signal?.addEventListener("abort",abort,{once:true});if(signal?.aborted)abort();
 child.stdout?.on("data",(data:Buffer)=>{total+=data.length;if(total>MAX_OUTPUT){finish(Error("Rizin output byte budget exceeded"));return;}chunks.push(data);});child.stderr?.on("data",()=>{});child.on("error",()=>finish(Error("Engine launch failed")));child.on("close",code=>finish(code===0?undefined:Error("Engine exited unsuccessfully")));
 });
}
export async function recoverRizinProgram(engine:string|undefined,target:string,options:{functionName?:string;maxFunctions?:number}={},timeoutMs=120000,signal?:AbortSignal):Promise<AdvancedResult>{
 const blocked=(status:AdvancedResult["status"],reason:string):AdvancedResult=>({protocol:"cline-advanced-analysis/v1",status,engine:"rizin",engineVersion:null,evidence:{reason},limitations:["No target execution, native equivalence or OS isolation is established."]});
 if(!engine)return blocked("blocked","Configure a reviewed absolute CLINE_RE_RIZIN executable");
 if(!isAbsolute(engine)||/\.(?:bat|cmd|ps1)$/i.test(engine))throw Error("Reviewed absolute native Rizin executable required");
 if(!isAbsolute(target)||!Number.isInteger(timeoutMs)||timeoutMs<1000||timeoutMs>300000)throw Error("Invalid target or deadline");
 if(signal?.aborted)return blocked("cancelled","Cancelled before input acquisition");
 const deadline=Date.now()+timeoutMs,directory=await mkdtemp(join(tmpdir(),"cline-rizin-"));
 try{
  const source=await open(await realpath(target),constants.O_RDONLY|(process.platform==="win32"?0:constants.O_NOFOLLOW));const snapshot=join(directory,"artifact.bin"),hash=createHash("sha256");let bytes=0;
  try{const before=await source.stat();if(!before.isFile()||before.size>MAX_INPUT)throw Error("Regular bounded artifact required");const dest=await open(snapshot,"wx",0o600);try{const buffer=Buffer.alloc(65536);for(;;){if(signal?.aborted)return blocked("cancelled","Cancelled while copying artifact");if(Date.now()>deadline)throw Error("deadline exceeded");const {bytesRead}=await source.read(buffer,0,buffer.length,null);if(!bytesRead)break;bytes+=bytesRead;if(bytes>MAX_INPUT)throw Error("Input byte budget exceeded");hash.update(buffer.subarray(0,bytesRead));let written=0;while(written<bytesRead){const chunk=await dest.write(buffer,written,bytesRead-written,null);if(!chunk.bytesWritten)throw Error("Snapshot short write");written+=chunk.bytesWritten;}}await dest.sync();}finally{await dest.close();}const after=await source.stat();if(before.size!==after.size||before.mtimeMs!==after.mtimeMs||bytes!==before.size)throw Error("Artifact changed while copying");}finally{await source.close();}
  const versionOutput=await invoke(engine,["-v"],directory,deadline,signal);const version=/^rizin ([0-9]+\.[0-9]+\.[0-9]+)\b/m.exec(versionOutput)?.[1];if(!version)throw Error("Unrecognized Rizin version output");
  // Fixed data-only query. Disable user scripts/plugins, debugging and exec I/O.
  const raw=await invoke(engine,["-NN","-q","-2","-x","-e","scr.color=false","-c","aaa;iIj;aflj",snapshot],directory,deadline,signal);
  const program=parseRizinProgram(raw,version,options);if(!program.functions.length)return blocked("failed","No selected functions recovered");
  return {protocol:"cline-advanced-analysis/v1",status:program.coverage.truncated||program.imageBase===null?"partial":"completed",engine:"rizin",engineVersion:version,input:{sha256:hash.digest("hex"),bytes,format:program.format},evidence:{program},limitations:["Function boundaries and assembly block counts are static Rizin interpretations, not native semantic equivalence.","Assembly block counts are not directly comparable to Ghidra high-p-code CFG block counts.","No target execution, automatic patching or measured OS/network containment."]};
 }catch(error){if(signal?.aborted)return blocked("cancelled","Cancelled during static recovery");return blocked("failed",error instanceof Error?error.message:"Static recovery failed");}finally{await rm(directory,{recursive:true,force:true});}
}
