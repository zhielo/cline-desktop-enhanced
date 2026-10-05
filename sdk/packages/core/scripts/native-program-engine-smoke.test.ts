import { describe, it, expect } from "bun:test";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { recoverNativeProgram, type NativeProgram } from "../src/extensions/tools/executors/native-program";
const engine=process.env.CLINE_RE_GHIDRA;
if(!engine||!isAbsolute(engine))throw new Error("An absolute reviewed Ghidra headless path is required; this real corpus never skips");
describe("real native adapter on an owned compiled fixture",()=>{
 it("recovers nonempty entry-bound CFG and p-code while retaining the copied artifact hash",async()=>{
  const directory=await mkdtemp(join(tmpdir(),"cline-native-corpus-"));
  try{
   const source=join(directory,"owned.c");
   const windows=process.platform==="win32";
   const artifact=join(directory,windows?"owned.dll":"owned.so");
   await writeFile(source,`${windows?'__declspec(dllexport) ':''}unsigned analyze_fixture(unsigned x) { unsigned y=(x^0x5a)+7; for(unsigned i=0;i<3;i++)y=(y<<1)^i; if((x&3)==2)y+=11; return y; }`);
   if(windows)execFileSync("cl.exe",["/nologo","/LD","/Od",source,`/Fe:${artifact}`,`/Fo:${join(directory,"owned.obj")}`],{cwd:directory,timeout:30000,stdio:"pipe"});
   else execFileSync("gcc",["-shared","-fPIC","-O1","-g",source,"-o",artifact],{cwd:directory,timeout:30000,stdio:"pipe"});
   const bytes=await readFile(artifact);
   const result=await recoverNativeProgram(engine,artifact,{functionName:"analyze_fixture",maxFunctions:1,maxPcodeOps:512},120000);
   expect(result.status).toBe("completed");
   expect(result.engine).toBe("ghidra");
   expect(result.engineVersion).toBe("12.1.4");
   expect(result.input?.sha256).toBe(createHash("sha256").update(bytes).digest("hex"));
   expect(result.input?.bytes).toBe(bytes.length);
   const program=result.evidence.program as NativeProgram;
   expect(program.functions.length).toBe(1);
   const fn=program.functions[0];
   expect(fn.name).toBe("analyze_fixture");
   expect(fn.blocks.length).toBeGreaterThan(0);
   expect(fn.entryBlock).not.toBeNull();
   expect(fn.blocks.some(b=>b.id===fn.entryBlock)).toBe(true);
   expect(fn.pcode.length).toBeGreaterThan(0);
   expect(fn.pcode.some(op=>op.output===null)).toBe(true);
   expect(program.coverage.pcodeOperations).toBe(fn.pcode.length);
   expect(result.limitations.join(" ")).toContain("No target execution");
  }finally{await rm(directory,{recursive:true,force:true});}
 },180000);
});
