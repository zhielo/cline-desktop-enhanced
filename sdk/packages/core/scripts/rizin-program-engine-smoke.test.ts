import {it,expect} from "bun:test";
import {mkdtemp,writeFile,readFile,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join,isAbsolute} from "node:path";
import {execFileSync} from "node:child_process";
import {createHash} from "node:crypto";
import {recoverRizinProgram,type RizinProgram} from "../src/extensions/tools/executors/rizin-program";
const engine=process.env.CLINE_RE_RIZIN;
if(!engine||!isAbsolute(engine))throw Error("Reviewed absolute Rizin required; this real corpus never skips");
it("recovers owned functions through the fixed snapshotting adapter",async()=>{
 const dir=await mkdtemp(join(tmpdir(),"cline-rizin-corpus-"));try{
 const source=join(dir,"owned.c"),target=join(dir,"owned.so");await writeFile(source,"unsigned analyze_fixture(unsigned x){return (x^90)+7;}");
 execFileSync("gcc",["-shared","-fPIC","-O1","-g",source,"-o",target],{cwd:dir,timeout:30000,stdio:"pipe"});
 const bytes=await readFile(target),r=await recoverRizinProgram(engine,target,{functionName:"analyze_fixture",maxFunctions:1},30000);
 expect(r.status).toBe("completed");expect(r.engineVersion).toBe("0.9.1");expect(r.input?.sha256).toBe(createHash("sha256").update(bytes).digest("hex"));expect(r.input?.bytes).toBe(bytes.length);
 const p=r.evidence.program as RizinProgram;expect(p.functions.length).toBe(1);expect(p.functions[0].name.endsWith("analyze_fixture")).toBe(true);expect(p.imageBase).not.toBeNull();expect(r.limitations.join(" ")).toContain("not directly comparable");
 }finally{await rm(dir,{recursive:true,force:true});}
},40000);
