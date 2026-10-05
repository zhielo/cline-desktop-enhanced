import {describe,it,expect} from "vitest";
import {parseRizinProgram,safeRizinAddress,recoverRizinProgram} from "./rizin-program";
const info={baddr:0,arch:"x86",bits:64,bintype:"elf"};
function raw(functions:unknown[]=[{offset:4096,name:"dbg.owned",size:16,nbbs:2}]){return JSON.stringify(info)+"\n"+JSON.stringify(functions)+"\n";}
describe("bounded Rizin evidence",()=>{
 it("preserves precise numeric and explicit 64-bit hex addresses",()=>{expect(safeRizinAddress(4096)).toBe("1000");expect(safeRizinAddress("0xffffffffffffffff")).toBe("ffffffffffffffff");expect(safeRizinAddress(2**53)).toBeNull();expect(safeRizinAddress(-1)).toBeNull();});
 it("normalizes owned reported function fields",()=>{const p=parseRizinProgram(raw(),"unit-model");expect(p.functions[0].entry).toBe("1000");expect(p.functions[0].assemblyBlockCount).toBe(2);expect(p.coverage.truncated).toBe(false);});
 it("selects literal debug or symbol names without injecting commands",()=>{expect(parseRizinProgram(raw(),"unit-model",{functionName:"owned"}).functions.length).toBe(1);expect(parseRizinProgram(raw(),"unit-model",{functionName:"owned;!id"}).functions.length).toBe(0);});
 it("marks bounded selection truncation",()=>{const p=parseRizinProgram(raw([{offset:1,name:"a",size:1},{offset:2,name:"b",size:1}]),"unit-model",{maxFunctions:1});expect(p.functions.length).toBe(1);expect(p.coverage.truncated).toBe(true);expect(p.coverage.selectedFunctions).toBe(2);});
 it("rejects unsafe precision instead of rounding an entry address",()=>{expect(()=>parseRizinProgram(raw([{offset:2**53,name:"bad",size:1}]),"unit-model")).toThrow("precision");});
 it("rejects duplicate entries",()=>{expect(()=>parseRizinProgram(raw([{offset:1,name:"a",size:1},{offset:1,name:"b",size:1}]),"unit-model")).toThrow("Duplicate");});
 it("rejects unexpected output documents and byte overruns",()=>{expect(()=>parseRizinProgram(raw()+"{}","unit-model")).toThrow("two bounded");expect(()=>parseRizinProgram("x".repeat(1048577),"unit-model")).toThrow("byte budget");});
 it("rejects invalid budgets",()=>{expect(()=>parseRizinProgram(raw(),"unit-model",{maxFunctions:65})).toThrow("budget");});
 it("blocks missing engines",async()=>{expect((await recoverRizinProgram(undefined,"/missing")).status).toBe("blocked");});
 it("rejects relative or batch engines",async()=>{await expect(recoverRizinProgram("rizin","/missing")).rejects.toThrow("absolute");await expect(recoverRizinProgram("/reviewed/engine.cmd","/missing")).rejects.toThrow("absolute");});
 it("honors pre-acquisition cancellation",async()=>{const a=new AbortController();a.abort();expect((await recoverRizinProgram("/reviewed/rizin","/missing",{},1000,a.signal)).status).toBe("cancelled");});
});
