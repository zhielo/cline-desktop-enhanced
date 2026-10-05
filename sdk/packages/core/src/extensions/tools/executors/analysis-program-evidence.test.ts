import {describe,it,expect} from "vitest";import {analyzeProgramCfg,analyzeProgramTrace,programEvidenceResult} from "./analysis-program-evidence";
const cfg=(blocks:Array<[string,string[]]>)=>({schemaVersion:1,entry:"a",blocks:blocks.map(([id,successors])=>({id,successors}))});
const trace=()=>({schemaVersion:1,sinkSeq:3,sources:[{seq:0,location:"r0"}],instructions:[{seq:0,operation:"input",reads:[],writes:["r0"]},{seq:1,operation:"copy",reads:["r0"],writes:["r1"]},{seq:2,operation:"other",reads:[],writes:["r9"]},{seq:3,operation:"use",reads:["r1"],writes:["r2"]}]});
describe("bounded program evidence",()=>{
 it("computes diamond dominance and postdominance",()=>{const r=analyzeProgramCfg(cfg([["a",["b","c"]],["b",["d"]],["c",["d"]],["d",[]],["u",[]]]));expect(r.dominators.d).toEqual(["a","d"]);expect(r.postdominators.a).toEqual(["a","d"]);expect(r.unreachable).toEqual(["u"]);});
 it("omits postdominance for nonterminating regions",()=>{const r=analyzeProgramCfg(cfg([["a",["b"]],["b",["b"]]]));expect(r.noExitPath).toEqual(["a","b"]);expect(r.postdominators).toEqual({});expect(r.naturalLoops[0].header).toBe("b");});
 it("detects irreducible cycles",()=>expect(analyzeProgramCfg(cfg([["a",["b","c"]],["b",["c"]],["c",["b","d"]],["d",[]]])).irreducibleRegions).toEqual([["b","c"]]));
 it("rejects bad successors and duplicate IDs",()=>{expect(()=>analyzeProgramCfg(cfg([["a",["missing"]]]))).toThrow();expect(()=>analyzeProgramCfg(cfg([["a",[]],["a",[]]]))).toThrow();});
 it("rejects script fields and oversized CFGs",()=>{expect(()=>analyzeProgramCfg({...cfg([["a",[]]]),script:"run"})).toThrow();expect(()=>analyzeProgramCfg(cfg(Array.from({length:257},(_,i)=>[i?`n${i}`:"a",[]])))).toThrow();});
 it("slices transitive last definitions",()=>expect(analyzeProgramTrace(trace(),"slice").slice?.map(x=>x.instruction.seq)).toEqual([0,1,3]));
 it("kills input influence on overwrite",()=>{const t=trace();t.instructions[2]={seq:2,operation:"clear",reads:[],writes:["r1"]};expect(analyzeProgramTrace(t,"taint").influence?.map(x=>x.seq)).toEqual([1]);});
 it("reports unresolved memory",()=>{const t=trace();t.instructions[3].reads=["mem:unknown"];expect(analyzeProgramTrace(t,"slice").unresolvedReads).toEqual([{seq:3,location:"mem:unknown"}]);});
 it("rejects malformed trace order, sources and sinks",()=>{const t=trace();t.instructions[1].seq=0;expect(()=>analyzeProgramTrace(t,"slice")).toThrow();expect(()=>analyzeProgramTrace({...trace(),sinkSeq:10},"slice")).toThrow();expect(()=>analyzeProgramTrace({...trace(),sources:[{seq:0,location:"unknown"}]},"taint")).toThrow();});
 it("does not claim runtime execution or equivalence",()=>expect(programEvidenceResult("cfg_analyze",cfg([["a",[]]]))).toMatchObject({status:"partial",evidence:{equivalence:"not-proven"}}));
});
