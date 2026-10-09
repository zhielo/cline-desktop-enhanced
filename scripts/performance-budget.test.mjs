import { expect,test } from "bun:test";
import { comparePerformance,summarizeSamples } from "./performance-budget.mjs";
const baseline={environmentId:"owned-hardware",workloadVersion:"owned-v1",metrics:{startup:[100,110,120]}};
test("relative budgets use p95 and never call missing baseline passed",()=>{expect(comparePerformance(baseline)).toMatchObject({status:"baseline-required"});expect(comparePerformance({...baseline,metrics:{startup:[90,100,110]}},baseline).status).toBe("passed");expect(comparePerformance({...baseline,metrics:{startup:[100,120,140]}},baseline).status).toBe("failed");});
test("rejects incomparable, missing, empty, or fabricated measurements",()=>{expect(()=>comparePerformance({...baseline,environmentId:"different"},baseline)).toThrow();expect(()=>comparePerformance({...baseline,metrics:{}},baseline)).toThrow();expect(()=>summarizeSamples([1,NaN,3])).toThrow();expect(()=>summarizeSamples([1])).toThrow();});
test("even an unbaselined candidate must contain valid provenance and measured samples",()=>{
	expect(()=>comparePerformance({metrics:{startup:[1,2,3]}})).toThrow();
	expect(()=>comparePerformance({...baseline,metrics:{startup:[1,NaN,3]}})).toThrow();
	expect(()=>comparePerformance({...baseline,metrics:{}})).toThrow();
});
