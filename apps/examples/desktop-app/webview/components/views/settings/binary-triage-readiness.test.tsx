// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
const invoke = vi.hoisted(() => vi.fn(async (name: string) => {
 if(name === "binary_triage_status") return {capabilities:["radare2","yara","capa","floss"].map(id=>({id,state:"installed-not-tested",reason:"Needs owned test"}))};
 throw new Error("Owned radare2 fixture failed; not ready (failed; r2-open:FileNotFoundError)");
}));
vi.mock("@/lib/desktop-client",()=>({desktopClient:{invoke}}));
import {BinaryTriageReadiness,ownedTriageDiagnostic} from "./binary-triage-readiness";
Object.assign(globalThis,{IS_REACT_ACT_ENVIRONMENT:true});
it("shows bounded owned diagnostics, not arbitrary transport errors",()=>{
 expect(ownedTriageDiagnostic(new Error("transport SECRET /private/path"))).toBe("No bounded engine diagnostic was returned");
 expect(ownedTriageDiagnostic(new Error("Owned yara fixture failed; not ready (failed; yara-import:ModuleNotFoundError)"))).toContain("yara-import:ModuleNotFoundError");
});
it("opening does not execute; explicit test failure is visible without replay",async()=>{
 const host=document.createElement("div");document.body.append(host);const root=createRoot(host);
 const confirm=vi.spyOn(window,"confirm").mockReturnValue(true);invoke.mockClear();
 try {
  await act(async()=>root.render(<BinaryTriageReadiness/>));
  expect(invoke.mock.calls.every(([n])=>n==="binary_triage_status")).toBe(true);
  const button=Array.from(host.querySelectorAll("button")).find(b=>b.textContent==="Test triage fixtures")!;
  await act(async()=>button.click());
  expect(host.querySelector('[role="alert"]')?.textContent).toContain("r2-open:FileNotFoundError");
  expect(invoke.mock.calls.filter(([n])=>n==="binary_triage_test")).toHaveLength(1);
 } finally {await act(async()=>root.unmount());host.remove();confirm.mockRestore();}
});
