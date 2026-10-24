// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";
import { desktopClient } from "@/lib/desktop-client";
import {
	InvestigationWorkspace,
	correlateEvidence,
} from "./investigation-workspace";
it("reopens selected case and forks metadata without executing or replaying tools", async () => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	const box = document.createElement("div"),
		root = createRoot(box),
		onSelect = vi.fn();
	document.body.appendChild(box);
	const item = {
		id: "owned",
		title: "Owned",
		revision: 3,
		state: "paused",
		summary: "checkpoint",
		questions: ["Which loader?"],
		evidence: [],
		transformations: [],
		jobs: [],
	};
	const invoke = vi
		.spyOn(desktopClient, "invoke")
		.mockImplementation(async (name) =>
			name === "list_investigations"
				? [item]
				: name === "mutate_investigation"
					? { ...item, id: "fork", parentId: "owned", revision: 0 }
					: item,
		);
	try {
		await act(async () =>
			root.render(
				<InvestigationWorkspace
					cwd="/owned"
					environmentId="local"
					selectedId="owned"
					onSelect={onSelect}
				/>,
			),
		);
		expect(onSelect).toHaveBeenCalledWith("owned");
		expect(onSelect).not.toHaveBeenCalledWith("");
		expect(box.textContent).toContain("revision 3");
		const fork = [...box.querySelectorAll("button")].find((b) =>
			b.textContent?.includes("Fork without replay"),
		)!;
		await act(async () => {
			fork.click();
			await Promise.resolve();
		});
		expect(invoke).toHaveBeenCalledWith(
			"mutate_investigation",
			expect.objectContaining({
				input: expect.objectContaining({
					action: "fork",
					revision: 3,
					confirmWrite: true,
				}),
			}),
		);
		expect(
			invoke.mock.calls.every(([name]) =>
				[
					"list_investigations",
					"get_investigation",
					"mutate_investigation",
				].includes(name),
			),
		).toBe(true);
	} finally {
		await act(async () => root.unmount());
		box.remove();
		vi.restoreAllMocks();
	}
});
it("keeps same-descriptor correlations ambiguous across static artifacts and unresolved native hashes", () => {
	const method = {
		classDescriptor: "LOwned;",
		name: "work",
		descriptor: "()V",
	};
	const registration = {
		...method,
		addressHex: "0x1234",
		relativeAddress: "0x34",
	};
	const rows = correlateEvidence([
		{ id: "a", provenance: "static", methods: [method] },
		{ id: "b", provenance: "static", methods: [method] },
		{
			id: "c",
			provenance: "signed-worker-report-not-hardware-attestation",
			registrations: [registration],
		},
	]);
	expect(rows[0].correlation).toBe("ambiguous-static-descriptor-matches");
	expect(rows[0].nativeIdentity).toBe("unresolved-module-hash");
});
it("reviews an evidence-linked question with exact case and question revisions without running tools",async()=>{
 Object.assign(globalThis,{IS_REACT_ACT_ENVIRONMENT:true});
 const box=document.createElement("div"),root=createRoot(box);document.body.append(box);
 const hash="a".repeat(64),unknownId="11111111-1111-4111-8111-111111111111",evidenceId="22222222-2222-4222-8222-222222222222";
 const item={id:"case",title:"Owned",revision:4,state:"active",summary:"",questions:[],
  unknowns:[{id:unknownId,revision:2,question:"Which caller supplies input?",status:"open",note:"Needs retained evidence",supporting:[],contradicting:[]}],
  evidence:[{id:evidenceId,resultHash:hash,engine:"ghidra",provenance:"static"}],transformations:[],jobs:[]};
 const invoke=vi.spyOn(desktopClient,"invoke").mockImplementation(async(name)=>name==="list_investigations"?[item]:item);
 try{
  await act(async()=>root.render(<InvestigationWorkspace cwd="/owned" environmentId="local" selectedId="case" onSelect={()=>{}}/>));
  const selects=[...box.querySelectorAll("select")];
  const evidence=selects.find(s=>[...s.options].some(o=>o.value===evidenceId))!;
  const role=selects.find(s=>[...s.options].some(o=>o.value==="contradicting"))!;
  await act(async()=>{evidence.value=evidenceId;evidence.dispatchEvent(new Event("change",{bubbles:true}));role.value="contradicting";role.dispatchEvent(new Event("change",{bubbles:true}));});
  await act(async()=>{[...box.querySelectorAll("button")].find(b=>b.textContent==="Save question review")!.click();await Promise.resolve();});
  expect(invoke).toHaveBeenCalledWith("mutate_investigation",expect.objectContaining({input:{
   action:"update_unknown",id:"case",revision:4,unknownId,unknownRevision:2,status:"open",note:"Needs retained evidence",
   supporting:[],contradicting:[{id:evidenceId,resultHash:hash}],confirmWrite:true,
  }}));
  expect(invoke.mock.calls.every(([name])=>["list_investigations","get_investigation","mutate_investigation"].includes(name))).toBe(true);
 }finally{await act(async()=>root.unmount());box.remove();vi.restoreAllMocks();}
});
