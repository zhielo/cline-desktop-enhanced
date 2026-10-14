import { it, expect } from "vitest";
import { reconcileFeature, evidenceIndex } from "./investigation-report";
it("preserves provenance without upgrading static observations to runtime proof", () => {
	const r = reconcileFeature(
		"checkout",
		{
			id: "receipt",
			result: {
				facts: [
					{
						id: "fact",
						kind: "ipc-send",
						value: "checkout",
						confidence: "observed",
						location: {
							path: "preload.js",
							sha256: "a".repeat(64),
							line: 2,
							column: 1,
						},
					},
				],
			},
		},
		[{ id: "scenario" }],
	);
	expect(r.provenance).toEqual({
		receiptId: "receipt",
		scenarioIds: ["scenario"],
	});
	expect(r.staticCandidates[0]).toMatchObject({
		classification: "statically-inferred",
		sourceConfidence: "observed",
		location: { line: 2 },
	});
	expect(r.stages.find((s) => s.stage === "ipc")?.candidateIds).toEqual([
		"fact",
	]);
	expect(r.coverage.causalEdgesEstablished).toBe(0);
	expect(r.unresolvedBoundaries.every((g) => g.status === "unresolved")).toBe(
		true,
	);
});
it("bounds matches and tolerates malformed imported facts", () => {
	const r = reconcileFeature(
		"x",
		{
			result: {
				facts: [
					null,
					{},
					false,
					...Array.from({ length: 101 }, (_, i) => ({
						id: String(i),
						kind: "call",
						value: "x",
					})),
				],
			},
		},
		[],
	);
	expect(r.coverage).toMatchObject({
		matchingFacts: 101,
		returnedFacts: 100,
		truncated: true,
	});
	expect(reconcileFeature("absent", {}, []).status).toBe("unresolved");
});
it("indexes receipts without pretending provider output is embedded", () => {
	const index = evidenceIndex([
		{ payload: { task: { id: "task", status: "completed" } } },
		{ id: "s", capture: {} },
		{ id: "r", result: { facts: [{ id: "f" }] } },
	]);
	expect(index.map((x) => x.reference)).toEqual([
		"#/records/0",
		"#/records/1",
		"#/records/2",
	]);
	expect(index[0].interpretation).toContain("when present");
	expect(index.map((x) => x.kind)).toEqual([
		"task-receipt",
		"browser-scenario",
		"static-receipt",
	]);
});

it("reports selected native candidates with identity but no fabricated relocation or scenario edge", () => {
	const task = {
		providerSnapshot: {
			taskId: "task",
			targetSha256: "a".repeat(64),
			result: {
				engine: "ida",
				evidence: {
					selectedFunctions: [
						{
							name: "owned",
							addressHex: "0x1000",
							image: { addressSpace: "ida-database-virtual" },
							callees: [
								{ kind: "indirect", resolution: "unknown-expression-target" },
							],
						},
					],
				},
			},
		},
	};
	const report = reconcileFeature("owned", {}, [], [task]);
	expect(report.selectedNativeFunctions[0]).toMatchObject({
		taskId: "task",
		targetSha256: "a".repeat(64),
		classification: "provider-reported-static-candidates",
		runtimeRelocation: "not-established",
	});
	expect(report.coverage.causalEdgesEstablished).toBe(0);
});
it("Hybrid pairings retain the question without fabricating corroboration",()=>{
 const context={baselineKind:"receipt",baselineId:"receipt",evidenceHash:"a".repeat(64),question:"Which handler?",relation:"investigation-context-only"};
 const r=reconcileFeature("handler",{},[{id:"scenario",capture:{hybrid:context}}]);expect(r.hybridObservations).toEqual([expect.objectContaining({context,questionStatus:"unresolved",corroboration:"not-established"})]);expect(r.coverage.causalEdgesEstablished).toBe(0);
});
