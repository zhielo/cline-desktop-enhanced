import { it, expect } from "vitest";
import { mkdtemp, rm, realpath } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
	HybridProposalSchema,
	HybridContextSchema,
	runtimeAnalysisEnabled,
} from "./hybrid";
import { AnalysisModeSchema } from "./contracts";
import { FirstPartyAnalysisStore } from "./store";
it("adds Hybrid without changing existing modes or accepting unknown modes", () => {
	for (const mode of ["off", "static", "runtime", "hybrid"])
		expect(AnalysisModeSchema.parse(mode)).toBe(mode);
	expect(() => AnalysisModeSchema.parse("auto-execute")).toThrow();
	expect(runtimeAnalysisEnabled("hybrid")).toBe(true);
	expect(runtimeAnalysisEnabled("static")).toBe(false);
	expect(runtimeAnalysisEnabled("off")).toBe(false);
	expect(runtimeAnalysisEnabled("runtime")).toBe(true);
});
it("proposals are strict evidence selections and never authority", () => {
	const p = {
		baselineKind: "receipt",
		baselineId: "11111111-1111-4111-8111-111111111111",
		question: "Which handler is reached?",
	};
	expect(HybridProposalSchema.parse(p)).toEqual(p);
	for (const k of [
		"mode",
		"sessionId",
		"workspace",
		"executionToken",
		"confirmRecord",
		"evidenceHash",
	])
		expect(() => HybridProposalSchema.parse({ ...p, [k]: "fake" })).toThrow();
	expect(() => HybridProposalSchema.parse({ ...p, question: "  " })).toThrow();
	expect(() => HybridContextSchema.parse(p)).toThrow();
});
it("persists Hybrid per session across restart and preserves other session modes", async () => {
	const root = await realpath(
			await mkdtemp(join(tmpdir(), "hybrid-store-owned-")),
		),
		file = join(root, "evidence.sqlite");
	let db = new FirstPartyAnalysisStore(file);
	try {
		db.setMode("hybrid-owner", root, "hybrid");
		db.setMode("unchanged", root, "static");
		db.close();
		db = new FirstPartyAnalysisStore(file);
		expect(db.session("hybrid-owner")?.mode).toBe("hybrid");
		expect(db.session("unchanged")?.mode).toBe("static");
		expect(db.session("unknown")).toBeUndefined();
	} finally {
		db.close();
		await rm(root, { recursive: true, force: true });
	}
});
