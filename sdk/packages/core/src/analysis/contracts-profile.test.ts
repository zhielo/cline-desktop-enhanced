import { expect, it } from "vitest";
import { ANALYSIS_PROFILE, ResultSchema } from "./contracts";
import { ANALYSIS_PROFILE as NEUTRAL_PROFILE } from "./profile";

const receipt = {
	profile: NEUTRAL_PROFILE,
	parserVersion: "owned-profile-fixture",
	status: "partial",
	artifacts: [],
	facts: [],
	edges: [],
	limitations: [],
	counters: { entries: 0, bytes: 0, nodes: 0 },
};
it("re-exports the same runtime-neutral receipt profile and rejects stale receipt versions", () => {
	expect(ANALYSIS_PROFILE).toBe(NEUTRAL_PROFILE);
	expect(ResultSchema.parse(receipt).profile).toBe(NEUTRAL_PROFILE);
	for (const profile of [
		"cline-js-static/6",
		"cline-js-static/1",
		"",
		"unknown",
	])
		expect(ResultSchema.safeParse({ ...receipt, profile }).success).toBe(false);
});
it("retains the full original schema and rejects malformed fuse evidence", () => {
	expect(
		ResultSchema.safeParse({ ...receipt, electronFuses: {} }).success,
	).toBe(false);
	expect(
		ResultSchema.safeParse({
			...receipt,
			electronFuses: { artifact: { sha256: "wrong" }, slices: [] },
		}).success,
	).toBe(false);
});
