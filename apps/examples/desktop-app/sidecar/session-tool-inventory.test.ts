import { expect, it } from "vitest";
import { projectSessionToolInventory } from "./session-tool-inventory";
const fixture = {
	status: "last-request",
	revision: 0,
	providerId: "fixture-provider",
	modelId: "fixture-model",
	evidence: {
		version: 1,
		capturedAt: "2026-10-28T00:00:00.000Z",
		iteration: 1,
		toolNames: ["reverse_engineer"],
		toolCount: 1,
		modelToolNames: [],
		modelToolCount: 0,
		truncated: false,
	},
};
it("projects bounded request names without secret or unknown fields and preserves stale state", () => {
	const projected = projectSessionToolInventory("owner", {
		...fixture,
		apiKey: "SECRET",
		evidence: { ...fixture.evidence, headers: { secret: "SECRET" } },
	});
	expect(projected.status).toBe("last-request");
	expect(JSON.stringify(projected)).not.toContain("SECRET");
	expect(
		projectSessionToolInventory("owner", { ...fixture, status: "stale" })
			.status,
	).toBe("stale");
	expect(projected.authorization).toContain("Not granted");
});
it("missing, legacy, malformed and inconsistent evidence remain unavailable", () => {
	for (const value of [
		undefined,
		{},
		{ status: "unavailable" },
		{ ...fixture, evidence: { ...fixture.evidence, toolCount: 0 } },
		{
			...fixture,
			evidence: { ...fixture.evidence, toolNames: Array(257).fill("x") },
		},
	])
		expect(projectSessionToolInventory("owner", value).status).toBe(
			"unavailable",
		);
});
