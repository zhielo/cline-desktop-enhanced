import { expect, it, vi } from "vitest";
const modes = vi.hoisted(() => vi.fn());
vi.mock("@cline/core", () => ({
	AnalysisModeSchema: { parse: (v: unknown) => v },
	FirstPartyAnalysisStore: class {
		setMode = modes;
		session() {
			return undefined;
		}
		summaries() {
			return [];
		}
	},
	runFirstPartyAnalysis: vi.fn(),
	queryFirstPartyEvidence: vi.fn(),
	cancelFirstPartyAnalysis: vi.fn(),
}));
import {
	handleFirstPartyCommand,
	firstPartyReadiness,
} from "./first-party-analysis";
it("requires trusted changes and an idle session", async () => {
	const session = { id: "s", workspace: "/owned", busy: false };
	await expect(
		handleFirstPartyCommand(
			"first_party_analysis_mode",
			{ mode: "static" },
			session,
			false,
		),
	).rejects.toThrow("trusted");
	await expect(
		handleFirstPartyCommand(
			"first_party_analysis_mode",
			{ mode: "static" },
			{ ...session, busy: true },
			true,
		),
	).rejects.toThrow("idle");
	expect(modes).not.toHaveBeenCalled();
	await handleFirstPartyCommand(
		"first_party_analysis_mode",
		{ mode: "static" },
		session,
		true,
	);
	expect(modes).toHaveBeenCalledWith("s", "/owned", "static");
});
it("reports readiness separately without certifying native or runtime capabilities", () => {
	expect(firstPartyReadiness()).toMatchObject({
		installed: true,
		staticFixture: { status: "not-tested" },
	});
	expect(firstPartyReadiness().runtimeCapture).toContain("not implemented");
});
