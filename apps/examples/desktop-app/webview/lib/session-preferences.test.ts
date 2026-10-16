import { describe, expect, it } from "vitest";
import {
	readSessionReasoningPreference,
	reasoningPreferenceMetadata,
} from "@/lib/session-preferences";

describe("session reasoning preferences", () => {
	it("restores Medium, High, and Extra from session metadata", () => {
		for (const reasoningEffort of ["medium", "high", "xhigh"] as const) {
			expect(
				readSessionReasoningPreference(
					reasoningPreferenceMetadata({
						thinking: true,
						reasoningEffort,
					}),
				),
			).toEqual({ thinking: true, reasoningEffort });
		}
	});

	it("preserves an explicit None selection", () => {
		expect(
			readSessionReasoningPreference(
				reasoningPreferenceMetadata({ thinking: false }),
			),
		).toEqual({ thinking: false });
	});

	it("ignores malformed metadata instead of selecting an invalid effort", () => {
		expect(
			readSessionReasoningPreference({
				chatPreferences: { reasoning: { thinking: true, reasoningEffort: "deep" } },
			}),
		).toBeUndefined();
	});
});
