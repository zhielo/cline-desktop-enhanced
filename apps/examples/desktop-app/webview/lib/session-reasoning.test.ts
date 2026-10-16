// @vitest-environment jsdom
import { beforeEach, expect, it } from "vitest";
import {
	parseReasoning,
	readDraftReasoning,
	writeDraftReasoning,
	readSessionReasoning,
	writeSessionReasoning,
} from "./session-reasoning";
beforeEach(() => window.localStorage.clear());
it("isolates drafts, models, environments and existing chats", () => {
	writeDraftReasoning("local", "a", "cline", "one", {
		thinking: true,
		reasoningEffort: "high",
	});
	writeDraftReasoning("local", "b", "cline", "one", {
		thinking: true,
		reasoningEffort: "medium",
	});
	expect(readDraftReasoning("local", "a", "cline", "one").reasoningEffort).toBe(
		"high",
	);
	expect(
		readDraftReasoning("local", "new", "cline", "one").reasoningEffort,
	).toBe("medium");
	expect(
		readDraftReasoning("local", "a", "cline", "two").reasoningEffort,
	).toBeUndefined();
	expect(
		readDraftReasoning("ssh:a", "a", "cline", "one").reasoningEffort,
	).toBeUndefined();
	expect(readSessionReasoning("local", "a")).toBeUndefined();
	writeSessionReasoning("local", "a", {
		thinking: false,
		reasoningEffort: "high",
	});
	expect(readSessionReasoning("local", "a")).toEqual({
		thinking: false,
		reasoningEffort: undefined,
	});
});
it("rejects corrupted records and never persists credentials", () => {
	for (const value of [
		null,
		{ thinking: "true" },
		{ thinking: true, reasoningEffort: "extreme" },
	])
		expect(parseReasoning(value)).toBeUndefined();
	writeSessionReasoning("local", "a", {
		thinking: true,
		reasoningEffort: "xhigh",
		apiKey: "never-store",
	} as never);
	expect(JSON.stringify(window.localStorage)).not.toContain("never-store");
	window.localStorage.setItem(window.localStorage.key(0)!, "{broken");
	expect(readSessionReasoning("local", "a")).toBeUndefined();
});
