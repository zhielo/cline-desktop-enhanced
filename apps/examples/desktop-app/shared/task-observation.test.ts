import { describe, it, expect } from "vitest";
import {
	hostToolObservation,
	reportedOutcome,
	redactReportText,
	validationScope,
} from "./task-observation";
describe("host task observations", () => {
	const input = {
		sessionId: "session-1",
		toolCallId: "tool-1",
		toolName: "analyze",
		now: 10,
	};
	it("never promotes successful tool output to verified", () => {
		for (const output of [
			{ ok: true },
			{ status: "verified" },
			{ outcome: "bounded-checks-passed" },
		])
			expect(hostToolObservation({ ...input, output })?.outcome).toBe(
				"unverified",
			);
	});
	it("downgrades nested partial, blocked, timeout and error output", () => {
		expect(reportedOutcome({ result: { status: "partial" } })).toBe("partial");
		expect(
			reportedOutcome({ status: "blocked", result: { status: "partial" } }),
		).toBe("blocked");
		for (const output of [
			{ timedOut: true },
			{ result: { ok: false } },
			{ status: "cancelled" },
		])
			expect(reportedOutcome(output)).toBe("failed");
		expect(hostToolObservation({ ...input, running: true })?.execution).toBe(
			"running",
		);
	});
	it("treats malformed optional metadata as unavailable, not a tool failure", () => {
		expect(
			hostToolObservation({ ...input, toolCallId: "x".repeat(500) }),
		).toBeUndefined();
		expect(
			hostToolObservation({ ...input, durationMs: NaN })?.durationMs,
		).toBeUndefined();
		expect(reportedOutcome("x".repeat(70000))).toBe("unverified");
		expect(validationScope({ label: "x".repeat(9000) })).toBeUndefined();
	});
	it("redacts common credentials and private locations", () => {
		const output = redactReportText(
			"password=secretvalue Bearer abcdefgh https://user:pass@example.com/a?token=secret#private C:\\Users\\someone\\private.txt /home/user/private.txt ghp_1234567890abcdef",
		);
		for (const secret of [
			"secretvalue",
			"abcdefgh",
			"user:pass",
			"token=secret",
			"someone",
			"/home/user",
			"ghp_",
		])
			expect(output).not.toContain(secret);
		expect(output).toContain("https://example.com/a");
	});
});
