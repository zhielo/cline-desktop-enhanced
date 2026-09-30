import { describe, expect, it } from "vitest";
import { formatRunError, isTransientHubDisconnect } from "./run-error";

describe("formatRunError", () => {
	it.each([
		"API key expired",
		"The run failed because the API key expired",
		"The run failed: Unauthorized",
	])("adds guidance exactly once for %s", (detail) => {
		const formatted = formatRunError(detail);
		expect(formatted).toContain("Settings → API Providers");
		expect(formatted.match(/The run failed/g)).toHaveLength(1);
		expect(formatRunError(formatted)).toBe(formatted);
	});
	it("does not suggest changing credentials for a token limit", () => {
		expect(
			formatRunError("The run failed: maximum context tokens exceeded"),
		).not.toContain("Settings");
	});
});

describe("isTransientHubDisconnect", () => {
	it.each([
		"Hub connection closed (code=1006, reason=Connection ended)",
		"The run failed: Hub connection closed (code=1006, reason=Connection ended)",
	])("recognizes the recoverable abnormal close: %s", (detail) => {
		expect(isTransientHubDisconnect(detail)).toBe(true);
	});

	it.each([
		"Hub connection closed (code=1008, reason=Unauthorized)",
		"Cloud run failed",
		"Connection ended",
	])("does not hide a different failure: %s", (detail) => {
		expect(isTransientHubDisconnect(detail)).toBe(false);
	});
});

it.each([
	"session expired",
	"not logged in",
	"Please /login",
	"Please authenticate",
])("preserves CLI guidance for %s", (detail) => {
	const text = formatRunError(detail, "claude-code");
	expect(text).toContain("`claude` CLI");
	expect(text).not.toContain("Settings");
	expect(formatRunError(text, "claude-code")).toBe(text);
});
