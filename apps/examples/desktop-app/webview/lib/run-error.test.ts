import { describe, expect, it } from "vitest";
import {
	formatRunError,
	isCapabilityOwnerDisconnect,
	isRecoverableForkTransportError,
	isTransientHubDisconnect,
	retryRecoverableFork,
} from "./run-error";

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


describe("fork transport recovery", () => {
	it.each([
		"Hub connection closed (code=1006, reason=Connection ended)",
		"Capability owner client core-example disconnected before request was resolved.",
		"Desktop backend transport closed",
	])("recognizes a recoverable fork failure: %s", (detail) => {
		expect(isRecoverableForkTransportError(new Error(detail))).toBe(true);
	});

	it("recognizes the primary capability-owner failure", () => {
		expect(
			isCapabilityOwnerDisconnect(
				"The run failed: Capability owner client core-example disconnected before request was resolved.",
			),
		).toBe(true);
	});

	it("uses a reconciled result before replaying a lost fork response", async () => {
		let attempts = 0;
		const operation = async () => {
			attempts += 1;
			throw new Error(
				"Hub connection closed (code=1006, reason=Connection ended)",
			);
		};
		const result = await retryRecoverableFork(operation, 0, async () => ({
			sessionId: "recovered-fork",
		}));
		expect(result).toEqual({ sessionId: "recovered-fork" });
		expect(attempts).toBe(1);
	});

	it("retries one idempotent fork after a recoverable disconnect", async () => {
		let attempts = 0;
		const result = await retryRecoverableFork(async () => {
			attempts += 1;
			if (attempts === 1) {
				throw new Error(
					"Hub connection closed (code=1006, reason=Connection ended)",
				);
			}
			return "recovered";
		}, 0);
		expect(result).toBe("recovered");
		expect(attempts).toBe(2);
	});
});
