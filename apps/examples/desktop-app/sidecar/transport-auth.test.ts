import { describe, expect, it } from "vitest";
import { hasSidecarAuthentication } from "./transport-auth";

const token = "test-sidecar-process-token";
const request = (query = "", authorization?: string) =>
	new Request(`http://127.0.0.1:3126/transport${query}`, {
		headers: authorization === undefined ? {} : { authorization },
	});
describe("sidecar authentication", () => {
	it("requires a nonempty exact token", () => {
		for (const req of [
			request(),
			request("?approval_token="),
			request("?approval_token=wrong"),
			request("", "Bearer wrong"),
			request("", "Basic test"),
		])
			expect(hasSidecarAuthentication(req, token, true)).toBe(false);
		expect(
			hasSidecarAuthentication(request("?approval_token=" + token), "", true),
		).toBe(false);
	});
	it("accepts query credentials only for WebSockets", () => {
		expect(
			hasSidecarAuthentication(
				request("?approval_token=" + token),
				token,
				true,
			),
		).toBe(true);
		expect(
			hasSidecarAuthentication(request("?approval_token=" + token), token),
		).toBe(false);
	});
	it("accepts exact bearer credentials", () => {
		expect(
			hasSidecarAuthentication(request("", "Bearer " + token), token),
		).toBe(true);
		expect(
			hasSidecarAuthentication(request("", "bearer " + token), token, true),
		).toBe(true);
	});
	it("rejects duplicates, conflicting sources and oversized credentials", () => {
		for (const req of [
			request(`?approval_token=${token}&approval_token=${token}`),
			request(`?approval_token=${token}`, "Bearer " + token),
			request("", "Bearer " + "a".repeat(513)),
			request("", "Bearer a b"),
		])
			expect(hasSidecarAuthentication(req, token, true)).toBe(false);
		expect(
			hasSidecarAuthentication(
				request("", "Bearer " + "a".repeat(513)),
				"a".repeat(513),
			),
		).toBe(false);
	});
});
