import { expect, it } from "vitest";
import { InspectorConsoleCollector } from "./inspector-console";
import { byteDigest } from "./contracts";
import { InspectorRequestSchema } from "./inspector";
const hash = byteDigest(Buffer.from("owned"));
const scripts = [{ scriptId: "1", sha256: hash, staticMatch: true }];
const event = (args: unknown[] = []) => ({
	type: "log",
	timestamp: 101,
	stackTrace: {
		callFrames: [{ scriptId: "1", lineNumber: 2, columnNumber: 4 }],
	},
	args,
});
it("defaults console capture off and rejects truthy non-booleans", () => {
	const request = {
		operation: "js_inspector_observe",
		target: "owned.js",
		pid: 1,
		processToken: "owned",
		endpoint: "owned",
	};
	expect(InspectorRequestSchema.parse(request).captureConsole).toBe(false);
	expect(() =>
		InspectorRequestSchema.parse({ ...request, captureConsole: "true" }),
	).toThrow();
});
it("discards pre-enable/replay, post-window and invalid-coordinate reports", () => {
	const c = new InspectorConsoleCollector();
	c.accept(event(), 102);
	c.start(100);
	c.accept({ ...event(), timestamp: 99 }, 102);
	c.accept({ ...event(), timestamp: 103 }, 102);
	c.accept(
		{
			...event(),
			stackTrace: {
				callFrames: [{ scriptId: "1", lineNumber: -1, columnNumber: 0 }],
			},
		},
		102,
	);
	c.accept(event(), 102);
	c.stop();
	c.accept(event(), 102);
	const r = c.reconcile(scripts, hash);
	expect(r.reports).toHaveLength(1);
	expect(r.discarded).toBe(3);
	expect(r.verifiedBehavior).toBe(false);
});
it("keeps primitives bounded, exact string digests, opaque objects and no remote handles", () => {
	const c = new InspectorConsoleCollector();
	c.start(100);
	const text = "s".repeat(200);
	c.accept(
		event([
			{ type: "string", value: text },
			{
				type: "object",
				objectId: "SECRET",
				description: "SECRET",
				preview: { properties: [{ name: "SECRET" }] },
			},
			{ type: "number", unserializableValue: "-0" },
			{ type: "bigint", unserializableValue: "9007199254740993n" },
			{ type: "object", subtype: "null", value: null },
			{ type: "string", value: "x".repeat(16385) },
			{ type: "boolean", value: true },
			{ type: "undefined" },
			{ type: "string", value: "omitted" },
		]),
		102,
	);
	const r = c.reconcile(scripts, hash);
	expect(r.reports[0].arguments[0]).toMatchObject({
		value: text.slice(0, 160),
		sha256: byteDigest(Buffer.from(text)),
		truncated: true,
	});
	expect(r.reports[0].arguments).toHaveLength(8);
	expect(r.reports[0].argumentsTruncated).toBe(true);
	expect(r.reports[0].arguments[1]).toEqual({ type: "opaque", opaque: true });
	expect(JSON.stringify(r)).not.toContain("SECRET");
	expect(r.reports[0].arguments[3].value).toBe("9007199254740993n");
});
it("rejects mismatched, unverified and ambiguous script identities", () => {
	for (const ss of [
		[],
		[{ scriptId: "1", sha256: "f".repeat(64), staticMatch: true }],
		[{ scriptId: "1", sha256: hash, staticMatch: false }],
		[...scripts, ...scripts],
	]) {
		const c = new InspectorConsoleCollector();
		c.start(100);
		c.accept(event(), 102);
		expect(c.reconcile(ss, hash).reports).toEqual([]);
	}
});
it("bounds total reports and marks saturation without implying absence", () => {
	const c = new InspectorConsoleCollector();
	c.start(100);
	for (let i = 0; i < 30; i++) c.accept(event(), 102);
	const r = c.reconcile(scripts, hash);
	expect(r.reports).toHaveLength(24);
	expect(r.saturated).toBe(true);
	expect(r.note).toContain("not absence");
});
