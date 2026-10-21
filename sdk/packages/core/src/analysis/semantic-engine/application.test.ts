import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import {
	analyzeApplicationSources,
	applicationArtifacts,
	applicationSummary,
	parseJavaScriptApplicationGraph,
} from "./application";
import { ownedApplication, ownedSource } from "./application.fixture";
import { digestCanonicalValue, semanticSummary } from "./engine";
import { traceApplicationFeature } from "./upstream/src/domain/javascript/javascriptFeatureTrace";

it("projects imports, Electron boundaries and HTML relationships without executing source", async () => {
	const result = await analyzeApplicationSources(ownedApplication());
	const kinds = new Set(result.application.nodes.map((n) => n.kind));
	for (const kind of [
		"package",
		"javascript-module",
		"browser-window",
		"context-bridge-api",
		"ipc-channel",
	])
		expect(kinds.has(kind as never), kind).toBe(true);
	expect(result.application.edges.some((e) => e.relation === "imports")).toBe(
		true,
	);
	expect(
		result.semantic.nodes.some((n) => n.application_node_ids.length > 0),
	).toBe(true);
	expect(result.semantic.application_graph_id).toBe(
		result.application.graph_id,
	);
	expect(result.application.coverage.status).toBe("partial");
	expect(semanticSummary(result.semantic, true).profile).toBe(
		"cline-semantic/2",
	);
	const summary = applicationSummary(
		result.application,
		result.semantic,
		result.manifest,
	);
	expect(summary.rootManifestHash).toBe(
		createHash("sha256").update(JSON.stringify(summary.sources)).digest("hex"),
	);
	const trace = traceApplicationFeature({
		sourceEvidenceId: `ev_${"a".repeat(64)}`,
		graph: result.application,
		nativeEvidence: [],
		seed: { kind: "channel", value: "owned:add" },
		direction: "both",
	});
	expect(trace.summary.matched_seeds).toBeGreaterThan(0);
	expect(trace.summary.traced_edges).toBeGreaterThan(0);
	expect(trace.coverage.status).toBe("partial");
});
it("is Unicode-order deterministic and rejects stale graph identifiers", async () => {
	const sources = ownedApplication();
	const a = await analyzeApplicationSources(sources);
	const b = await analyzeApplicationSources([...sources].reverse());
	expect(digestCanonicalValue(a)).toBe(digestCanonicalValue(b));
	expect(() =>
		parseJavaScriptApplicationGraph({
			...a.application,
			graph_id: `jag_${"0".repeat(64)}`,
		}),
	).toThrow();
});
it("rejects changed bytes, count mismatch, duplicate normalized paths and traversal", () => {
	const good = ownedSource("safe.js", "const x=1");
	for (const bad of [
		{ ...good, sha256: "0".repeat(64) },
		{ ...good, bytes: 99 },
		{ ...good, path: "../escape.js" },
		{ ...good, path: "/escape.js" },
		{ ...good, path: "a\\b.js" },
	])
		expect(() => applicationArtifacts([bad])).toThrow();
	expect(() =>
		applicationArtifacts([
			ownedSource("e\u0301.js", "1"),
			ownedSource("é.js", "1"),
		]),
	).toThrow(/duplicate/);
});
it("retains invalid UTF-8 and malformed source as unavailable rather than executing or fabricating facts", async () => {
	const bytes = Buffer.from([0xff, 0xfe]);
	const bad = {
		path: "invalid.js",
		source: bytes.toString("utf8"),
		bytes: 2,
		sha256: createHash("sha256").update(bytes).digest("hex"),
		rawBytes: bytes,
	};
	const inputs = applicationArtifacts([bad]);
	expect(inputs.fileSet.invalid_utf8_files).toBe(1);
	expect(inputs.fileSet.files[0]?.text).toEqual({
		included: false,
		reason: "invalid-utf8",
	});
	const result = await analyzeApplicationSources([
		bad,
		ownedSource("broken.js", "function broken( {"),
	]);
	expect(result.semantic.coverage.status).not.toBe("complete");
	expect(result.semantic.unknowns.length).toBeGreaterThan(0);
});
it("honours cancellation and rejects graph/source manifest mismatches", async () => {
	const c = new AbortController();
	c.abort();
	await expect(
		analyzeApplicationSources(ownedApplication(), c.signal),
	).rejects.toThrow(/cancel/);
	const result = await analyzeApplicationSources(ownedApplication());
	expect(() =>
		applicationSummary(result.application, result.semantic, []),
	).toThrow(/binding/);
});
