import { randomUUID } from "node:crypto";
import { expect, it } from "vitest";
import { ANALYSIS_PROFILE, digest } from "./contracts";
import { correlateSavedEvidence } from "./correlation";
const hash = "a".repeat(64),
	scope = { sessionId: "owned", workspace: "/owned" };
function fixture() {
	const result = {
		profile: ANALYSIS_PROFILE,
		parserVersion: "owned-fixture",
		status: "completed",
		artifacts: [{ path: "owned.js", sha256: hash, bytes: 12, role: "source" }],
		facts: [
			{
				id: "ev_" + "b".repeat(64),
				kind: "function",
				value: "untrusted function label",
				confidence: "observed",
				authority: "shipped-artifact",
				location: { path: "owned.js", sha256: hash, line: 2, column: 1 },
				limitations: [],
			},
		],
		edges: [],
		limitations: [],
		counters: { entries: 1, bytes: 12, nodes: 1 },
	};
	const receipt = {
		...scope,
		id: randomUUID(),
		status: "completed",
		result,
		resultHash: digest(result),
	};
	const observed = {
		status: "partial",
		provider: "v8-cpu-sampling-selected-script",
		sourceSha256: hash,
		nodes: [{ nodeId: 1, line: 1, column: 0 }],
		samples: [1, 1],
	};
	const raw = {
		...scope,
		id: "c".repeat(64),
		taskId: randomUUID(),
		domain: "debugger",
		operation: "capture_execution_trace",
		tool: "managed-node-inspector/1",
		targetSha256: hash,
		resultHash: digest(observed),
		requestHash: hash,
		at: new Date().toISOString(),
		result: observed,
	};
	return { receipt, snapshot: { ...raw, snapshotHash: digest(raw) } };
}
it("correlates exact saved bytes and sampled function-definition-line candidates without execution claims", () => {
	const f = fixture(),
		r = correlateSavedEvidence(scope, f.receipt, [f.snapshot]);
	expect(r).toMatchObject({
		status: "partial",
		effect: "saved-evidence-read",
		verifiedBehavior: false,
	});
	expect(r.identity[0].staticIdentity).toBe("exact-byte-match");
	expect(r.sampling[0].candidates).toMatchObject([
		{
			nodeId: 1,
			sampleCount: 2,
			classification: "same-source-function-definition-line-candidate",
		},
	]);
	const { evidenceHash, ...body } = r;
	expect(evidenceHash).toBe(digest(body));
	expect(JSON.stringify(r)).not.toContain("untrusted function label");
});
it("rejects cross-owner, corrupt, duplicate or static-only task inputs", () => {
	const f = fixture();
	expect(() =>
		correlateSavedEvidence({ ...scope, sessionId: "other" }, f.receipt, [
			f.snapshot,
		]),
	).toThrow("scope");
	expect(() =>
		correlateSavedEvidence(scope, { ...f.receipt, resultHash: hash }, [
			f.snapshot,
		]),
	).toThrow("integrity");
	expect(() =>
		correlateSavedEvidence(scope, f.receipt, [
			{ ...f.snapshot, resultHash: hash },
		]),
	).toThrow("integrity");
	expect(() =>
		correlateSavedEvidence(scope, f.receipt, [f.snapshot, f.snapshot]),
	).toThrow("uniqueness");
	expect(() =>
		correlateSavedEvidence(scope, f.receipt, [
			{ ...f.snapshot, domain: "static" },
		]),
	).toThrow();
});
it("never maps a contradictory source hash or unknown provider and treats empty samples as inconclusive", () => {
	for (const change of [
		{ sourceSha256: "d".repeat(64) },
		{ provider: "forged" },
		{ samples: [] },
	]) {
		const f = fixture(),
			result = { ...f.snapshot.result, ...change },
			raw = { ...f.snapshot, result, resultHash: digest(result) };
		const { snapshotHash: _, ...body } = raw;
		const r = correlateSavedEvidence(scope, f.receipt, [
			{ ...body, snapshotHash: digest(body) },
		]);
		expect(r.sampling[0].candidates).toEqual([]);
		expect(r.verifiedBehavior).toBe(false);
	}
});
it("bounds selected inputs and excludes unsampled or invalid node positions", () => {
	const f = fixture();
	expect(() => correlateSavedEvidence(scope, f.receipt, [])).toThrow(
		"one to ten",
	);
	expect(() =>
		correlateSavedEvidence(scope, f.receipt, Array(11).fill(f.snapshot)),
	).toThrow("one to ten");
	const result = {
			...f.snapshot.result,
			nodes: [
				{ nodeId: 1, line: -1 },
				{ nodeId: 2, line: 1 },
			],
			samples: [1],
		},
		raw = { ...f.snapshot, result, resultHash: digest(result) };
	const { snapshotHash: _, ...body } = raw;
	expect(
		correlateSavedEvidence(scope, f.receipt, [
			{ ...body, snapshotHash: digest(body) },
		]).sampling[0].candidates,
	).toEqual([]);
});
it("retains only hash-matched native RVA observations from mixed static/runtime snapshots", () => {
	const f = fixture();
	const wrap = (
		result: unknown,
		domain: string,
		tool: string,
		operation: string,
	) => {
		const raw = {
			...f.snapshot,
			id: randomUUID().replaceAll("-", "").padEnd(64, "0"),
			taskId: randomUUID(),
			domain,
			tool,
			operation,
			result,
			resultHash: digest(result),
		};
		const { snapshotHash: _, ...body } = raw;
		return { ...body, snapshotHash: digest(body) };
	};
	const native = wrap(
		{
			engine: "owned-native",
			engineVersion: "1",
			input: { sha256: hash },
			evidence: {
				selectedFunctions: [
					{
						addressHex: "0x1010",
						architecture: "x86_64",
						image: {
							preferredBaseHex: "0x1000",
							addressSpace: "elf-link-time-virtual",
						},
						pseudocode: "DO NOT EXPORT RAW",
						disassembly: {
							engine: "owned",
							byteFingerprint: hash,
							requestedBytes: 8,
						},
					},
				],
			},
		},
		"static",
		"reverse-engineering",
		"decompile_function_bundle",
	);
	const observed = {
		artifactSha256: hash,
		rva: "0x10",
		architecture: "x86_64",
		scope: "host-read-process-memory-exact-birth-and-module-32-byte-range",
		processToken: "owned-birth",
		runtimeImageBase: "0x2000",
	};
	const runtime = wrap(
		{ moduleObservation: observed },
		"debugger",
		"windows-native-module",
		"native_module_observe",
	);
	const report = correlateSavedEvidence(scope, f.receipt, [native, runtime]);
	expect(report.native).toHaveLength(1);
	expect(report.native[0]).toMatchObject({
		runtimeImageBase: "0x2000",
		runtimeObservations: [
			expect.objectContaining({ processToken: "owned-birth" }),
		],
	});
	expect(JSON.stringify(report)).not.toContain("DO NOT EXPORT RAW");
	const mismatch = wrap(
		{ moduleObservation: { ...observed, architecture: "arm64" } },
		"debugger",
		"windows-native-module",
		"native_module_observe",
	);
	expect(
		correlateSavedEvidence(scope, f.receipt, [native, mismatch]).native[0]
			.runtimeObservations,
	).toEqual([]);
});
