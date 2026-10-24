import { randomUUID } from "node:crypto";
import { expect, it } from "vitest";
import { digest } from "./contracts";
import { querySavedNativeValueFlow } from "./native-value-flow";
const hash = "a".repeat(64),
	scope = { sessionId: "owned", workspace: "/owned" };
const flow = (sources: unknown[], frontiers: string[] = []) => ({
	sources,
	frontiers,
	visited: 1,
	coverage:
		"bounded-selected-function-def-use-dependencies-not-value-equivalence",
});
function fixture() {
	const callee = {
		schemaVersion: 1,
		addressHex: "0x2000",
		name: "callee",
		signature: "int callee(int x)",
		pseudocode: "DO NOT EXPORT PSEUDOCODE",
		architecture: "x86:LE:64:default",
		image: {
			preferredBaseHex: "0x1000",
			addressSpace: "ghidra-program-virtual",
		},
		callees: [],
		relationsTruncated: false,
		coverage: "selected-function-decompiler-and-bounded-high-pcode-not-runtime",
		returnFlows: [
			{
				fromAddressHex: "0x2001",
				flow: flow([
					{ kind: "parameter", parameterIndex: 0 },
					{ kind: "constant", valueHex: "0x7", bytes: 4 },
				]),
			},
		],
	};
	const caller = {
		...callee,
		addressHex: "0x1000",
		name: "caller",
		callees: [
			{
				fromAddressHex: "0x1010",
				kind: "direct",
				targetAddressHex: "0x2000",
				resolution: "bounded-high-pcode-constant-candidate",
				argumentsTruncated: false,
				argumentFlows: [
					{ ...flow([{ kind: "parameter", parameterIndex: 0 }]), index: 0 },
				],
			},
		],
		returnFlows: [
			{
				fromAddressHex: "0x1011",
				flow: flow([{ kind: "call-return", fromAddressHex: "0x1010" }]),
			},
		],
	};
	const wrap = (selected: unknown[], extra: Record<string, unknown> = {}) => {
		const result = {
			engine: "ghidra",
			engineVersion: "12.1.4",
			input: { sha256: hash },
			evidence: { selectedFunctions: selected },
			...extra,
		};
		const raw = {
			...scope,
			id: "b".repeat(64),
			taskId: randomUUID(),
			domain: "static",
			operation: "decompile",
			tool: "reverse-engineering",
			targetSha256: hash,
			resultHash: digest(result),
			requestHash: hash,
			at: new Date().toISOString(),
			result,
		};
		return { ...raw, snapshotHash: digest(raw) };
	};
	const snapshots = [wrap([caller]), wrap([callee])];
	const query = {
		action: "trace",
		taskIds: snapshots.map((s) => s.taskId),
		rootTaskId: snapshots[0].taskId,
		rootAddress: "0x1000",
		maxDepth: 3,
	};
	return { caller, callee, wrap, snapshots, query };
}
it("binds callee parameters to the exact retained caller argument without claiming value equivalence", () => {
	const f = fixture(),
		r = querySavedNativeValueFlow(scope, f.query, f.snapshots);
	expect(r.steps).toContainEqual(
		expect.objectContaining({ kind: "constant-dependency", valueHex: "0x7" }),
	);
	expect(r.steps.filter((s) => s.kind === "parameter-dependency")).toHaveLength(
		2,
	);
	expect(r.steps).toContainEqual(
		expect.objectContaining({
			reason: "root-parameter-without-caller-binding",
		}),
	);
	expect(r.verifiedBehavior).toBe(false);
	expect(JSON.stringify(r)).not.toContain("DO NOT EXPORT PSEUDOCODE");
	const { evidenceHash, ...body } = r;
	expect(evidenceHash).toBe(digest(body));
});
it("retains missing callees, engine mismatches and repeated observations as explicit frontiers", () => {
	for (const extra of [
		{ engineVersion: "other" },
		{ input: { sha256: "c".repeat(64) } },
		{ engine: "ida" },
	]) {
		const f = fixture(),
			other = f.wrap([f.callee], extra);
		const snapshots = [f.snapshots[0], other];
		const r = querySavedNativeValueFlow(
			scope,
			{ ...f.query, taskIds: snapshots.map((s) => s.taskId) },
			snapshots,
		);
		expect(
			r.steps.some((s) => s.reason === "callee-not-retained-or-incompatible"),
		).toBe(true);
		expect(r.steps.some((s) => s.kind === "constant-dependency")).toBe(false);
	}
	const f = fixture(),
		snapshots = [...f.snapshots, f.wrap([f.callee])];
	const r = querySavedNativeValueFlow(
		scope,
		{ ...f.query, taskIds: snapshots.map((s) => s.taskId) },
		snapshots,
	);
	expect(
		r.steps.some((s) => s.reason === "multiple-retained-callee-observations"),
	).toBe(true);
});
it("rejects cross-scope, tampering, duplicate inputs and invented roots", () => {
	const f = fixture();
	for (const values of [
		[{ ...f.snapshots[0], workspace: "/other" }, f.snapshots[1]],
		[{ ...f.snapshots[0], resultHash: "0".repeat(64) }, f.snapshots[1]],
	])
		expect(() => querySavedNativeValueFlow(scope, f.query, values)).toThrow(
			"integrity",
		);
	expect(() =>
		querySavedNativeValueFlow(
			scope,
			{ ...f.query, taskIds: [f.query.taskIds[0], f.query.taskIds[0]] },
			f.snapshots,
		),
	).toThrow("distinct");
	expect(() =>
		querySavedNativeValueFlow(
			scope,
			{ ...f.query, rootAddress: "0x9999" },
			f.snapshots,
		),
	).toThrow("exactly one");
	expect(() =>
		querySavedNativeValueFlow(scope, { ...f.query, maxDepth: 5 }, f.snapshots),
	).toThrow();
});
it("lists source-qualified functions and keeps old return records unknown", () => {
	const f = fixture();
	const legacy = { ...f.callee };
	delete (legacy as Partial<typeof legacy>).returnFlows;
	const s = f.wrap([legacy]);
	const r = querySavedNativeValueFlow(
		scope,
		{ action: "list", taskIds: [s.taskId] },
		[s],
	);
	expect(r.functions[0].returnFlowsAvailable).toBe(false);
	expect(r.steps).toEqual([]);
});
it("retains memory and recursion frontiers within a finite graph", () => {
	const f = fixture();
	const recursive = {
		...f.caller,
		callees: [{ ...f.caller.callees[0], targetAddressHex: "0x1000" }],
		returnFlows: [
			{
				...f.caller.returnFlows[0],
				flow: flow(
					[{ kind: "call-return", fromAddressHex: "0x1010" }],
					["memory-load"],
				),
			},
		],
	};
	const s = f.wrap([recursive]);
	const r = querySavedNativeValueFlow(
		scope,
		{ ...f.query, taskIds: [s.taskId], rootTaskId: s.taskId },
		[s],
	);
	expect(r.steps).toContainEqual(
		expect.objectContaining({ reason: "dependency-cycle" }),
	);
	expect(r.steps).toContainEqual(
		expect.objectContaining({ reason: "memory-load" }),
	);
	expect(r.steps.length).toBeLessThan(10);
});
