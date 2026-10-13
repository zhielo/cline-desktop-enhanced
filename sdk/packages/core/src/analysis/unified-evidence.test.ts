import { mkdtemp, rm, realpath } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { expect, it } from "vitest";
import {
	UnifiedEvidenceStore,
	nativeDossiers,
	dossierDisagreements,
	unifiedEvidenceView,
} from "./unified-evidence";
import { digest } from "./contracts";
const hash = "a".repeat(64);
it("retains approved completed task provenance, exact hash matches and explicit unknowns", async () => {
	const root = await realpath(await mkdtemp(join(tmpdir(), "cline-unified-"))),
		store = new UnifiedEvidenceStore(join(root, "snapshots.sqlite"));
	try {
		const result = {
			result: {
				engine: "owned-engine",
				engineVersion: "1",
				input: { sha256: hash },
				evidence: {
					selectedFunctions: [
						{
							name: "owned",
							addressHex: "0x401000",
							disassembly: { instructions: ["ret"] },
						},
					],
				},
			},
		};
		const plan = {
			id: randomUUID(),
			workspaceRoot: root,
			kind: "static",
			operation: "advanced_analysis",
			status: "completed",
			requestHash: hash,
			targetIdentity: { sha256: hash },
			evidence: {
				resultHash: digest(result),
				requestHash: hash,
				tool: "reverse-engineering",
			},
			completedAt: new Date().toISOString(),
		};
		expect(() => store.record("s", root, plan, result)).toThrow(
			"owning session",
		);
		store.bind("s", root, { ...plan, status: "awaiting-approval" });
		expect(() =>
			store.bind("other", root, { ...plan, status: "awaiting-approval" }),
		).toThrow("immutable");
		expect(() => store.record("other", root, plan, result)).toThrow(
			"owning session",
		);
		const first = store.record("s", root, plan, result);
		expect(store.record("s", root, plan, result)).toEqual(first);
		expect(store.list("other", root)).toEqual([]);
		const snapshots = store.list("s", root),
			dossiers = nativeDossiers(snapshots);
		expect(dossiers).toHaveLength(1);
		expect(dossiers[0].pseudocode).toBe("unknown");
		expect(dossiers[0].imageBase).toBe("unknown");
		const view = unifiedEvidenceView(undefined, snapshots);
		expect(view[0].staticIdentity).toBe("not-in-static-inventory");
		expect(view[0].verifiedBehavior).toBe(false);
		expect(() =>
			store.record("s", root, { ...plan, status: "running" }, result),
		).toThrow();
		expect(() => store.record("s", root, plan, { changed: true })).toThrow(
			"binding",
		);
		expect(() =>
			store.record(
				"s",
				root,
				{ ...plan, workspaceRoot: root + "/other" },
				result,
			),
		).toThrow("binding");
	} finally {
		store.close();
		await rm(root, { recursive: true, force: true });
	}
});
it("reports differing engine outputs, not inferred truth or equivalence", () => {
	const identity = {
			sha256: hash,
			address: "0x1",
			engine: "one",
			architecture: "x86_64",
			addressSpace: "elf-link-time-virtual",
			preferredBase: "0x0",
			byteFingerprint: hash,
			requestedBytes: 1,
		},
		a = { identity, snapshotId: "a", disassembly: "ret" },
		b = {
			...a,
			identity: { ...identity, engine: "two" },
			snapshotId: "b",
			disassembly: "nop",
		};
	expect(dossierDisagreements([a, b])[0].disagreement).toBe(
		"different-engine-output",
	);
	expect(dossierDisagreements([a, b])[0].interpretation).toContain("not proof");
});

it("refuses to compare native outputs with different ranges or missing scope", () => {
	const identity = {
		sha256: hash,
		address: "0x1",
		architecture: "x86_64",
		addressSpace: "elf-link-time-virtual",
		preferredBase: "0x0",
		byteFingerprint: hash,
		requestedBytes: 1,
	};
	expect(
		dossierDisagreements([
			{ identity, disassembly: "ret" },
			{ identity: { ...identity, requestedBytes: 2 }, disassembly: "nop" },
		])[0].disagreement,
	).toBe("not-comparable-range-or-architecture");
	expect(
		dossierDisagreements([
			{ identity: { sha256: hash, address: "0x1" } },
			{ identity: { sha256: hash, address: "0x1" } },
		])[0].disagreement,
	).toBe("not-comparable-range-or-architecture");
});

it("retains link-time RVA and derives only selected same-artifact static callers", () => {
	const fn = (addressHex: string, callees: unknown[]) => ({
		addressHex,
		name: "owned",
		architecture: "x86_64",
		image: {
			preferredBaseHex: "0x1000000000000000",
			addressSpace: "elf-link-time-virtual",
		},
		callees,
		disassembly: {
			engine: "capstone",
			engineVersion: "5.0.9",
			byteFingerprint: hash,
			requestedBytes: 8,
			instructions: [],
		},
	});
	const snapshot = {
		targetSha256: hash,
		id: "owned",
		snapshotHash: hash,
		at: "owned",
		result: {
			engine: "android-static",
			engineVersion: "v3",
			input: { sha256: hash },
			evidence: {
				selectedFunctions: [
					fn("0x1000000000000010", [
						{
							targetAddressHex: "0x1000000000000020",
							fromAddressHex: "0x1000000000000010",
						},
					]),
					fn("0x1000000000000020", []),
				],
			},
		},
	};
	const rows = nativeDossiers([
		snapshot as Parameters<typeof nativeDossiers>[0][number],
	]);
	expect(rows[0].identity).toMatchObject({
		normalizedRva: "0x10",
		disassembler: "capstone",
		preferredBase: "0x1000000000000000",
	});
	expect(rows[0].runtimeImageBase).toBe("unknown");
	expect(rows[1].callers).toHaveLength(1);
	const changed = { ...snapshot, targetSha256: "b".repeat(64) };
	expect(
		nativeDossiers([changed as Parameters<typeof nativeDossiers>[0][number]]),
	).toEqual([]);
	const many = {
		...snapshot,
		result: {
			...snapshot.result,
			evidence: {
				selectedFunctions: Array.from({ length: 50 }, () =>
					fn("0x1000000000000010", []),
				),
			},
		},
	};
	expect(
		nativeDossiers(
			Array.from(
				{ length: 10 },
				() => many as Parameters<typeof nativeDossiers>[0][number],
			),
		),
	).toHaveLength(250);
});
