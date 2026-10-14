import { mkdtemp, rm, realpath, mkdir, symlink } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { execFileSync } from "node:child_process";
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
it("binds native-resolved workspace aliases without permitting another workspace or session", async () => {
	const root = await mkdtemp(join(tmpdir(), "cline-unified-alias-"));
	const owned = join(root, "owned-workspace");
	const other = join(root, "other-workspace");
	const alias = join(root, "owned-alias");
	await mkdir(owned);
	await mkdir(other);
	await symlink(
		owned,
		alias,
		process.platform === "win32" ? "junction" : "dir",
	);
	const store = new UnifiedEvidenceStore(join(root, "snapshots.sqlite"));
	const result = { owned: true };
	const plan = {
		id: randomUUID(),
		workspaceRoot: realpathSync.native(alias),
		kind: "static",
		operation: "owned",
		status: "awaiting-approval",
		requestHash: hash,
	};
	try {
		store.bind("s", alias, plan);
		expect(() => store.bind("other", alias, plan)).toThrow("immutable");
		expect(() => store.bind("s", other, plan)).toThrow("workspace mismatch");
		const completed = {
			...plan,
			status: "completed",
			completedAt: new Date().toISOString(),
			evidence: {
				resultHash: digest(result),
				requestHash: hash,
				tool: "owned",
			},
		};
		const snapshot = store.record("s", alias, completed, result);
		expect(store.list("s", alias)).toEqual([snapshot]);
		expect(() => store.record("other", alias, completed, result)).toThrow(
			"owning session",
		);
		expect(() => store.record("s", other, completed, result)).toThrow(
			"binding mismatch",
		);
	} finally {
		store.close();
		await rm(root, { recursive: true, force: true });
	}
});
it.skipIf(process.platform !== "win32")(
	"binds real Windows 8.3 workspace paths to native task plans",
	async () => {
		const root = await mkdtemp(join(tmpdir(), "cline-unified-short-path-"));
		const store = new UnifiedEvidenceStore(join(root, "snapshots.sqlite"));
		try {
			const short = execFileSync(
				"cmd.exe",
				["/d", "/c", `for %I in ("${root}") do @echo %~sI`],
				{ encoding: "utf8", timeout: 10000 },
			).trim();
			const nativeRoot = realpathSync.native(root);
			expect(short.toLowerCase()).not.toBe(nativeRoot.toLowerCase());
			expect(realpathSync.native(short)).toBe(nativeRoot);
			const result = { owned: true };
			const plan = {
				id: randomUUID(),
				workspaceRoot: nativeRoot,
				kind: "execution",
				operation: "js_isolated_execute",
				status: "awaiting-approval",
				requestHash: hash,
			};
			store.bind("s", short, plan);
			const snapshot = store.record(
				"s",
				short,
				{
					...plan,
					status: "completed",
					completedAt: new Date().toISOString(),
					evidence: {
						resultHash: digest(result),
						requestHash: hash,
						tool: "owned",
					},
				},
				result,
			);
			expect(store.list("s", short)).toEqual([snapshot]);
			expect(() => store.bind("other", short, plan)).toThrow("immutable");
		} finally {
			store.close();
			await rm(root, { recursive: true, force: true });
		}
	},
);
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

it("ties runtime RVA observations to host observer, exact artifact and process-specific scope", () => {
	const snapshot = (
		result: unknown,
		tool = "native-static",
		operation = "decompile",
		domain = "static",
	) => ({
		id: tool,
		sessionId: "s",
		workspace: "owned",
		taskId: tool,
		domain,
		operation,
		tool,
		targetSha256: hash,
		resultHash: digest(result),
		requestHash: hash,
		at: new Date().toISOString(),
		result,
		snapshotHash: hash,
	});
	const native = snapshot({
		engine: "ghidra",
		input: { sha256: hash },
		evidence: {
			selectedFunctions: [
				{
					name: "owned",
					addressHex: "0x401000",
					architecture: "x86:LE:64:default",
					image: {
						preferredBaseHex: "0x400000",
						addressSpace: "ghidra-program-virtual",
					},
					pseudocode: "return 42;",
				},
			],
		},
	});
	const result = {
		moduleObservation: {
			artifactSha256: hash,
			architecture: "x86_64",
			rva: "0x1000",
			processToken: "win32:638000000000000001",
			pid: 42,
			runtimeImageBase: "0x700000",
			runtimeAddress: "0x701000",
			scope: "host-read-process-memory-exact-birth-and-module-32-byte-range",
		},
	};
	const observed = snapshot(
		result,
		"windows-native-module",
		"native_module_observe",
		"debugger",
	);
	expect(nativeDossiers([native, observed])[0].runtimeImageBase).toBe(
		"0x700000",
	);
	expect(
		nativeDossiers([
			native,
			snapshot(
				result,
				"untrusted-provider",
				"native_module_observe",
				"debugger",
			),
		])[0].runtimeImageBase,
	).toBe("unknown");
	expect(
		nativeDossiers([native, { ...observed, targetSha256: "b".repeat(64) }])[0]
			.runtimeImageBase,
	).toBe("unknown");
	const different = snapshot(
		{ moduleObservation: { ...result.moduleObservation, rva: "0x2000" } },
		"windows-native-module",
		"native_module_observe",
		"debugger",
	);
	expect(nativeDossiers([native, different])[0].runtimeImageBase).toBe(
		"unknown",
	);
});
