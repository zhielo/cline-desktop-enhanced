import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it, expect } from "vitest";
import { InvestigationStore } from "./analysis-investigation-store";
import type { AnalysisTaskPlan } from "./analysis-task-orchestrator";
const roots: string[] = [];
const stores: InvestigationStore[] = [];
function fixture() {
	const root = mkdtempSync(join(tmpdir(), "investigation-"));
	roots.push(root);
	const store = new InvestigationStore(join(root, "state.sqlite"));
	stores.push(store);
	return { root, store };
}
afterEach(() => {
	for (const store of stores.splice(0)) store.close();
	for (const root of roots.splice(0))
		rmSync(root, { recursive: true, force: true });
});
function plan(root: string): AnalysisTaskPlan {
	return {
		id: "job",
		workspaceRoot: root,
		kind: "static",
		operation: "advanced_analysis",
		request: { advanced_action: "compare_expressions" },
		requestHash: "a".repeat(64),
		permission: "Inspect",
		status: "completed",
		requirements: [],
		budget: { timeoutMs: 1000, maxOutputBytes: 1000, network: "disabled" },
		risk: "low",
		createdAt: "now",
		expiresAt: "later",
		targetIdentity: {
			path: join(root, "owned.json"),
			kind: "file",
			sha256: "b".repeat(64),
		},
		evidence: {
			resultHash: "c".repeat(64),
			tool: "fixture",
			outputPaths: [],
			requestHash: "a".repeat(64),
		},
	};
}
describe("durable investigation metadata", () => {
	it("persists checkpoints, refuses stale edits and confines workspace access", () => {
		const { root, store } = fixture(),
			c = store.mutate(root, {
				action: "create",
				title: "Owned APK",
				confirmWrite: true,
			});
		const updated = store.mutate(root, {
			action: "checkpoint",
			id: c.id,
			revision: 0,
			summary: "Keep evidence IDs",
			questions: ["Which loader?"],
			state: "paused",
			confirmWrite: true,
		});
		expect(updated.revision).toBe(1);
		expect(() =>
			store.mutate(root, {
				action: "checkpoint",
				id: c.id,
				revision: 0,
				summary: "overwrite",
				questions: [],
				state: "active",
				confirmWrite: true,
			}),
		).toThrow("changed");
		const other = join(root, "other");
		mkdirSync(other);
		expect(() => store.get(other, c.id)).toThrow("workspace");
		store.close();
		expect(store.get(root, c.id).summary).toBe("Keep evidence IDs");
	});
	it("forks evidence without copying running jobs or replaying work", () => {
		const { root, store } = fixture(),
			c = store.mutate(root, {
				action: "create",
				title: "Case",
				confirmWrite: true,
			}),
			p = plan(root);
		store.bind(root, c.id, p);
		const completed = store.record(root, c.id, p, {
			engine: "z3",
			status: "completed",
			input: { sha256: "b".repeat(64) },
			evidence: { equivalence: "unsat" },
		});
		const fork = store.mutate(root, {
			action: "fork",
			id: c.id,
			revision: completed.revision,
			title: "Edited branch",
			confirmWrite: true,
		});
		expect(fork.parentId).toBe(c.id);
		expect(fork.jobs).toEqual([]);
		expect(fork.evidence).toHaveLength(1);
		expect(fork.transformations[0].verdict).toBe(
			"equivalent-under-expression-model-only",
		);
		expect(store.get(root, c.id).title).toBe("Case");
	});
	it("does not upgrade an imported or mismatched expression result into a proof", () => {
		const { root, store } = fixture(),
			c = store.mutate(root, {
				action: "create",
				title: "Case",
				confirmWrite: true,
			}),
			p = plan(root);
		store.bind(root, c.id, p);
		expect(() => store.record(root, c.id, { ...p, id: "unknown" }, {})).toThrow(
			"bound",
		);
		const saved = store.record(root, c.id, p, {
			engine: "z3",
			status: "completed",
			input: { sha256: "d".repeat(64) },
			evidence: { equivalence: "unsat", plaintext: "not retained" },
		});
		expect(saved.transformations[0].verdict).toBe("heuristic-or-inconclusive");
		expect(JSON.stringify(saved)).not.toContain("not retained");
		expect(saved.evidence[0].provenance).toBe("static-or-imported-report");
		expect(store.get(root, c.id).events.at(-1)?.hash).toMatch(/^[a-f0-9]{64}$/);
	});
	it("requires explicit write confirmation and rejects unknown execution fields", () => {
		const { root, store } = fixture();
		expect(() =>
			store.mutate(root, { action: "create", title: "Case" }),
		).toThrow();
		expect(() =>
			store.mutate(root, {
				action: "create",
				title: "Case",
				confirmWrite: true,
				execute: "target.apk",
			}),
		).toThrow();
	});
});

it("retains native summaries, explicit coverage counts and signed receipt references", () => {
	const { root, store } = fixture(),
		c = store.mutate(root, {
			action: "create",
			title: "Owned",
			confirmWrite: true,
		}),
		p = plan(root);
	store.bind(root, c.id, p);
	const saved = store.record(
		root,
		c.id,
		p,
		{
			engine: "android-frida",
			status: "partial",
			evidence: {
				registrations: Array.from({ length: 65 }, () => ({
					name: "work",
					classDescriptor: "LOwned;",
					descriptor: "()V",
					relativeAddress: "0x10",
					module: "owned.so",
					processId: 42,
					classLoaderIdentity: "unresolved",
				})),
				selectedFunctions: [{ id: "native", name: "work", addressHex: "0x10" }],
			},
			outputPaths: ["private/receipt.json"],
		},
		true,
	);
	expect(saved.evidence[0].metadataCoverage).toMatchObject({
		registrations: { available: 65, retained: 64 },
	});
	expect(saved.evidence[0].functions).toMatchObject([
		{ id: "native", name: "work", addressHex: "0x10" },
	]);
	expect(saved.evidence[0].engineExecution).toBe(
		"reported-by-signed-worker-not-device-validated",
	);
	expect(store.get(root, c.id).events).toHaveLength(3);
});
