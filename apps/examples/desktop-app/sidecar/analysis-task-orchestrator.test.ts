import {
	mkdtempSync,
	readFileSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AnalysisTaskOrchestrator } from "./analysis-task-orchestrator";

const roots: string[] = [];

afterEach(() => {
	delete process.env.CLINE_ANALYSIS_SANDBOX_WORKER;
	delete process.env.CLINE_ANALYSIS_SANDBOX_PUBLIC_KEY;
	for (const root of roots.splice(0)) {
		rmSync(root, { recursive: true, force: true });
	}
});

function workspace() {
	const root = mkdtempSync(join(tmpdir(), "cline-analysis-plan-"));
	roots.push(root);
	return root;
}

describe("AnalysisTaskOrchestrator", () => {
	it("confines canonical targets and blocks symlink escapes", async () => {
		const orchestrator = new AnalysisTaskOrchestrator();
		const root = workspace();
		const outside = workspace();
		writeFileSync(join(outside, "sample.exe"), "sample");
		symlinkSync(outside, join(root, "linked"), "dir");
		await expect(
			orchestrator.prepare({
				workspaceRoot: root,
				kind: "static",
				request: {
					engine: "auto",
					operation: "inspect",
					target: "linked/sample.exe",
				},
			}),
		).rejects.toThrow("outside the workspace");
	});

	it("binds every argument to one expiring approval token", async () => {
		let now = 1_000;
		const orchestrator = new AnalysisTaskOrchestrator({
			now: () => now,
			approvalTtlMs: 1_000,
		});
		const root = workspace();
		const target = join(root, "sample.exe");
		writeFileSync(target, "sample");
		const request = {
			debugger: "auto",
			operation: "continue",
			target,
			pid: 41,
			address: "0x401000",
			confirm_execution_control: true,
		};
		const plan = await orchestrator.prepare({
			workspaceRoot: root,
			kind: "debugger",
			request,
		});
		expect(() =>
			orchestrator.approve(plan.id, ["authorized-target"], plan.requestHash),
		).toThrow("execution-control");
		const approved = orchestrator.approve(
			plan.id,
			plan.requirements,
			plan.requestHash,
		);
		await expect(
			orchestrator.consume({
				planId: plan.id,
				executionToken: approved.executionToken,
				workspaceRoot: root,
				kind: "debugger",
				request: { ...request, pid: 42 },
			}),
		).rejects.toThrow("exact request envelope");
		expect(
			(
				await orchestrator.consume({
					planId: plan.id,
					executionToken: approved.executionToken,
					workspaceRoot: root,
					kind: "debugger",
					request,
				})
			).status,
		).toBe("running");

		const expiring = await orchestrator.prepare({
			workspaceRoot: root,
			kind: "static",
			request: { operation: "inspect", engine: "auto", target },
		});
		now = 2_001;
		expect(() =>
			orchestrator.approve(
				expiring.id,
				expiring.requirements,
				expiring.requestHash,
			),
		).toThrow("unexpired");
	});

	it("invalidates approval if the target changes after review", async () => {
		const orchestrator = new AnalysisTaskOrchestrator();
		const root = workspace();
		const target = join(root, "sample.exe");
		writeFileSync(target, "before");
		const request = { operation: "inspect", engine: "auto", target };
		const plan = await orchestrator.prepare({
			workspaceRoot: root,
			kind: "static",
			request,
		});
		const approved = orchestrator.approve(
			plan.id,
			plan.requirements,
			plan.requestHash,
		);
		writeFileSync(target, "after");
		await expect(
			orchestrator.consume({
				planId: plan.id,
				executionToken: approved.executionToken,
				workspaceRoot: root,
				kind: "static",
				request,
			}),
		).rejects.toThrow("target changed");
	});

	it("persists bounded metadata and interrupts running work after restart", async () => {
		const root = workspace();
		const ledger = join(root, "state", "analysis.json");
		const request = { operation: "inspect", engine: "auto" };
		const first = new AnalysisTaskOrchestrator({ ledgerFilePath: ledger });
		const plan = await first.prepare({
			workspaceRoot: root,
			kind: "static",
			request,
		});
		const approved = first.approve(
			plan.id,
			plan.requirements,
			plan.requestHash,
		);
		await first.consume({
			planId: plan.id,
			executionToken: approved.executionToken,
			workspaceRoot: root,
			kind: "static",
			request,
		});
		expect(readFileSync(ledger, "utf8")).not.toContain(approved.executionToken);
		const restored = new AnalysisTaskOrchestrator({ ledgerFilePath: ledger });
		expect(restored.list(root)[0]).toMatchObject({
			id: plan.id,
			status: "interrupted",
		});
	});

	it("propagates user cancellation through the executor abort signal", async () => {
		const root = workspace();
		const orchestrator = new AnalysisTaskOrchestrator();
		const request = { operation: "inspect", engine: "auto" };
		const plan = await orchestrator.prepare({
			workspaceRoot: root,
			kind: "static",
			request,
		});
		const approved = orchestrator.approve(
			plan.id,
			plan.requirements,
			plan.requestHash,
		);
		await orchestrator.consume({
			planId: plan.id,
			executionToken: approved.executionToken,
			workspaceRoot: root,
			kind: "static",
			request,
		});
		const signal = orchestrator.signal(plan.id);
		expect(signal.aborted).toBe(false);
		expect(orchestrator.cancel(plan.id).status).toBe("cancelled");
		expect(signal.aborted).toBe(true);
	});

	it("requires an HTTPS sandbox endpoint and pinned worker key", async () => {
		const root = workspace();
		const orchestrator = new AnalysisTaskOrchestrator();
		await expect(
			orchestrator.prepare({
				workspaceRoot: root,
				kind: "dynamic",
				request: { operation: "execute" },
			}),
		).rejects.toThrow("attested isolated analysis worker");
		process.env.CLINE_ANALYSIS_SANDBOX_WORKER = "http://localhost:1234";
		process.env.CLINE_ANALYSIS_SANDBOX_PUBLIC_KEY = "test-public-key";
		await expect(
			orchestrator.prepare({
				workspaceRoot: root,
				kind: "dynamic",
				request: { operation: "execute" },
			}),
		).rejects.toThrow("HTTPS endpoint");
	});
});

describe("known-key decryption review", () => {
	it("requires authorized decryption and sensitive-plaintext acknowledgments", async () => {
		const orchestrator = new AnalysisTaskOrchestrator();
		const root = workspace();
		writeFileSync(join(root, "owned.bin"), "ciphertext");
		const plan = await orchestrator.prepare({
			workspaceRoot: root,
			kind: "static",
			request: {
				operation: "advanced_analysis",
				advanced_action: "decrypt_blob",
				target: "owned.bin",
				advanced_options: {
					decrypt: { algorithm: "aes-256-gcm", nonce_hex: "0".repeat(24) },
				},
			},
		});
		expect(plan.risk).toBe("moderate");
		expect(plan.requirements).toEqual(
			expect.arrayContaining([
				"authorized-decryption",
				"sensitive-plaintext-processing",
			]),
		);
		expect(() => orchestrator.approve(plan.id, [], plan.requestHash)).toThrow(
			"Missing required approvals",
		);
		expect(
			orchestrator.approve(plan.id, plan.requirements, plan.requestHash)
				.executionToken,
		).toBeTruthy();
	});
});

describe("approval races and bounded ledger retention", () => {
	async function approvedFile(orchestrator: AnalysisTaskOrchestrator) {
		const root = workspace();
		writeFileSync(join(root, "owned.bin"), "owned fixture");
		const request = { operation: "inspect", target: "owned.bin" };
		const plan = await orchestrator.prepare({
			workspaceRoot: root,
			kind: "static",
			request,
		});
		const approval = orchestrator.approve(
			plan.id,
			plan.requirements,
			plan.requestHash,
		);
		return {
			root,
			plan,
			consume: {
				planId: plan.id,
				executionToken: approval.executionToken,
				workspaceRoot: root,
				kind: "static" as const,
				request,
			},
		};
	}
	it("consumes a file-bound token exactly once under concurrent requests", async () => {
		const o = new AnalysisTaskOrchestrator();
		const f = await approvedFile(o);
		try {
			const results = await Promise.allSettled([
				o.consume(f.consume),
				o.consume(f.consume),
			]);
			expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
			expect(results.filter((r) => r.status === "rejected")).toHaveLength(1);
		} finally {
			o.cancel(f.plan.id);
		}
	});
	it("does not resurrect a cancelled approval while target hashing is in flight", async () => {
		const o = new AnalysisTaskOrchestrator();
		const f = await approvedFile(o);
		const consuming = o.consume(f.consume);
		o.cancel(f.plan.id);
		try {
			await expect(consuming).rejects.toThrow("exact request envelope");
			expect(o.list(f.root)[0].status).toBe("cancelled");
		} finally {
			if (o.list(f.root)[0].status === "running") o.cancel(f.plan.id);
		}
	});
	it("rechecks expiry after asynchronous target hashing", async () => {
		let now = 1000;
		const o = new AnalysisTaskOrchestrator({
			now: () => now,
			approvalTtlMs: 1000,
		});
		const f = await approvedFile(o);
		const consuming = o.consume(f.consume);
		now = 2001;
		try {
			await expect(consuming).rejects.toThrow("exact request envelope");
			expect(o.list(f.root)[0].status).toBe("expired");
		} finally {
			if (o.list(f.root)[0].status === "running") o.cancel(f.plan.id);
		}
	});
	it("rejects new plans rather than evicting pending approvals", async () => {
		const o = new AnalysisTaskOrchestrator({ maxPlans: 1 });
		const root = workspace();
		const input = {
			workspaceRoot: root,
			kind: "static" as const,
			request: { operation: "inspect" },
		};
		const plan = await o.prepare(input);
		await expect(o.prepare(input)).rejects.toThrow("capacity");
		expect(o.list(root).map((p) => p.id)).toEqual([plan.id]);
	});
	it("retains running task control and reclaims only terminal ledger entries", async () => {
		const o = new AnalysisTaskOrchestrator({ maxPlans: 1 });
		const f = await approvedFile(o);
		await o.consume(f.consume);
		try {
			await expect(
				o.prepare({
					workspaceRoot: f.root,
					kind: "static",
					request: { operation: "inspect" },
				}),
			).rejects.toThrow("capacity");
			expect(o.signal(f.plan.id).aborted).toBe(false);
			o.complete(f.plan.id, { owned: true }, "fixture");
			const next = await o.prepare({
				workspaceRoot: f.root,
				kind: "static",
				request: { operation: "inspect" },
			});
			expect(o.list(f.root).map((p) => p.id)).toEqual([next.id]);
		} finally {
			if (
				o.list(f.root).some((p) => p.id === f.plan.id && p.status === "running")
			)
				o.cancel(f.plan.id);
		}
	});
});
