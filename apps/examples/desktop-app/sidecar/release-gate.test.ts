import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { UnifiedEvidenceStore } from "@cline/core";
import { afterEach, expect, it, vi } from "vitest";
import {
	AnalysisTaskOrchestrator,
	type AnalysisTaskPlan,
} from "./analysis-task-orchestrator";
import { handleReleaseGate, type ReleaseGateHostPorts } from "./release-gate";
const resources: Array<{
	root: string;
	store: UnifiedEvidenceStore;
	tasks: AnalysisTaskOrchestrator;
}> = [];
afterEach(() => {
	for (const r of resources) {
		for (const p of r.tasks.list(r.root))
			if (["running", "approved", "awaiting-approval"].includes(p.status))
				r.tasks.cancel(p.id);
		r.store.close();
		rmSync(r.root, {
			recursive: true,
			force: true,
			maxRetries: 5,
			retryDelay: 100,
		});
	}
	resources.length = 0;
});
function fixture() {
	const root = realpathSync(mkdtempSync(join(tmpdir(), "release-gate-"))),
		tasks = new AnalysisTaskOrchestrator({
			ledgerFilePath: join(root, "tasks.json"),
		}),
		store = new UnifiedEvidenceStore(join(root, "evidence.sqlite"));
	resources.push({ root, tasks, store });
	let mode = "static",
		profile = true;
	const collect = vi.fn(async () => ({
		status: "passed",
		expectedHead: "a".repeat(40),
		limitations: ["Owned transport fixture only, not live CI proof"],
	}));
	const ports: ReleaseGateHostPorts = {
		tasks,
		session: () => ({ workspace: root, mode }),
		assertProfile: () => {
			if (!profile) throw Error("profile denied");
		},
		bind: (id, w, p) => store.bind(id, w, p),
		record: (id, w, p, r) => store.record(id, w, p, r),
		snapshots: (id, w) => store.list(id, w),
		collect: collect as unknown as ReleaseGateHostPorts["collect"],
	};
	const request = {
		action: "check",
		pullNumber: 133,
		expectedHead: "a".repeat(40),
	};
	const call = (value: unknown, id = "owner") =>
		handleReleaseGate(value, { sessionId: id, workspace: root }, ports);
	const prepare = () =>
		call({ phase: "prepare", request }) as Promise<AnalysisTaskPlan>;
	const approve = (p: AnalysisTaskPlan) =>
		tasks.approve(p.id, p.requirements, p.requestHash).executionToken;
	return {
		root,
		tasks,
		store,
		ports,
		collect,
		request,
		call,
		prepare,
		approve,
		mode: (v: string) => {
			mode = v;
		},
		profile: (v: boolean) => {
			profile = v;
		},
	};
}
it("real canonical Inspect approval precedes recorded network; immutable saved read after Off never replays", async () => {
	const f = fixture(),
		p = await f.prepare();
	expect(p.permission).toBe("Inspect");
	expect(p.budget.network).toBe("recorded");
	expect(p.requirements).toContain(
		"no-credentials-installer-execution-ci-rerun-or-merge",
	);
	expect(f.collect).not.toHaveBeenCalled();
	await expect(
		f.call({
			phase: "run",
			request: f.request,
			planId: p.id,
			executionToken: "model-consent",
		}),
	).rejects.toThrow();
	expect(f.collect).not.toHaveBeenCalled();
	const token = f.approve(p);
	expect(
		await f.call({
			phase: "run",
			request: f.request,
			planId: p.id,
			executionToken: token,
		}),
	).toMatchObject({ snapshotAvailable: true, result: { status: "passed" } });
	expect(f.collect).toHaveBeenCalledOnce();
	f.mode("off");
	expect(
		await f.call({ request: { action: "read", taskId: p.id } }),
	).toMatchObject({ saved: true, receipt: { status: "passed" } });
	await expect(
		f.call({ request: { action: "read", taskId: p.id } }, "other"),
	).rejects.toThrow("unavailable");
	f.mode("static");
	await expect(
		f.call({
			phase: "run",
			request: f.request,
			planId: p.id,
			executionToken: token,
		}),
	).rejects.toThrow();
	expect(f.collect).toHaveBeenCalledOnce();
});
it("changed intent and owner cannot consume exact reviewed plans", async () => {
	const f = fixture(),
		p = await f.prepare(),
		token = f.approve(p);
	await expect(
		f.call({
			phase: "run",
			request: { ...f.request, pullNumber: 134 },
			planId: p.id,
			executionToken: token,
		}),
	).rejects.toThrow();
	await expect(
		f.call(
			{ phase: "run", request: f.request, planId: p.id, executionToken: token },
			"other",
		),
	).rejects.toThrow("owning");
	expect(f.collect).not.toHaveBeenCalled();
});
it("Off, restricted profiles and authority injection deny before network; ordinary Static stays offline", async () => {
	const f = fixture();
	f.mode("off");
	await expect(f.prepare()).rejects.toThrow();
	f.mode("static");
	f.profile(false);
	await expect(f.prepare()).rejects.toThrow();
	f.profile(true);
	await expect(
		f.call({ phase: "prepare", request: { ...f.request, token: "secret" } }),
	).rejects.toThrow();
	expect(f.collect).not.toHaveBeenCalled();
	await expect(
		f.tasks.prepare({
			workspaceRoot: f.root,
			kind: "execution",
			request: { operation: "check_release_gate" },
		}),
	).rejects.toThrow("Inspect");
	expect(
		(
			await f.tasks.prepare({
				workspaceRoot: f.root,
				kind: "static",
				request: { operation: "inspect" },
			})
		).budget.network,
	).toBe("disabled");
});
it("unavailable evidence is saved as blocked, never certified by task completion", async () => {
	const f = fixture();
	f.collect.mockRejectedValue(new Error("Missing required evidence"));
	const p = await f.prepare(),
		token = f.approve(p);
	expect(
		await f.call({
			phase: "run",
			request: f.request,
			planId: p.id,
			executionToken: token,
		}),
	).toMatchObject({ snapshotAvailable: true, result: { status: "blocked" } });
	expect(f.tasks.list(f.root)[0].status).toBe("completed");
	expect(
		await f.call({ request: { action: "read", taskId: p.id } }),
	).toMatchObject({ receipt: { status: "blocked" } });
});
it("mode change cancels active reads; owning cleanup remains available after Off", async () => {
	const f = fixture();
	let entered!: () => void;
	const started = new Promise<void>((r) => (entered = r));
	f.ports.collect = (async (_p, _h, o) => {
		entered();
		return await new Promise((_r, reject) =>
			o?.signal?.addEventListener("abort", () => reject(o.signal!.reason), {
				once: true,
			}),
		);
	}) as ReleaseGateHostPorts["collect"];
	const p = await f.prepare(),
		token = f.approve(p),
		running = f.call({
			phase: "run",
			request: f.request,
			planId: p.id,
			executionToken: token,
		});
	await started;
	f.mode("off");
	await expect(running).rejects.toThrow();
	expect(f.tasks.list(f.root)[0].status).toBe("cancelled");
	expect(
		await f.call({ request: { action: "cancel", taskId: p.id } }),
	).toMatchObject({ status: "cancelled" });
	expect(f.store.list("owner", f.root)).toHaveLength(0);
});
it("snapshot retention failure cannot replay completed approved reads", async () => {
	const f = fixture();
	f.ports.record = () => {
		throw Error("disk full");
	};
	const p = await f.prepare(),
		token = f.approve(p);
	expect(
		await f.call({
			phase: "run",
			request: f.request,
			planId: p.id,
			executionToken: token,
		}),
	).toMatchObject({ snapshotAvailable: false });
	await expect(
		f.call({
			phase: "run",
			request: f.request,
			planId: p.id,
			executionToken: token,
		}),
	).rejects.toThrow();
	expect(f.collect).toHaveBeenCalledOnce();
});
