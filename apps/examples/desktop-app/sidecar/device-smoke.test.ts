import { mkdtemp, realpath, rm, writeFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
const state = vi.hoisted(() => ({
	mode: "runtime",
	workspace: "",
	profile: true,
	bind: vi.fn(),
	record: vi.fn(),
}));
vi.mock("./first-party-analysis", () => ({
	firstPartyStore: () => ({
		session: () => ({ mode: state.mode, workspace: state.workspace }),
		get: () => undefined,
	}),
	bindFirstPartyTaskEvidence: state.bind,
	recordFirstPartyTaskEvidence: state.record,
	sessionTaskSnapshots: () => [],
}));
import { apk } from "./__fixtures__/incident";
import {
	AnalysisTaskOrchestrator,
	type AnalysisTaskPlan,
} from "./analysis-task-orchestrator";
import { ApkIncidentService } from "./apk-incident-service";
import { digest } from "./incident-artifacts";
import { handleDeviceSmoke } from "./device-smoke";
const resources: {
	root: string;
	service: ApkIncidentService;
	tasks: AnalysisTaskOrchestrator;
}[] = [];
afterEach(async () => {
	for (const r of resources) {
		for (const p of r.tasks.list(r.root))
			if (["running", "awaiting-approval", "approved"].includes(p.status))
				r.tasks.cancel(p.id);
		await new Promise((r) => setTimeout(r, 120));
		r.service.close();
		await rm(r.root, { recursive: true, force: true });
	}
	resources.length = 0;
	state.mode = "runtime";
	state.profile = true;
	state.bind.mockReset();
	state.record.mockReset();
});
async function fixture() {
	const root = await realpath(await mkdtemp(join(tmpdir(), "device-smoke-")));
	state.workspace = root;
	const bytes = apk(),
		target = join(root, "owned.apk");
	await writeFile(target, bytes);
	const tasks = new AnalysisTaskOrchestrator({
		ledgerFilePath: join(root, "tasks.json"),
	});
	const calls: string[] = [];
	let held = false,
		release: undefined | (() => void),
		wrong = false;
	const service = new ApkIncidentService({
		dbPath: join(root, "incidents.sqlite"),
		cacheRoot: join(root, "private"),
		tasks,
		sleep: async () => {
			if (held)
				await new Promise<void>((r) => {
					release = r;
				});
		},
		reverse: async () => {
			throw new Error("No build/install allowed");
		},
		android: async (input, signal) => {
			signal?.throwIfAborted();
			calls.push(String(input.operation));
			if (input.operation === "pull_apk_bounded") {
				const data = wrong ? apk(undefined, "different") : bytes;
				await writeFile(String(input.output_path), data);
				return {
					succeeded: true,
					coverage: "base-apk-only",
					sha256: digest(data),
				};
			}
			if (input.operation === "device_info")
				return { stdout: "owned-device-info", exitCode: 0 };
			if (input.operation === "processes")
				return {
					stdout: "USER PID NAME\nu0_a1 42 com.example.app",
					exitCode: 0,
				};
			return {
				exitCode: 0,
				stdout: input.operation === "logcat" ? "owned token=secret" : "",
			};
		},
	});
	resources.push({ root, service, tasks });
	const request = {
		action: "start",
		target,
		expected_sha256: digest(bytes),
		deviceSerial: "owned-device",
		packageName: "com.example.app",
		durationSeconds: 4,
		purpose: "Owned fixture launch observation",
	};
	const call = (input: unknown, sessionId = "owner") =>
		handleDeviceSmoke(
			input,
			{ sessionId, workspace: root },
			tasks,
			service,
			() => {
				if (!state.profile) throw new Error("profile changed");
			},
		);
	const prepare = () =>
		call({ phase: "prepare", request }) as Promise<AnalysisTaskPlan>;
	const approve = (p: AnalysisTaskPlan) => ({
		phase: "run",
		request,
		planId: p.id,
		executionToken: tasks.approve(p.id, p.requirements, p.requestHash)
			.executionToken,
	});
	const terminal = async (taskId: string) => {
		for (let i = 0; i < 200; i++) {
			const c = service.byPlan(root, taskId);
			if (c && ["completed", "incomplete"].includes(c.status)) return c;
			await new Promise((r) => setTimeout(r, 10));
		}
		throw new Error("Fixture did not terminate");
	};
	return {
		root,
		target,
		tasks,
		service,
		calls,
		request,
		call,
		prepare,
		approve,
		terminal,
		hold: () => {
			held = true;
		},
		release: () => {
			held = false;
			release?.();
		},
		wrong: () => {
			wrong = true;
		},
	};
}
it("uses exact approved existing launch engine and completed snapshot; never installs or force-stops", async () => {
	const f = await fixture(),
		p = await f.prepare();
	expect(f.calls).toEqual([]);
	expect(p.requirements).toContain("execution-control");
	const run = f.approve(p),
		accepted = (await f.call(run)) as { taskId: string; completed: boolean };
	expect(accepted.taskId).toBe(p.id);
	expect(accepted.completed).toBe(false);
	const c = await f.terminal(p.id);
	expect(c.status).toBe("completed");
	expect(c.result).toContain("Not a verified fix");
	expect(f.calls.filter((x) => x === "launch")).toHaveLength(1);
	expect(f.calls).not.toContain("install");
	expect(f.calls).not.toContain("force_stop");
	expect(state.record).toHaveBeenCalledWith(
		"owner",
		f.root,
		expect.objectContaining({
			status: "completed",
			evidence: expect.any(Object),
		}),
		expect.objectContaining({ status: "completed" }),
	);
	expect(
		await f.call({ request: { action: "status", taskId: p.id } }),
	).toMatchObject({ taskStatus: "completed", cleanupConfirmed: true });
	await expect(f.call(run)).rejects.toThrow("approval");
	expect(
		(await readdir(join(f.root, "private", c.id))).filter((x) =>
			x.endsWith(".apk"),
		),
	).toEqual([]);
});
it("denies missing approval, altered intent, cross-owner access and changed APK", async () => {
	const f = await fixture(),
		p = await f.prepare();
	await expect(
		f.call({ phase: "run", request: f.request, planId: p.id }),
	).rejects.toThrow("one-use");
	const run = f.approve(p);
	await expect(f.call(run, "other")).rejects.toThrow("exact owning request");
	for (const change of [{ deviceSerial: "other" }, { purpose: "different" }])
		await expect(
			f.call({ ...run, request: { ...f.request, ...change } }),
		).rejects.toThrow("exact owning request");
	await expect(
		f.call({ request: { action: "status", taskId: p.id } }, "other"),
	).rejects.toThrow("owning session");
	await writeFile(f.target, apk(undefined, "changed"));
	await expect(f.call(run)).rejects.toThrow("changed");
	expect(f.calls).toEqual([]);
});
it("fails before launch on manifest or installed base APK mismatch", async () => {
	const f = await fixture();
	await expect(
		f.call({
			phase: "prepare",
			request: { ...f.request, packageName: "com.other.app" },
		}),
	).rejects.toThrow("package mismatch");
	const p = await f.prepare();
	f.wrong();
	await f.call(f.approve(p));
	expect((await f.terminal(p.id)).status).toBe("incomplete");
	expect(f.calls).not.toContain("launch");
	expect(state.record).not.toHaveBeenCalled();
});
it("Static, missing Hybrid basis and restricted profiles cannot prepare device work", async () => {
	const f = await fixture();
	state.mode = "static";
	await expect(f.prepare()).rejects.toThrow("Runtime/Hybrid");
	state.mode = "hybrid";
	await expect(f.prepare()).rejects.toThrow();
	state.mode = "runtime";
	state.profile = false;
	await expect(f.prepare()).rejects.toThrow("profile");
	expect(f.calls).toEqual([]);
});
it.each([
	"mode",
	"profile",
	"cancel",
])("stops observation on %s change; status/cancel remain available after Off", async (change) => {
	const f = await fixture();
	f.hold();
	const p = await f.prepare();
	await f.call(f.approve(p));
	for (let i = 0; i < 100 && !f.calls.includes("logcat"); i++)
		await new Promise((r) => setTimeout(r, 10));
	expect(f.calls).toContain("logcat");
	if (change === "mode") state.mode = "off";
	if (change === "profile") state.profile = false;
	if (change === "cancel")
		await f.call({ request: { action: "cancel", taskId: p.id } });
	await new Promise((r) => setTimeout(r, 150));
	f.release();
	expect((await f.terminal(p.id)).status).toBe("incomplete");
	expect(
		await f.call({ request: { action: "status", taskId: p.id } }),
	).toMatchObject({ taskStatus: "cancelled", cleanupConfirmed: true });
	expect(f.calls).not.toContain("force_stop");
});
it("prevents overlapping work on the same selected device", async () => {
	const f = await fixture();
	f.hold();
	const p = await f.prepare();
	await f.call(f.approve(p));
	for (let i = 0; i < 100 && !f.calls.includes("logcat"); i++)
		await new Promise((r) => setTimeout(r, 10));
	const p2 = (await f.call(
		{ phase: "prepare", request: f.request },
		"other",
	)) as AnalysisTaskPlan;
	await expect(f.call(f.approve(p2), "other")).rejects.toThrow("concurrency");
	await f.call({ request: { action: "cancel", taskId: p.id } });
	f.release();
	await f.terminal(p.id);
});

it("legacy start cannot bypass the owning AI mode/profile lifecycle", async () => {
	const f = await fixture(),
		p = await f.prepare(),
		approved = f.approve(p);
	await expect(
		f.service.start(f.root, p.id, approved.executionToken),
	).rejects.toThrow("legacy start");
	expect(f.calls).toEqual([]);
});
