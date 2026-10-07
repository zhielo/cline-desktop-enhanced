import { mkdtemp, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { apk } from "./__fixtures__/incident";
import { AnalysisTaskOrchestrator } from "./analysis-task-orchestrator";
import {
	ApkIncidentService,
	packageFailures,
	packageProcesses,
} from "./apk-incident-service";
import { digest } from "./incident-artifacts";

const resources: { root: string; service: ApkIncidentService }[] = [];
async function cleanupFixtures(
	fixtures: { root: string; service: Pick<ApkIncidentService, "close"> }[],
	remove: (root: string) => Promise<void> = (root) =>
		rm(root, { recursive: true, force: true }),
) {
	// Windows retains SQLite WAL locks until every connection to the shared root is closed.
	// Close all owners first, then remove each unique root exactly once; no retry/skip hides a leak.
	for (const fixture of fixtures) fixture.service.close();
	for (const root of new Set(fixtures.map((fixture) => fixture.root)))
		await remove(root);
}
afterEach(async () => {
	await cleanupFixtures(resources.splice(0));
});
async function fixture() {
	const root = await mkdtemp(join(tmpdir(), "incident-case-")),
		original = apk(),
		candidate = apk(undefined, "candidate");
	await writeFile(join(root, "original.apk"), original);
	await writeFile(join(root, "candidate.apk"), candidate);
	let installed = original,
		crashCalls = 0;
	const calls: Record<string, unknown>[] = [],
		state = {
			badSignature: false,
			wrongDeviceHash: false,
			historical: false,
			crash: false,
		};
	const tasks = new AnalysisTaskOrchestrator({
		ledgerFilePath: join(root, "tasks.json"),
	});
	const options = {
		dbPath: join(root, "cases.sqlite"),
		// Exercise a valid non-canonical cache spelling on every OS; Windows also
		// exercises its realpath drive/temp-directory normalization.
		cacheRoot: join(root, "private") + "/../private",
		tasks,
		sleep: async () => {},
		android: async (input: Record<string, unknown>) => {
			calls.push(input);
			if (input.operation === "debug_reports") {
				const text =
					'Cmd line: com.example.app\n"main" tid=1 Blocked\n - waiting to lock <0x1> held by thread 2\n';
				return {
					succeeded: true,
					coverage: "explicit-path-package-scoped-adb-observations",
					deviceSerialSha256: digest(String(input.device_serial)),
					reports: [
						{
							sourcePath: "/data/anr/anr_owned",
							status: "scoped-report-read",
							sourceComplete: true,
							text,
							sha256: digest(text),
						},
					],
					limitations: ["Owned fixture, not a physical-device validation"],
				};
			}

			if (input.operation === "pull_apk_bounded") {
				const b = state.wrongDeviceHash ? candidate : installed;
				await writeFile(String(input.output_path), b);
				return {
					succeeded: true,
					coverage: "base-apk-only",
					sha256: digest(b),
				};
			}
			if (input.operation === "install")
				installed = String(input.path).includes(".apk")
					? await (await import("node:fs/promises")).readFile(
							String(input.path),
						)
					: installed;
			if (input.operation === "processes")
				return {
					stdout:
						"USER PID NAME\nu0_a1 42 com.example.app\nu0_a1 43 com.example.app:worker\nu0_a2 44 com.other.app",
				};
			if (input.operation === "logcat")
				return { stdout: "owned log token=abc" };
			if (input.operation === "crash_logs") {
				crashCalls++;
				return {
					stdout:
						state.historical || (state.crash && crashCalls > 1)
							? "E FATAL EXCEPTION: main\nE Process: com.example.app, PID: 42\nE java.lang.IllegalStateException: failure"
							: "",
				};
			}
			return { exitCode: 0 };
		},
		reverse: async (input: Record<string, unknown>) => ({
			verified: !state.badSignature,
			sha256: digest(
				await (await import("node:fs/promises")).readFile(String(input.target)),
			),
		}),
	};
	const service = new ApkIncidentService(options);
	resources.push({ root, service });
	const request = {
		operation: "observe_apk",
		target: "original.apk",
		package: "com.example.app",
		device_serial: "owned-device",
		reproduction: "Tap owned test button",
		expected: "no crash, same output",
		duration_seconds: 2,
	};
	async function start(input: unknown = request) {
		const plan = await service.prepare(root, input),
			approved = tasks.approve(plan.id, plan.requirements, plan.requestHash);
		return service.start(root, plan.id, approved.executionToken);
	}
	async function completed(id: string) {
		for (let i = 0; i < 100; i++) {
			const c = service.get(root, id);
			if (!["accepted", "running"].includes(c.status)) return c;
			await new Promise((r) => setTimeout(r, 10));
		}
		throw new Error("Fixture did not complete");
	}
	return {
		root,
		service,
		tasks,
		calls,
		state,
		start,
		completed,
		request,
		options,
	};
}
describe("durable APK incidents", () => {
	it("scopes multiple processes and discards unrelated crash records", () => {
		expect(
			packageProcesses(
				"USER PID NAME\nx 1 com.example.app\nx 2 com.example.app:worker\nx 3 com.other.app",
				"com.example.app",
			).map((p) => p.pid),
		).toEqual([1, 2]);
		expect(
			packageFailures(
				"E FATAL EXCEPTION: main\nProcess: com.other.app, PID: 3\nE FATAL EXCEPTION: main\nProcess: com.example.app, PID: 1\ntoken=abc",
				"com.example.app",
			),
		).toEqual([
			expect.objectContaining({
				kind: "java-crash",
				text: expect.stringContaining("[REDACTED]"),
			}),
		]);
		expect(() => packageProcesses("unknown table", "x.y")).toThrow(
			"process table",
		);
	});
	it("returns accepted then checkpoints completion without a fixed verdict or replay", async () => {
		const f = await fixture(),
			receipt = await f.start();
		expect(receipt.completed).toBe(false);
		const c = await f.completed(receipt.id);
		expect(c.status).toBe("completed");
		expect(c.result).toContain("Not a verified fix");
		const count = f.calls.length;
		f.service.get(f.root, c.id);
		f.service.list(f.root);
		expect(f.calls.length).toBe(count);
		expect(
			f.calls
				.filter((call) => call.operation === "logcat")
				.map((call) => call.process_id),
		).toEqual([42, 43]);
	});
	it("requires device log approvals and exact installed APK before any launch", async () => {
		const f = await fixture(),
			p = await f.service.prepare(f.root, {
				...f.request,
				operation: "launch_apk",
			});
		expect(p.requirements).toContain("sensitive-device-logs");
		expect(p.requirements).toContain("execution-control");
		expect(() => f.tasks.approve(p.id, [], p.requestHash)).toThrow();
		f.state.wrongDeviceHash = true;
		const a = f.tasks.approve(p.id, p.requirements, p.requestHash),
			r = await f.service.start(f.root, p.id, a.executionToken),
			c = await f.completed(r.id);
		expect(c.status).toBe("incomplete");
		expect(f.calls.some((call) => call.operation === "launch")).toBe(false);
	});
	it("blocks tampered candidates and unsuccessful real signature verification", async () => {
		const f = await fixture(),
			request = {
				...f.request,
				operation: "validate_apk_patch",
				compare_target: "candidate.apk",
			},
			p = await f.service.prepare(f.root, request),
			a = f.tasks.approve(p.id, p.requirements, p.requestHash);
		await writeFile(join(f.root, "candidate.apk"), apk(undefined, "changed"));
		await expect(
			f.service.start(f.root, p.id, a.executionToken),
		).rejects.toThrow("Candidate changed");
		expect(f.calls.length).toBe(0);
		await writeFile(join(f.root, "candidate.apk"), apk(undefined, "candidate"));
		f.state.badSignature = true;
		const r = await f.start(request),
			c = await f.completed(r.id);
		expect(c.status).toBe("incomplete");
		expect(f.calls.some((call) => call.operation === "install")).toBe(false);
	});
	it("requires a separately approved identity-bound rollback and manual review", async () => {
		const f = await fixture(),
			r = await f.start({
				...f.request,
				operation: "validate_apk_patch",
				compare_target: "candidate.apk",
			}),
			c = await f.completed(r.id);
		expect(c.events.some((e) => e.stage === "candidate-installed")).toBe(true);
		expect(c.review).toBeUndefined();
		await expect(
			f.service.prepare(f.root, {
				...f.request,
				operation: "rollback_apk",
				compare_target: "candidate.apk",
			}),
		).rejects.toThrow("Prior patch");
		const p = await f.service.prepare(f.root, {
			...f.request,
			operation: "rollback_apk",
			compare_target: "candidate.apk",
			rollback_case_id: c.id,
		});
		expect(p.requirements).toContain("package-change");
		const a = f.tasks.approve(p.id, p.requirements, p.requestHash),
			restore = await f.service.start(f.root, p.id, a.executionToken);
		expect((await f.completed(restore.id)).stage).toBe("rollback-completed");
		const reviewed = f.service.review(f.root, {
			id: c.id,
			revision: c.revision,
			reproductionCompleted: true,
			regressionPassed: true,
			notes: "Checked fixture regressions",
		});
		expect(reviewed.review?.regressionPassed).toBe(true);
		expect(() =>
			f.service.review(f.root, {
				id: c.id,
				revision: c.revision,
				reproductionCompleted: true,
				regressionPassed: true,
				notes: "stale",
			}),
		).toThrow("Reload");
	});
	it("marks another owner's live case control-unavailable without reclaiming execution", async () => {
		const f = await fixture();
		let release!: () => void;
		f.options.sleep = async () =>
			new Promise<void>((res) => {
				release = res;
			});
		const otherService = new ApkIncidentService(f.options);
		resources.push({ root: f.root, service: otherService });
		const r = await f.start({ ...f.request, duration_seconds: 4 });
		for (let i = 0; i < 50 && !release; i++)
			await new Promise((res) => setTimeout(res, 10));
		expect(otherService.get(f.root, r.id).controlUnavailable).toBe(true);
		const before = f.calls.length;
		otherService.list(f.root);
		expect(f.calls.length).toBe(before);
		release();
		await f.completed(r.id);
	});
	it("retains matching failure evidence but does not automatically call it fixed", async () => {
		const f = await fixture();
		f.state.crash = true;
		const r = await f.start(),
			c = await f.completed(r.id);
		expect(c.failures[0]?.kind).toBe("java-crash");
		expect(c.result).toContain("Matching failure");
	});
});

it("does not count a baseline crash as a new regression", async () => {
	const f = await fixture();
	f.state.historical = true;
	const r = await f.start();
	const c = await f.completed(r.id);
	expect(c.failures).toHaveLength(0);
});
it("one-shot approval cannot create duplicate jobs", async () => {
	const f = await fixture(),
		p = await f.service.prepare(f.root, f.request),
		a = f.tasks.approve(p.id, p.requirements, p.requestHash);
	const results = await Promise.allSettled([
		f.service.start(f.root, p.id, a.executionToken),
		f.service.start(f.root, p.id, a.executionToken),
	]);
	expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
	const accepted = results.find(
		(r) => r.status === "fulfilled",
	) as PromiseFulfilledResult<{ id: string }>;
	await f.completed(accepted.value.id);
	expect(f.service.list(f.root)).toHaveLength(1);
});
it("cancels observation without replaying or claiming a fix", async () => {
	const f = await fixture();
	let release!: () => void;
	f.options.sleep = async () =>
		new Promise<void>((r) => {
			release = r;
		});
	const accepted = await f.start({ ...f.request, duration_seconds: 4 });
	for (let i = 0; i < 50 && !release; i++)
		await new Promise((r) => setTimeout(r, 10));
	const c = f.service.get(f.root, accepted.id);
	f.tasks.cancel(c.planId);
	release();
	const stopped = await f.completed(c.id);
	expect(stopped.status).toBe("incomplete");
	expect(stopped.result).toContain("Do not infer a fix");
	const count = f.calls.length;
	f.service.get(f.root, c.id);
	expect(f.calls.length).toBe(count);
});

it("closes every SQLite owner before deleting shared fixture directories", async () => {
	const events: string[] = [];
	await cleanupFixtures(
		[
			{
				root: "shared-root",
				service: {
					close: () => {
						events.push("close-first");
					},
				},
			},
			{
				root: "shared-root",
				service: {
					close: () => {
						events.push("close-second");
					},
				},
			},
			{
				root: "other-root",
				service: {
					close: () => {
						events.push("close-third");
					},
				},
			},
		],
		async (root) => {
			expect(events.slice(0, 3)).toEqual([
				"close-first",
				"close-second",
				"close-third",
			]);
			events.push(`remove-${root}`);
		},
	);
	expect(events).toEqual([
		"close-first",
		"close-second",
		"close-third",
		"remove-shared-root",
		"remove-other-root",
	]);
});

it("collects separately approved diagnostic reports without launch, install or blanket root", async () => {
	const f = await fixture();
	const p = await f.service.prepare(f.root, {
		...f.request,
		operation: "collect_apk_debug",
		debug_report_paths: ["/data/anr/anr_owned"],
		use_root: true,
	});
	expect(p.permission).toBe("Inspect");
	expect(p.requirements).toContain("explicit-root-read-without-policy-change");
	expect(p.requirements).not.toContain("execution-control");
	const approval = f.tasks.approve(p.id, p.requirements, p.requestHash),
		accepted = await f.service.start(f.root, p.id, approval.executionToken),
		c = await f.completed(accepted.id);
	expect(c.stage).toBe("diagnostic-report-completed");
	expect(
		f.calls.some((c) =>
			["launch", "install", "force_stop"].includes(String(c.operation)),
		),
	).toBe(false);
	const report = c.observations.find((o) => o.stage === "diagnostic-report")!;
	expect(report.text).toBeUndefined();
	const viewed = await f.service.diagnosticReport(
		f.root,
		c.id,
		String(report.sha256),
	);
	expect(viewed.text).toContain("com.example.app");
	expect(viewed.parsed.scope).toContain("adb-file-observation");
});

it("rejects a diagnostic incident directory junction even when report bytes match", async () => {
	const f = await fixture();
	const p = await f.service.prepare(f.root, {
		...f.request,
		operation: "collect_apk_debug",
		debug_report_paths: ["/data/anr/anr_owned"],
	});
	const approval = f.tasks.approve(p.id, p.requirements, p.requestHash),
		accepted = await f.service.start(f.root, p.id, approval.executionToken),
		c = await f.completed(accepted.id),
		report = c.observations.find((o) => o.stage === "diagnostic-report")!,
		directory = join(f.root, "private", c.id),
		moved = join(f.root, "moved-reports");
	await rename(directory, moved);
	await symlink(moved, directory, "junction");
	await expect(
		f.service.diagnosticReport(f.root, c.id, String(report.sha256)),
	).rejects.toThrow("Diagnostic incident directory link not permitted");
});

it("rejects modified and oversized private diagnostic reports", async () => {
	const f = await fixture();
	const p = await f.service.prepare(f.root, {
		...f.request,
		operation: "collect_apk_debug",
		debug_report_paths: ["/data/anr/anr_owned"],
	});
	const approval = f.tasks.approve(p.id, p.requirements, p.requestHash),
		accepted = await f.service.start(f.root, p.id, approval.executionToken),
		c = await f.completed(accepted.id),
		report = c.observations.find((o) => o.stage === "diagnostic-report")!,
		path = join(f.root, "private", c.id, `${report.sha256}.report.txt`);
	await writeFile(path, "tampered");
	await expect(
		f.service.diagnosticReport(f.root, c.id, String(report.sha256)),
	).rejects.toThrow("Diagnostic report integrity mismatch");
	await writeFile(path, Buffer.alloc(524289));
	await expect(
		f.service.diagnosticReport(f.root, c.id, String(report.sha256)),
	).rejects.toThrow("Diagnostic report integrity/budget mismatch");
});
