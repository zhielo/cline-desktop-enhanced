import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { probeProcessStartTokenAsync } from "@cline/core";
import { afterEach, expect, it, vi } from "vitest";
import { ManagedInspectorSessions } from "./managed-inspector";

const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
	for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});
async function fixture(lifetimeMs = 30000) {
	const root = realpathSync.native(
		await mkdtemp(join(tmpdir(), "owned-managed-node-")),
	);
	cleanups.push(() => rm(root, { recursive: true, force: true }));
	const target = join(root, "owned.js"),
		text =
			"function neverCalled(){ return 7; }\nsetInterval(()=>{let sum=0;for(let i=0;i<100000;i++)sum+=i;},5);\n";
	await writeFile(target, text);
	const child = spawn(process.execPath, ["--inspect=127.0.0.1:0", target], {
		stdio: ["ignore", "ignore", "pipe"],
	});
	cleanups.push(async () => {
		if (child.exitCode === null && child.signalCode === null) {
			child.kill();
			await new Promise<void>((r) => child.once("exit", () => r()));
		}
	});
	const endpoint = await new Promise<string>((yes, no) => {
		let text = "";
		const timer = setTimeout(
			() => no(new Error("Owned Inspector endpoint unavailable")),
			5000,
		);
		child.stderr!.on("data", (chunk) => {
			text += chunk;
			const match = text.match(/ws:\/\/127\.0\.0\.1:\d+\/[a-f0-9-]+/);
			if (match) {
				clearTimeout(timer);
				yes(match[0]);
			}
		});
		child.once("error", no);
	});
	const identity = await probeProcessStartTokenAsync(child.pid!);
	if (identity.status !== "found") throw new Error("Owned identity absent");
	const manager = new ManagedInspectorSessions(),
		owner = { sessionId: "owned", workspace: root };
	let mode = true;
	const current = () => {
		if (!mode) throw new Error("Mode changed");
	};
	const request = {
		target,
		expected_sha256: createHash("sha256").update(text).digest("hex"),
		pid: child.pid!,
		processToken: identity.token,
		endpoint,
		lifetimeMs,
	};
	let id: string | undefined;
	cleanups.push(async () => {
		if (id) await manager.stop(owner, id);
	});
	return {
		root,
		target,
		text,
		child,
		manager,
		owner,
		request,
		current,
		setMode: () => {
			mode = false;
		},
		attach: async () => {
			const result = await manager.attach(
				owner,
				request,
				current,
				new AbortController().signal,
			);
			id = result.runtimeSessionId;
			return result;
		},
	};
}
it.skipIf(!["linux", "win32"].includes(process.platform))(
	"owns a real hash-bound Inspector session, scopes breakpoints and labels CPU samples honestly",
	async () => {
		const f = await fixture(),
			attached = await f.attach(),
			id = attached.runtimeSessionId;
		expect(attached).toMatchObject({ status: "partial", pid: f.child.pid });
		expect(() =>
			f.manager.describe({ ...f.owner, sessionId: "other" }, id),
		).toThrow("owning scope");
		const bp = await f.manager.breakpoints(
			f.owner,
			id,
			[{ line: 0, column: 24 }],
			new AbortController().signal,
		);
		expect(bp.activeBreakpoints).toBe(1);
		const sampled = await f.manager.sample(
			f.owner,
			id,
			250,
			new AbortController().signal,
		);
		expect(sampled.provider).toBe("v8-cpu-sampling-selected-script");
		expect(sampled.status).toBe("partial");
		expect(JSON.stringify(sampled)).not.toContain(f.target);
		expect(JSON.stringify(sampled)).not.toContain("neverCalled");
		expect(sampled.limitations[0]).toContain("NOT a complete execution trace");
		const stopped = (await f.manager.stop(f.owner, id)) as {
			transportClosed: boolean;
			protocolCleanupConfirmed: boolean;
		};
		expect(stopped.transportClosed).toBe(true);
		expect(stopped.protocolCleanupConfirmed).toBe(true);
		expect(await f.manager.stop(f.owner, id)).toEqual(stopped);
		await expect(
			f.manager.stop({ ...f.owner, sessionId: "other" }, id),
		).rejects.toThrow("owning scope");
		expect(f.child.exitCode).toBeNull();
	},
	30000,
);
it.skipIf(!["linux", "win32"].includes(process.platform))(
	"closes on sampling cancellation and mode change, without killing the owned process",
	async () => {
		const f = await fixture(),
			id = (await f.attach()).runtimeSessionId,
			abort = new AbortController();
		const running = f.manager.sample(f.owner, id, 2000, abort.signal);
		setTimeout(() => abort.abort(), 100);
		await expect(running).rejects.toThrow();
		const receipt = (await f.manager.stop(f.owner, id)) as {
			transportClosed: boolean;
		};
		expect(receipt.transportClosed).toBe(true);
		expect(() => f.manager.describe(f.owner, id)).toThrow();
		const other = await fixture(),
			otherId = (await other.attach()).runtimeSessionId;
		other.setMode();
		await new Promise((r) => setTimeout(r, 300));
		expect(() => other.manager.describe(other.owner, otherId)).toThrow();
		expect(
			(
				(await other.manager.stop(other.owner, otherId)) as {
					transportClosed: boolean;
				}
			).transportClosed,
		).toBe(true);
		expect(other.child.exitCode).toBeNull();
	},
	30000,
);
it.skipIf(!["linux", "win32"].includes(process.platform))(
	"enforces expiry and closes even after the workspace is removed",
	async () => {
		const f = await fixture(1500),
			id = (await f.attach()).runtimeSessionId;
		await rm(f.root, { recursive: true, force: true });
		await new Promise((r) => setTimeout(r, 1800));
		expect(
			((await f.manager.stop(f.owner, id)) as { transportClosed: boolean })
				.transportClosed,
		).toBe(true);
	},
	30000,
);
it.skipIf(!["linux", "win32"].includes(process.platform))(
	"rejects stale source/process identities, endpoint forgery and resource budgets",
	async () => {
		const f = await fixture(),
			signal = new AbortController().signal;
		await expect(
			f.manager.attach(
				f.owner,
				{ ...f.request, expected_sha256: "0".repeat(64) },
				f.current,
				signal,
			),
		).rejects.toThrow();
		await expect(
			f.manager.attach(
				f.owner,
				{ ...f.request, processToken: "stale" },
				f.current,
				signal,
			),
		).rejects.toThrow();
		await expect(
			f.manager.attach(
				f.owner,
				{
					...f.request,
					endpoint: f.request.endpoint.replace("127.0.0.1", "localhost"),
				},
				f.current,
				signal,
			),
		).rejects.toThrow("loopback");
		await expect(
			f.manager.attach(
				f.owner,
				{ ...f.request, lifetimeMs: 120001 },
				f.current,
				signal,
			),
		).rejects.toThrow("lifetime");
		const id = (await f.attach()).runtimeSessionId;
		await expect(
			f.manager.attach(f.owner, f.request, f.current, signal),
		).rejects.toThrow("concurrency");
		await expect(f.manager.sample(f.owner, id, 2001, signal)).rejects.toThrow(
			"duration",
		);
	},
	30000,
);
it.skipIf(!["linux", "win32"].includes(process.platform))(
	"source changes invalidate follow-up control and close the connection",
	async () => {
		const f = await fixture(),
			id = (await f.attach()).runtimeSessionId;
		await writeFile(f.target, f.text + "// changed");
		await expect(
			f.manager.sample(f.owner, id, 200, new AbortController().signal),
		).rejects.toThrow();
		expect(
			((await f.manager.stop(f.owner, id)) as { transportClosed: boolean })
				.transportClosed,
		).toBe(true);
		expect(f.child.exitCode).toBeNull();
	},
	30000,
);

it.skipIf(!["linux", "win32"].includes(process.platform))(
	"graceful shutdown closes every owned session without killing the target",
	async () => {
		const f = await fixture(),
			attached = await f.attach();
		const results = await f.manager.stopAll("owned-shutdown-test");
		expect(results).toHaveLength(1);
		expect(results[0]).toMatchObject({
			status: "fulfilled",
			value: {
				status: "completed",
				stopReason: "owned-shutdown-test",
				transportClosed: true,
				protocolCleanupConfirmed: true,
			},
		});
		expect(f.child.exitCode).toBeNull();
		expect(f.child.signalCode).toBeNull();
		expect(() =>
			f.manager.describe(f.owner, attached.runtimeSessionId),
		).toThrow("owning scope");
		expect(await f.manager.stopAll()).toEqual([]);
	},
);

it.skipIf(!["linux", "win32"].includes(process.platform))(
	"rejects loaded-source changes before follow-up control even when disk bytes still match",
	async () => {
		const f = await fixture(),
			id = (await f.attach()).runtimeSessionId;
		const protocol = f.manager as unknown as {
			send(
				session: unknown,
				method: string,
				params?: Record<string, unknown>,
				cleanup?: boolean,
			): Promise<Record<string, unknown>>;
		};
		const original = protocol.send.bind(f.manager);
		const requests = vi
			.spyOn(protocol, "send")
			.mockImplementation((session, method, params, cleanup) =>
				method === "Debugger.getScriptSource"
					? Promise.resolve({
							scriptSource: f.text + "// other debugger changed loaded code",
						})
					: original(session, method, params, cleanup),
			);
		await expect(
			f.manager.breakpoints(
				f.owner,
				id,
				[{ line: 0, column: 24 }],
				new AbortController().signal,
			),
		).rejects.toThrow("Loaded script differs");
		expect(
			requests.mock.calls.some((call) => call[1] === "Debugger.setBreakpoint"),
		).toBe(false);
		expect(await f.manager.stop(f.owner, id)).toMatchObject({
			transportClosed: true,
			protocolCleanupConfirmed: true,
		});
		requests.mockRestore();
	},
);
