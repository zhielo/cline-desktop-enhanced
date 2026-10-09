import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { analysisResourceGovernor } from "./resource-governor";
import { withProjectLease } from "./analysis-project-lease";
import { redactSensitiveText } from "./process-environment-policy";
import type { FunctionSelector } from "./targeted-decompiler-scripts";

export type WorkerLaunch = {
	root: string;
	command: string;
	args: string[];
	nonce: string;
};
export type ManagedEngineProgress = {
	phase: string;
	pid: number | null;
	elapsedMs: number;
	remainingMs: number | null;
};
type Worker = {
	id: string;
	launch: WorkerLaunch;
	child: ChildProcess;
	exited: boolean;
	busy: boolean;
	diagnostics: string;
	stopping?: boolean;
	release: () => void;
	closed: Promise<void>;
	lease: Promise<void>;
	idle?: ReturnType<typeof setTimeout>;
	lifetime?: ReturnType<typeof setTimeout>;
};
/** cmd.exe expands these characters even without a shell command string. Fail rather than guess quoting. */
export function guardManagedBatchArguments(command: string, args: string[]) {
	if ([command, ...args].some((value) => /[&|<>^%!\r\n"]/.test(value)))
		throw new Error(
			"Managed batch worker path/argument contains unsupported cmd.exe expansion characters",
		);
}
/** Never issue a PID-based tree kill after the owned root exit has been observed. */
export function managedRootIsRunning(
	child: Pick<ChildProcess, "pid" | "exitCode" | "signalCode">,
): child is Pick<ChildProcess, "pid" | "exitCode" | "signalCode"> & {
	pid: number;
} {
	return (
		typeof child.pid === "number" &&
		child.pid > 0 &&
		child.exitCode === null &&
		child.signalCode === null
	);
}
async function readMailbox(root: string, name: string, limit: number) {
	const expected = join(root, name),
		before = await lstat(expected);
	if (!before.isFile() || before.isSymbolicLink() || before.size > limit)
		throw new Error("Unsafe managed-engine mailbox response");
	if ((await realpath(expected)) !== expected)
		throw new Error("Redirected managed-engine mailbox response");
	const handle = await open(
		expected,
		constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
	);
	try {
		const info = await handle.stat();
		if (
			info.ino !== before.ino ||
			info.dev !== before.dev ||
			info.size !== before.size
		)
			throw new Error("Mailbox response identity changed");
		const buffer = Buffer.alloc(info.size + 1);
		let count = 0;
		while (count < buffer.length) {
			const result = await handle.read(
				buffer,
				count,
				buffer.length - count,
				count,
			);
			if (!result.bytesRead) break;
			count += result.bytesRead;
		}
		if (count !== info.size || (await handle.stat()).size !== info.size)
			throw new Error("Mailbox response changed during read");
		return JSON.parse(buffer.subarray(0, count).toString("utf8")) as Record<
			string,
			unknown
		>;
	} finally {
		await handle.close();
	}
}
const delay = (ms: number) =>
	new Promise<void>((resolve) => setTimeout(resolve, ms));
/** Two workers per owning SDK process. Coordination only: not an OS sandbox or licensed-engine validation. */
export class ManagedEnginePool {
	private workers = new Map<string, Worker>();
	private creating = new Set<string>();
	constructor(
		private options: {
			leaseRoot?: string;
			idleMs?: number;
			lifetimeMs?: number;
			maxWorkers?: number;
		} = {},
	) {}
	private armIdle(worker: Worker) {
		clearTimeout(worker.idle);
		worker.idle = setTimeout(
			() => void this.stop(worker).catch(() => {}),
			this.options.idleMs ?? 90000,
		);
	}
	private async stop(worker: Worker) {
		worker.stopping = true;
		clearTimeout(worker.idle);
		clearTimeout(worker.lifetime);
		if (!worker.exited && managedRootIsRunning(worker.child)) {
			if (process.platform === "win32") {
				const killer = spawn(
					"taskkill.exe",
					["/pid", String(worker.child.pid), "/t", "/f"],
					{ stdio: "ignore", windowsHide: true },
				);
				killer.on("error", () => {});
			} else {
				try {
					process.kill(-worker.child.pid, "SIGKILL");
				} catch {
					worker.child.kill("SIGKILL");
				}
			}
		}
		await new Promise<void>((resolve, reject) => {
			const timer = setTimeout(
				() =>
					reject(
						new Error("Worker termination unconfirmed; project lease retained"),
					),
				10000,
			);
			worker.closed.then(
				() => {
					clearTimeout(timer);
					resolve();
				},
				(error) => {
					clearTimeout(timer);
					reject(error);
				},
			);
		});
		await worker.lease;
	}
	private async create(
		key: string,
		project: string,
		factory: () => Promise<WorkerLaunch>,
		signal: AbortSignal | undefined,
		timeoutMs: number,
    onWaiting?: (worker: Worker, remainingMs: number) => void,
	) {
		if (this.creating.has(key))
			throw new Error(
				"Worker startup already in progress; no duplicate launch",
			);
		if (
			this.workers.size + this.creating.size >=
			(this.options.maxWorkers ?? 2)
		)
			throw new Error(
				"Managed engine pool capacity reached; wait for an idle worker to exit",
			);
		this.creating.add(key);
		let release = () => {};
		const hold = new Promise<void>((resolve) => {
			release = resolve;
		});
		let acquiredResolve = () => {},
			acquiredReject = (_e: unknown) => {};
		const acquired = new Promise<void>((resolve, reject) => {
			acquiredResolve = resolve;
			acquiredReject = reject;
		});
		const lease = withProjectLease(
			project,
			async () => {
				acquiredResolve();
				await hold;
			},
			signal,
			{ root: this.options.leaseRoot },
		);
		lease.catch(acquiredReject);
		let worker: Worker | undefined;
		let releaseResource: (() => void) | undefined;
		let releaseStartup: (() => void) | undefined;
		try {
			await acquired;
			signal?.throwIfAborted();
			releaseResource = await analysisResourceGovernor.acquire(
				256,
				signal,
				Math.min(timeoutMs, 60000),
				true,
			);
			const launch = await factory();
			launch.root = await realpath(launch.root);
			signal?.throwIfAborted();
			const batch =
				process.platform === "win32" && /\.(bat|cmd)$/i.test(launch.command);
			if (batch) guardManagedBatchArguments(launch.command, launch.args);
			releaseStartup = await analysisResourceGovernor.acquire(
				1,
				signal,
				Math.min(timeoutMs, 60000),
			);
			const child = spawn(
				batch ? (process.env.ComSpec ?? "cmd.exe") : launch.command,
				batch
					? ["/d", "/s", "/c", "call", launch.command, ...launch.args]
					: launch.args,
				{
					stdio: ["ignore", "pipe", "pipe"],
					detached: process.platform !== "win32",
					windowsHide: true,
				},
			);
			let resolveClosed = () => {};
			const closed = new Promise<void>((resolve) => {
				resolveClosed = resolve;
			});
			worker = {
				id: randomUUID(),
				launch,
				child,
				exited: false,
				busy: true,
				diagnostics: "",
				release,
				closed,
				lease,
			};
			const current = worker;
			// Always drain both pipes; retain only a bounded diagnostic tail.
			const drain = (chunk: Buffer) => {
				current.diagnostics = (
					current.diagnostics + chunk.toString("utf8")
				).slice(-4096);
			};
			child.stdout?.on("data", drain);
			child.stderr?.on("data", drain);
			const exited = () => {
				if (current.exited) return;
				current.exited = true;
				clearTimeout(current.idle);
				clearTimeout(current.lifetime);
				current.release();
				releaseResource?.();
				releaseStartup?.();
				releaseStartup = undefined;
				this.workers.delete(key);
				resolveClosed();
			};
			child.once("close", exited);
			child.once("error", () => {
				if (!child.pid) exited();
			});
			this.workers.set(key, current);
			current.lifetime = setTimeout(
				() => void this.stop(current).catch(() => {}),
				this.options.lifetimeMs ?? 900000,
			);
			await this.waitFor(current, "ready.json", timeoutMs, signal, 4096, remaining => onWaiting?.(current, remaining));
			releaseStartup?.();
			releaseStartup = undefined;
			return current;
		} catch (error) {
			if (worker) await this.stop(worker);
			else {
				releaseResource?.();
				releaseStartup?.();
				release();
				await lease;
			}
			throw error;
		} finally {
			this.creating.delete(key);
		}
	}
	private async waitFor(
		worker: Worker,
		name: string,
		timeoutMs: number,
		signal: AbortSignal | undefined,
		limit: number,
		onWaiting?: (remainingMs: number) => void,
	) {
		const until = Date.now() + timeoutMs;
		let lastProgressAt = 0;
		for (;;) {
			if (Date.now() - lastProgressAt >= 30_000) {
				lastProgressAt = Date.now();
				try { onWaiting?.(Math.max(0, until - Date.now())); } catch { /* Observer only. */ }
			}
			signal?.throwIfAborted();
			if (worker.exited)
				throw new Error(
					`Managed engine exited; no automatic replay or restart. ${redactSensitiveText(worker.diagnostics).slice(-1000)}`,
				);
			try {
				const response = await readMailbox(worker.launch.root, name, limit);
				if (response.protocol !== 1 || response.nonce !== worker.launch.nonce)
					throw new Error("Managed engine protocol/nonce mismatch");
				return response;
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
			}
			if (Date.now() >= until)
				throw new Error(
					"Managed engine response timed out; no automatic replay",
				);
			await delay(50);
		}
	}
	async query(
		key: string,
		project: string,
		factory: () => Promise<WorkerLaunch>,
		selector: FunctionSelector,
		signal?: AbortSignal,
		timeoutMs = 120000,
		onProgress?: (event: ManagedEngineProgress) => void,
	) {
		const started = Date.now();
		const notify = (phase: string, worker?: Worker, remainingMs: number | null = null) => {
			try { onProgress?.({phase, pid:worker?.child.pid ?? null, elapsedMs:Date.now()-started, remainingMs}); }
			catch { /* A failed UI observer must not alter worker ownership. */ }
		};
		if (
			Boolean(selector.symbol) === Boolean(selector.address) ||
			(selector.symbol !== undefined &&
				(selector.symbol.length < 1 || selector.symbol.length > 4096)) ||
			(selector.address !== undefined &&
				!/^0x[0-9a-fA-F]{1,16}$/.test(selector.address))
		)
			throw new Error("Exactly one exact function selector required");
		signal?.throwIfAborted();
		let worker = this.workers.get(key);
		notify(worker ? "checking existing worker" : "creating private worker; awaiting readiness", worker);
		const reused = !!worker;
		if (worker?.busy || worker?.stopping)
			throw new Error("Managed engine is busy; request not queued or replayed");
		if (worker) {
			worker.busy = true;
			clearTimeout(worker.idle);
		} else worker = await this.create(key, project, factory, signal, timeoutMs, (current, remaining) => notify("awaiting worker ready mailbox; import/auto-analysis not yet proven complete", current, remaining));
		const current = worker,
			id = randomUUID();
		notify("worker readiness verified; waiting for execution admission", current);
		let releaseExecution: (() => void) | undefined;
		try {
			releaseExecution = await analysisResourceGovernor.acquire(
				128,
				signal,
				Math.min(timeoutMs, 60000),
			);
			if (current.exited)
				throw new Error("Managed engine exited; no automatic restart");
			const request = {
				protocol: 1,
				nonce: current.launch.nonce,
				id,
				kind: selector.symbol ? "symbol" : "address",
				value64: Buffer.from(selector.symbol ?? selector.address!).toString(
					"base64",
				),
			};
			const stage = join(current.launch.root, `${id}.request.stage`);
			await writeFile(stage, JSON.stringify(request), {
				flag: "wx",
				mode: 0o600,
			});
			await rename(stage, join(current.launch.root, "request.json"));
			notify("selected-function request submitted once; awaiting response", current, Math.min(timeoutMs,60000));
			const response = await this.waitFor(
				current,
				`${id}.json`,
				Math.min(timeoutMs, 60000),
				signal,
				1024 * 1024,
				remaining => notify("awaiting selected-function mailbox response", current, remaining),
			);
			if (
				response.id !== id ||
				!["completed", "failed"].includes(String(response.status))
			)
				throw new Error("Managed engine request binding mismatch");
			if (response.status !== "completed")
				throw new Error(
					typeof response.error === "string"
						? response.error.slice(0, 1000)
						: "Managed engine decompilation failed",
				);
			if (
				typeof response.code !== "string" ||
				response.code.length > 100000 ||
				typeof response.entry !== "string" ||
				response.entry.length > 128
			)
				throw new Error("Managed engine result budget/shape mismatch");
			await rm(join(current.launch.root, `${id}.json`));
			notify("selected-function response verified", current, 0);
			return {
				workerId: current.id,
				pid: current.child.pid,
				reusedWorker: reused,
				entry: response.entry,
				code: response.code,
				coverage: "fixed-selected-function-disk-analysis",
				notice:
					"Not a semantic equivalence proof, OS sandbox or loaded-memory observation",
			};
		} catch (error) {
			if (releaseExecution) await this.stop(current);
			throw error;
		} finally {
			releaseExecution?.();
			current.busy = false;
			if (!current.exited && !current.stopping) this.armIdle(current);
		}
	}
	async close() {
		await Promise.all(
			[...this.workers.values()].map((worker) => this.stop(worker)),
		);
	}
}
