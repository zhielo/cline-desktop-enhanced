import { createHash, randomUUID } from "node:crypto";
import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { assertInspectorOwner, sameInspectorSourcePath } from "@cline/core";
import WebSocket from "ws";
import {
	assertCaptureFile,
	assertCaptureProcess,
} from "./runtime-capture-backend";

export type InspectorOwner = { sessionId: string; workspace: string };
export type ManagedInspectorTarget = {
	target: string;
	expected_sha256: string;
	pid: number;
	processToken: string;
	endpoint: string;
	lifetimeMs: number;
	hybrid?: unknown;
};
type Pending = {
	resolve(value: Record<string, unknown>): void;
	reject(error: Error): void;
	timer: ReturnType<typeof setTimeout>;
};
type ManagedSession = {
	id: string;
	owner: string;
	target: ManagedInspectorTarget;
	socket: WebSocket;
	scriptId: string;
	breakpoints: Set<string>;
	enabled: boolean;
	busy: boolean;
	profilerEnabled: boolean;
	profiling: boolean;
	nextId: number;
	messages: number;
	bytes: number;
	pending: Map<number, Pending>;
	current(): void;
	closed: Promise<void>;
	resolveClosed(): void;
	expiresAt: string;
	expiry?: ReturnType<typeof setTimeout>;
	modePoll?: ReturnType<typeof setInterval>;
	stop?: Promise<unknown>;
};
const digest = (value: string) =>
	createHash("sha256").update(value).digest("hex");
const key = (owner: InspectorOwner) => {
	let workspace = resolve(owner.workspace);
	try {
		workspace = realpathSync(workspace);
	} catch {
		/* Internal cleanup must still work after workspace removal. */
	}
	return JSON.stringify([owner.sessionId, workspace]);
};
function endpointPort(endpoint: string) {
	const u = new URL(endpoint);
	if (
		u.protocol !== "ws:" ||
		u.hostname !== "127.0.0.1" ||
		!u.port ||
		u.username ||
		u.password ||
		u.search ||
		u.hash ||
		!/^\/[a-f0-9-]{36}$/i.test(u.pathname)
	)
		throw new Error(
			"Only an exact loopback Node Inspector endpoint is supported",
		);
	const port = Number(u.port);
	if (!Number.isInteger(port) || port < 1 || port > 65535)
		throw new Error("Invalid Inspector port");
	return port;
}
/** Bounded Node Inspector only. No shell, evaluate, launch, step or resume methods. */
export class ManagedInspectorSessions {
	private readonly sessions = new Map<string, ManagedSession>();
	private readonly closed = new Map<
		string,
		{ owner: string; receipt: unknown }
	>();
	private async identity(target: ManagedInspectorTarget, signal: AbortSignal) {
		signal.throwIfAborted();
		await assertCaptureFile(target.target, target.expected_sha256, signal);
		await assertCaptureProcess(target.pid, target.processToken, signal);
		await assertInspectorOwner(target.pid, endpointPort(target.endpoint));
		signal.throwIfAborted();
	}
	private owned(owner: InspectorOwner, id: string) {
		const session = this.sessions.get(id);
		if (!session || session.owner !== key(owner) || session.stop)
			throw new Error(
				"Managed runtime session unavailable in this owning scope",
			);
		session.current();
		return session;
	}
	describe(owner: InspectorOwner, id: string) {
		const s = this.owned(owner, id);
		return { ...s.target, runtimeSessionId: id, expiresAt: s.expiresAt };
	}
	private send(
		s: ManagedSession,
		method: string,
		params: Record<string, unknown> = {},
		cleanup = false,
	) {
		if (
			(s.stop && !cleanup) ||
			s.nextId >= (cleanup ? 128 : 125) ||
			s.socket.readyState !== WebSocket.OPEN
		)
			return Promise.reject(
				new Error("Inspector protocol budget exhausted or socket closed"),
			);
		const id = ++s.nextId;
		return new Promise<Record<string, unknown>>((resolve, reject) => {
			const timer = setTimeout(
				() => {
					s.pending.delete(id);
					reject(new Error("Bounded Inspector request timed out"));
				},
				cleanup ? 1000 : 2000,
			);
			s.pending.set(id, { resolve, reject, timer });
			s.socket.send(JSON.stringify({ id, method, params }), (error) => {
				if (error) {
					const pending = s.pending.get(id);
					if (pending) {
						clearTimeout(pending.timer);
						s.pending.delete(id);
						pending.reject(new Error("Inspector request transport failed"));
					}
				}
			});
		});
	}
	async attach(
		owner: InspectorOwner,
		target: ManagedInspectorTarget,
		current: () => void,
		signal: AbortSignal,
	) {
		if (
			!Number.isInteger(target.lifetimeMs) ||
			target.lifetimeMs < 1000 ||
			target.lifetimeMs > 120000
		)
			throw new Error("Managed session lifetime must be 1–120 seconds");
		owner = { ...owner, workspace: realpathSync.native(owner.workspace) };
		current();
		await this.identity(target, signal);
		current();
		const ownerKey = key(owner);
		if (
			this.sessions.size >= 2 ||
			[...this.sessions.values()].some((s) => s.owner === ownerKey)
		)
			throw new Error("Managed Inspector session concurrency budget exhausted");
		let resolveClosed!: () => void;
		const closed = new Promise<void>((resolve) => {
			resolveClosed = resolve;
		});
		const socket = new WebSocket(target.endpoint, {
			maxPayload: 1024 * 1024,
			handshakeTimeout: 2500,
			followRedirects: false,
		});
		const s: ManagedSession = {
			id: randomUUID(),
			owner: ownerKey,
			target: { ...target },
			socket,
			scriptId: "",
			breakpoints: new Set(),
			enabled: false,
			busy: false,
			profilerEnabled: false,
			profiling: false,
			nextId: 0,
			messages: 0,
			bytes: 0,
			pending: new Map(),
			current,
			closed,
			resolveClosed,
			expiresAt: new Date(Date.now() + target.lifetimeMs).toISOString(),
		};
		this.sessions.set(s.id, s);
		const scriptIds = new Set<string>();
		const abort = () => {
			void this.stop(owner, s.id, "approval-task-cancelled");
		};
		signal.addEventListener("abort", abort, { once: true });
		socket.on("message", (data) => {
			try {
				const text = data.toString();
				s.messages++;
				s.bytes += Buffer.byteLength(text);
				if (s.messages > 1024 || s.bytes > 8 * 1024 * 1024)
					throw new Error("Inspector receive budget exceeded");
				const message = JSON.parse(text) as Record<string, unknown>;
				if (typeof message.id === "number") {
					const pending = s.pending.get(message.id);
					if (!pending) return;
					clearTimeout(pending.timer);
					s.pending.delete(message.id);
					if (message.error)
						pending.reject(
							new Error("Inspector rejected the bounded operation"),
						);
					else
						pending.resolve(
							message.result && typeof message.result === "object"
								? (message.result as Record<string, unknown>)
								: {},
						);
				} else if (message.method === "Debugger.scriptParsed") {
					const p = message.params as Record<string, unknown> | undefined;
					if (
						typeof p?.url !== "string" ||
						typeof p?.scriptId !== "string" ||
						p.scriptId.length > 80
					)
						return;
					let label = p.url;
					try {
						if (label.startsWith("file:")) label = fileURLToPath(label);
					} catch {
						return;
					}
					if (sameInspectorSourcePath(label, target.target))
						scriptIds.add(p.scriptId);
					if (scriptIds.size > 4)
						throw new Error("Ambiguous selected Inspector script labels");
				}
			} catch {
				void this.stop(owner, s.id, "protocol-or-resource-failure");
			}
		});
		socket.on("close", () => {
			s.resolveClosed();
			for (const p of s.pending.values()) {
				clearTimeout(p.timer);
				p.reject(new Error("Inspector socket closed"));
			}
			s.pending.clear();
			if (!s.stop) void this.stop(owner, s.id, "transport-closed");
		});
		socket.on("error", () => {
			void this.stop(owner, s.id, "transport-error");
		});
		try {
			await new Promise<void>((yes, no) => {
				const open = () => {
						cleanup();
						yes();
					},
					error = () => {
						cleanup();
						no(new Error("Inspector attachment failed"));
					},
					cancel = () => {
						cleanup();
						no(new Error("Inspector attachment cancelled"));
					};
				const cleanup = () => {
					socket.off("open", open);
					socket.off("error", error);
					socket.off("close", error);
					signal.removeEventListener("abort", cancel);
				};
				socket.once("open", open);
				socket.once("error", error);
				socket.once("close", error);
				signal.addEventListener("abort", cancel, { once: true });
				if (signal.aborted) cancel();
			});
			signal.throwIfAborted();
			current();
			// Debugger activation/cleanup can pause/resume the target. This is Execute-
			// approved debug control, never advertised as passive observation.
			s.enabled = true;
			await this.send(s, "Debugger.enable", {
				maxScriptsCacheSize: 1024 * 1024,
			});
			const deadline = Date.now() + 2000;
			while (!scriptIds.size && Date.now() < deadline) {
				signal.throwIfAborted();
				await new Promise((r) => setTimeout(r, 25));
			}
			if (scriptIds.size !== 1)
				throw new Error(
					"Exact selected source is absent or ambiguous; no execution will be initiated to discover it",
				);
			const scriptId = [...scriptIds][0]!;
			const source = await this.send(s, "Debugger.getScriptSource", {
				scriptId,
			});
			if (
				typeof source.scriptSource !== "string" ||
				Buffer.byteLength(source.scriptSource) > 1024 * 1024 ||
				digest(source.scriptSource) !== target.expected_sha256
			)
				throw new Error("Loaded script differs from the approved source hash");
			s.scriptId = scriptId;
			await this.identity(target, signal);
			current();
			if (s.stop || Date.now() >= Date.parse(s.expiresAt))
				throw new Error("Managed Inspector lifetime expired during attachment");
			s.expiry = setTimeout(
				() => {
					void this.stop(owner, s.id, "lifetime-expired");
				},
				Math.max(1, Date.parse(s.expiresAt) - Date.now()),
			);
			s.expiry.unref();
			s.modePoll = setInterval(() => {
				try {
					current();
				} catch {
					void this.stop(owner, s.id, "scope-or-mode-changed");
				}
			}, 100);
			s.modePoll.unref();
			return {
				schemaVersion: 1,
				status: "partial",
				runtimeSessionId: s.id,
				provider: "node-inspector-managed",
				pid: target.pid,
				sourceSha256: target.expected_sha256,
				expiresAt: s.expiresAt,
				limitations: [
					"Selected loaded-script hash reconciliation only, not proof of behavior or exclusive debugger ownership.",
					"Debugger activation and cleanup may pause/resume the selected process. This session was independently approved for debug execution control; no evaluate, launch, step or explicit resume is provided.",
					"Node Inspector only; no native/JVM/Android debugger parity. Lifetime expiration, mode changes and cancellation close the managed connection.",
				],
			};
		} catch (error) {
			await this.stop(owner, s.id, "attach-failed");
			throw error;
		} finally {
			signal.removeEventListener("abort", abort);
		}
	}
	private async loadedSource(s: ManagedSession) {
		const source = await this.send(s, "Debugger.getScriptSource", {
			scriptId: s.scriptId,
		});
		if (
			typeof source.scriptSource !== "string" ||
			Buffer.byteLength(source.scriptSource) > 1024 * 1024 ||
			digest(source.scriptSource) !== s.target.expected_sha256
		)
			throw new Error("Loaded script differs from the approved source hash");
	}
	private async operation<T>(
		owner: InspectorOwner,
		id: string,
		signal: AbortSignal,
		work: (s: ManagedSession) => Promise<T>,
	) {
		const s = this.owned(owner, id);
		if (s.busy)
			throw new Error(
				"Managed Inspector session already has an active operation",
			);
		s.busy = true;
		const abort = () => {
			void this.stop(owner, id, "operation-cancelled");
		};
		signal.addEventListener("abort", abort, { once: true });
		try {
			signal.throwIfAborted();
			await this.identity(s.target, signal);
			await this.loadedSource(s);
			s.current();
			const result = await work(s);
			signal.throwIfAborted();
			s.current();
			await this.identity(s.target, signal);
			await this.loadedSource(s);
			if (s.stop)
				throw new Error("Managed Inspector session stopped during operation");
			return result;
		} catch (error) {
			await this.stop(owner, id, "operation-failed");
			throw error;
		} finally {
			s.busy = false;
			signal.removeEventListener("abort", abort);
		}
	}
	async breakpoints(
		owner: InspectorOwner,
		id: string,
		locations: { line: number; column: number }[],
		signal: AbortSignal,
	) {
		return this.operation(owner, id, signal, async (s) => {
			if (
				!locations.length ||
				locations.length > 8 ||
				s.breakpoints.size + locations.length > 8 ||
				locations.some(
					(p) =>
						!Number.isInteger(p.line) ||
						p.line < 0 ||
						p.line > 100000 ||
						!Number.isInteger(p.column) ||
						p.column < 0 ||
						p.column > 4096,
				)
			)
				throw new Error("Scoped breakpoint budget or locations invalid");
			const actual: { line: number; column: number }[] = [];
			for (const location of locations) {
				signal.throwIfAborted();
				const result = await this.send(s, "Debugger.setBreakpoint", {
					location: {
						scriptId: s.scriptId,
						lineNumber: location.line,
						columnNumber: location.column,
					},
				});
				if (
					typeof result.breakpointId !== "string" ||
					result.breakpointId.length > 256
				)
					throw new Error("Breakpoint identity unavailable");
				s.breakpoints.add(result.breakpointId);
				const at = result.actualLocation as Record<string, unknown> | undefined;
				if (
					at?.scriptId !== s.scriptId ||
					typeof at.lineNumber !== "number" ||
					typeof at.columnNumber !== "number"
				)
					throw new Error("Breakpoint resolved outside exact selected script");
				actual.push({ line: at.lineNumber, column: at.columnNumber });
			}
			return {
				schemaVersion: 1,
				status: "partial",
				provider: "node-inspector-scoped-breakpoints",
				runtimeSessionId: id,
				sourceSha256: s.target.expected_sha256,
				locations: actual,
				activeBreakpoints: s.breakpoints.size,
				limitations: [
					"Zero-based locations in the exact hash-reconciled script only; no conditions, logpoint expressions, evaluation or automatic continuation.",
					"Breakpoints can pause target execution until cleanup; attachment explicitly authorized debug execution control. OS/process state is shared with other Inspector clients.",
				],
			};
		});
	}
	async sample(
		owner: InspectorOwner,
		id: string,
		durationMs: number,
		signal: AbortSignal,
	) {
		if (!Number.isInteger(durationMs) || durationMs < 200 || durationMs > 2000)
			throw new Error("CPU sampling duration must be 200–2000 ms");
		return this.operation(owner, id, signal, async (s) => {
			s.profilerEnabled = true;
			await this.send(s, "Profiler.enable");
			await this.send(s, "Profiler.setSamplingInterval", { interval: 1000 });
			s.profiling = true;
			await this.send(s, "Profiler.start");
			await new Promise<void>((yes, no) => {
				const timer = setTimeout(() => {
					signal.removeEventListener("abort", abort);
					yes();
				}, durationMs);
				const abort = () => {
					clearTimeout(timer);
					signal.removeEventListener("abort", abort);
					no(new Error("CPU sampling cancelled"));
				};
				signal.addEventListener("abort", abort, { once: true });
				if (signal.aborted) abort();
			});
			const result = await this.send(s, "Profiler.stop");
			s.profiling = false;
			await this.send(s, "Profiler.disable");
			s.profilerEnabled = false;
			const profile = result.profile as Record<string, unknown> | undefined;
			if (
				!profile ||
				!Array.isArray(profile.nodes) ||
				!Array.isArray(profile.samples)
			)
				throw new Error("CPU sampling profile unavailable");
			const nodes = profile.nodes as {
				id: number;
				callFrame?: {
					scriptId?: string;
					functionName?: string;
					lineNumber?: number;
					columnNumber?: number;
				};
			}[];
			const allowed = new Map<
				number,
				{
					nodeId: number;
					functionNameHash: string;
					line: number;
					column: number;
				}
			>();
			for (const n of nodes.slice(0, 4096))
				if (
					n.callFrame?.scriptId === s.scriptId &&
					allowed.size < 128 &&
					Number.isSafeInteger(n.id) &&
					typeof n.callFrame.lineNumber === "number" &&
					typeof n.callFrame.columnNumber === "number"
				)
					allowed.set(n.id, {
						nodeId: n.id,
						functionNameHash: digest(
							String(n.callFrame.functionName ?? "").slice(0, 4096),
						),
						line: n.callFrame.lineNumber,
						column: n.callFrame.columnNumber,
					});
			const selectedSamples = profile.samples.filter(
				(n) => typeof n === "number" && allowed.has(n),
			);
			const samples = selectedSamples.slice(0, 256);
			return {
				schemaVersion: 1,
				status: "partial",
				provider: "v8-cpu-sampling-selected-script",
				runtimeSessionId: id,
				durationMs,
				sourceSha256: s.target.expected_sha256,
				nodes: [...allowed.values()],
				samples,
				truncated:
					nodes.length > 4096 ||
					nodes.filter((n) => n.callFrame?.scriptId === s.scriptId).length >
						128 ||
					selectedSamples.length > 256,
				limitations: [
					"Statistical CPU samples, NOT a complete execution trace, chronological call log or proof a non-sampled function did not execute.",
					"Only selected-script nodes/samples retained; unrelated scripts/paths/URLs and function-name plaintext excluded. Engine output is untrusted data.",
					"Inspector profiler state can be shared with other debugger clients; no claim of exclusive engine ownership or native/JVM/Android parity.",
				],
			};
		});
	}
	async stopAll(reason = "sidecar-shutdown") {
		return Promise.allSettled(
			[...this.sessions.values()].map((session) => {
				const [sessionId, workspace] = JSON.parse(session.owner) as [
					string,
					string,
				];
				return this.stop({ sessionId, workspace }, session.id, reason);
			}),
		);
	}
	async stop(owner: InspectorOwner, id: string, reason = "requested") {
		const ownerKey = key(owner),
			s = this.sessions.get(id);
		if (!s) {
			const saved = this.closed.get(id);
			if (saved?.owner !== ownerKey)
				throw new Error(
					"Managed runtime session unavailable in this owning scope",
				);
			return saved.receipt;
		}
		if (s.owner !== ownerKey)
			throw new Error(
				"Managed runtime session unavailable in this owning scope",
			);
		if (s.stop) return s.stop;
		s.stop = (async () => {
			if (s.expiry) clearTimeout(s.expiry);
			if (s.modePoll) clearInterval(s.modePoll);
			let protocolCleanupConfirmed = false;
			try {
				if (s.socket.readyState === WebSocket.OPEN) {
					let complete = true;
					for (const method of [
						...(s.profiling ? ["Profiler.stop"] : []),
						...(s.profilerEnabled ? ["Profiler.disable"] : []),
						...(s.enabled ? ["Debugger.disable"] : []),
					]) {
						try {
							await this.send(s, method, {}, true);
						} catch {
							complete = false;
						}
					}
					protocolCleanupConfirmed = complete;
				}
			} finally {
				try {
					if (s.socket.readyState === WebSocket.CONNECTING)
						s.socket.terminate();
					else s.socket.close();
				} catch {
					s.socket.terminate();
				}
			}
			let timer: ReturnType<typeof setTimeout> | undefined;
			await Promise.race([
				s.closed,
				new Promise<void>((r) => {
					timer = setTimeout(() => {
						s.socket.terminate();
						r();
					}, 1000);
				}),
			]);
			if (timer) clearTimeout(timer);
			const receipt = {
				schemaVersion: 1,
				status:
					protocolCleanupConfirmed && s.socket.readyState === WebSocket.CLOSED
						? "completed"
						: "partial",
				provider: "node-inspector-managed-cleanup",
				runtimeSessionId: id,
				stopReason: reason,
				transportClosed: s.socket.readyState === WebSocket.CLOSED,
				protocolCleanupConfirmed,
				stoppedAt: new Date().toISOString(),
				limitations: [
					"Owned profiler stop/disable and debugger disable are attempted within a four-second cleanup budget. No target kill or explicit resume. Debugger disable/disconnect can resume a paused target as disclosed at attach approval.",
					"Transport closure is not proof of process exit, exact subsequent execution state or cleanup of another Inspector client's breakpoints.",
				],
			};
			this.sessions.delete(id);
			this.closed.set(id, { owner: ownerKey, receipt });
			while (this.closed.size > 128)
				this.closed.delete(this.closed.keys().next().value!);
			return receipt;
		})();
		return s.stop;
	}
}

export const managedInspectorSessions = new ManagedInspectorSessions();
