import {
	type ChildProcessWithoutNullStreams,
	type SpawnOptionsWithoutStdio,
	spawn,
} from "node:child_process";
import { randomUUID } from "node:crypto";
import { StringDecoder } from "node:string_decoder";
import {
	type ProcessStartTokenProbeResult,
	probeProcessStartTokenAsync,
} from "../../../runtime/process-start-token";
import {
	createStreamingSecretRedactor,
	prepareProcessEnvironment,
	redactSensitiveText,
	type StreamingSecretRedactor,
} from "./process-environment-policy";

export const DEFAULT_MAX_PROCESS_SESSIONS = 64;
export const DEFAULT_MAX_PROCESS_SESSIONS_PER_OWNER = 8;
export const DEFAULT_PROCESS_OUTPUT_BYTES = 1024 * 1024;
export const DEFAULT_COMPLETED_PROCESS_RETENTION_MS = 60 * 60 * 1_000;

export type ProcessSessionState =
	| "starting"
	| "running"
	| "exited"
	| "failed"
	| "cancelled";

export type ProcessSessionOutputStream = "stdout" | "stderr";
export type ProcessSessionSignal = "interrupt" | "terminate" | "kill";

export interface ProcessSessionStartOptions {
	ownerSessionId: string;
	executable: string;
	args?: string[];
	cwd: string;
	env?: Record<string, string>;
	toolCallId?: string;
	interactive?: boolean;
	columns?: number;
	rows?: number;
}

export interface ProcessSessionSnapshot {
	processId: string;
	ownerSessionId: string;
	toolCallId?: string;
	state: ProcessSessionState;
	pid: number | null;
	processStartToken?: string;
	executable: string;
	args: string[];
	cwd: string;
	startedAtMs: number;
	completedAtMs?: number;
	exitCode?: number | null;
	exitSignal?: NodeJS.Signals | null;
	error?: string;
	interactive: boolean;
	terminalColumns?: number;
	terminalRows?: number;
	latestCursor: number;
	droppedOutputBytes: number;
}

export interface ProcessSessionOutputChunk {
	cursor: number;
	stream: ProcessSessionOutputStream;
	text: string;
}

export interface ProcessSessionReadResult {
	session: ProcessSessionSnapshot;
	chunks: ProcessSessionOutputChunk[];
	nextCursor: number;
	truncated: boolean;
	droppedOutputBytes: number;
}

export interface ProcessSessionManagerOptions {
	maxSessions?: number;
	maxSessionsPerOwner?: number;
	maxOutputBytes?: number;
	completedRetentionMs?: number;
	/**
	 * Whether sessions inherit non-sensitive variables from the host.
	 * @default true
	 */
	inheritEnvironment?: boolean;
	/**
	 * Exact sensitive variable names approved by the host. Values remain
	 * redacted from all retained output.
	 */
	allowedSensitiveEnvironmentVariables?: string[];
	processStartTokenProbe?: (
		pid: number,
	) => ProcessStartTokenProbeResult | Promise<ProcessStartTokenProbeResult>;
	spawnProcess?: (
		command: string,
		args: readonly string[],
		options: SpawnOptionsWithoutStdio,
	) => ChildProcessWithoutNullStreams;
	spawnTerminalProcess?: ProcessSessionTerminalSpawner;
}

export interface ProcessSessionTerminal {
	readonly closed: boolean;
	write(data: string | Uint8Array): number;
	resize(columns: number, rows: number): void;
	close(): void;
}

export interface ProcessSessionTerminalProcess {
	readonly pid: number;
	readonly terminal: ProcessSessionTerminal;
	readonly exited: Promise<number>;
	readonly exitCode: number | null;
	readonly signalCode: NodeJS.Signals | null;
	kill(signal?: NodeJS.Signals): void;
}

export type ProcessSessionTerminalSpawner = (
	command: string,
	args: readonly string[],
	options: {
		cwd: string;
		env: Record<string, string | undefined>;
		columns: number;
		rows: number;
		onData: (data: Uint8Array) => void;
	},
) => ProcessSessionTerminalProcess;

interface BunTerminalRuntime {
	Terminal: new (options: {
		cols: number;
		rows: number;
		name: string;
		data: (terminal: ProcessSessionTerminal, data: Uint8Array) => void;
	}) => ProcessSessionTerminal;
	spawn(
		command: string[],
		options: {
			cwd: string;
			env: Record<string, string | undefined>;
			detached: boolean;
			windowsHide: boolean;
			terminal: ProcessSessionTerminal;
		},
	): {
		pid: number;
		exited: Promise<number>;
		exitCode: number | null;
		signalCode: NodeJS.Signals | null;
		kill(signal?: NodeJS.Signals): void;
	};
}

type StoredOutputChunk = ProcessSessionOutputChunk & { bytes: number };

interface ManagedProcessSession {
	snapshot: ProcessSessionSnapshot;
	child?: ChildProcessWithoutNullStreams;
	terminalProcess?: ProcessSessionTerminalProcess;
	output: BoundedProcessOutput;
	stdoutDecoder: StringDecoder;
	stderrDecoder: StringDecoder;
	stdoutRedactor: StreamingSecretRedactor;
	stderrRedactor: StreamingSecretRedactor;
	secretValues: string[];
	cleanupTimer?: NodeJS.Timeout;
	cancelRequested: boolean;
	settled: boolean;
}

function spawnBunTerminalProcess(
	command: string,
	args: readonly string[],
	options: Parameters<ProcessSessionTerminalSpawner>[2],
): ProcessSessionTerminalProcess {
	const bun = (globalThis as { Bun?: BunTerminalRuntime }).Bun;
	if (!bun || typeof bun.Terminal !== "function") {
		throw new Error(
			"Interactive process sessions require Bun 1.3.14 or newer with Bun.Terminal support",
		);
	}
	const terminal = new bun.Terminal({
		cols: options.columns,
		rows: options.rows,
		name: "xterm-256color",
		data: (_terminal, data) => options.onData(data),
	});
	try {
		const child = bun.spawn([command, ...args], {
			cwd: options.cwd,
			env: options.env,
			detached: process.platform !== "win32",
			windowsHide: true,
			terminal,
		});
		return {
			pid: child.pid,
			terminal,
			exited: child.exited,
			get exitCode() {
				return child.exitCode;
			},
			get signalCode() {
				return child.signalCode;
			},
			kill: (signal) => child.kill(signal),
		};
	} catch (error) {
		terminal.close();
		throw error;
	}
}

function positiveInteger(
	value: number | undefined,
	fallback: number,
	minimum = 1,
): number {
	return typeof value === "number" && Number.isFinite(value)
		? Math.max(minimum, Math.floor(value))
		: fallback;
}

function utf8Bytes(text: string): number {
	return Buffer.byteLength(text, "utf8");
}

function takeUtf8Prefix(text: string, maxBytes: number): string {
	if (maxBytes <= 0) return "";
	let result = "";
	let bytes = 0;
	for (const character of text) {
		const characterBytes = utf8Bytes(character);
		if (bytes + characterBytes > maxBytes) break;
		result += character;
		bytes += characterBytes;
	}
	return result;
}

function takeUtf8Suffix(text: string, maxBytes: number): string {
	if (maxBytes <= 0) return "";
	const characters = Array.from(text);
	let result = "";
	let bytes = 0;
	for (let index = characters.length - 1; index >= 0; index -= 1) {
		const character = characters[index];
		const characterBytes = utf8Bytes(character);
		if (bytes + characterBytes > maxBytes) break;
		result = character + result;
		bytes += characterBytes;
	}
	return result;
}

/**
 * Keeps an immutable head plus a rolling tail. Cursors remain monotonic even
 * when middle output is evicted, allowing readers to detect an omission
 * instead of silently treating a truncated transcript as complete.
 */
class BoundedProcessOutput {
	private readonly headLimit: number;
	private readonly tailLimit: number;
	private readonly head: StoredOutputChunk[] = [];
	private readonly tail: StoredOutputChunk[] = [];
	private headBytes = 0;
	private tailBytes = 0;
	private latestCursor = 0;
	private highestDroppedCursor = 0;
	private droppedBytes = 0;

	constructor(maxBytes: number) {
		this.headLimit = Math.ceil(maxBytes / 2);
		this.tailLimit = Math.max(1, maxBytes - this.headLimit);
	}

	append(stream: ProcessSessionOutputStream, text: string): void {
		if (!text) return;
		const headRoom = this.headLimit - this.headBytes;
		if (headRoom > 0) {
			const prefix = takeUtf8Prefix(text, headRoom);
			if (prefix) {
				this.pushHead(stream, prefix);
				text = text.slice(prefix.length);
			}
		}
		if (text) this.pushTail(stream, text);
	}

	read(cursor: number): {
		chunks: ProcessSessionOutputChunk[];
		nextCursor: number;
		truncated: boolean;
		droppedOutputBytes: number;
	} {
		const normalizedCursor = Number.isSafeInteger(cursor)
			? Math.max(0, cursor)
			: 0;
		const chunks = [...this.head, ...this.tail]
			.filter((chunk) => chunk.cursor > normalizedCursor)
			.sort((left, right) => left.cursor - right.cursor)
			.map(({ cursor: chunkCursor, stream, text }) => ({
				cursor: chunkCursor,
				stream,
				text,
			}));
		return {
			chunks,
			nextCursor: this.latestCursor,
			truncated: this.highestDroppedCursor > normalizedCursor,
			droppedOutputBytes: this.droppedBytes,
		};
	}

	get cursor(): number {
		return this.latestCursor;
	}

	get omittedBytes(): number {
		return this.droppedBytes;
	}

	private pushHead(stream: ProcessSessionOutputStream, text: string): void {
		const bytes = utf8Bytes(text);
		this.head.push({
			cursor: ++this.latestCursor,
			stream,
			text,
			bytes,
		});
		this.headBytes += bytes;
	}

	private pushTail(stream: ProcessSessionOutputStream, text: string): void {
		const cursor = ++this.latestCursor;
		const originalBytes = utf8Bytes(text);
		if (originalBytes > this.tailLimit) {
			const retained = takeUtf8Suffix(text, this.tailLimit);
			const retainedBytes = utf8Bytes(retained);
			this.droppedBytes += originalBytes - retainedBytes;
			this.highestDroppedCursor = cursor;
			text = retained;
		}
		const bytes = utf8Bytes(text);
		this.tail.push({ cursor, stream, text, bytes });
		this.tailBytes += bytes;
		while (this.tailBytes > this.tailLimit && this.tail.length > 1) {
			const removed = this.tail.shift();
			if (!removed) break;
			this.tailBytes -= removed.bytes;
			this.droppedBytes += removed.bytes;
			this.highestDroppedCursor = Math.max(
				this.highestDroppedCursor,
				removed.cursor,
			);
		}
	}
}

/**
 * Host-scoped lifecycle service for resumable child processes.
 *
 * Pipe-based execution remains the default. Explicit interactive sessions use
 * Bun.Terminal, backed by a Unix PTY or Windows ConPTY in Bun 1.3.14+.
 */
export class ProcessSessionManager {
	private readonly sessions = new Map<string, ManagedProcessSession>();
	private readonly maxSessions: number;
	private readonly maxSessionsPerOwner: number;
	private readonly maxOutputBytes: number;
	private readonly completedRetentionMs: number;
	private readonly inheritEnvironment: boolean;
	private readonly allowedSensitiveEnvironmentVariables: string[];
	private readonly processStartTokenProbe: NonNullable<
		ProcessSessionManagerOptions["processStartTokenProbe"]
	>;
	private readonly spawnProcess: NonNullable<
		ProcessSessionManagerOptions["spawnProcess"]
	>;
	private readonly spawnTerminalProcess: ProcessSessionTerminalSpawner;

	constructor(options: ProcessSessionManagerOptions = {}) {
		this.maxSessions = positiveInteger(
			options.maxSessions,
			DEFAULT_MAX_PROCESS_SESSIONS,
		);
		this.maxSessionsPerOwner = positiveInteger(
			options.maxSessionsPerOwner,
			DEFAULT_MAX_PROCESS_SESSIONS_PER_OWNER,
		);
		this.maxOutputBytes = positiveInteger(
			options.maxOutputBytes,
			DEFAULT_PROCESS_OUTPUT_BYTES,
			2,
		);
		this.completedRetentionMs = positiveInteger(
			options.completedRetentionMs,
			DEFAULT_COMPLETED_PROCESS_RETENTION_MS,
			0,
		);
		this.inheritEnvironment = options.inheritEnvironment !== false;
		this.allowedSensitiveEnvironmentVariables = [
			...(options.allowedSensitiveEnvironmentVariables ?? []),
		];
		this.processStartTokenProbe =
			options.processStartTokenProbe ?? probeProcessStartTokenAsync;
		this.spawnProcess =
			options.spawnProcess ??
			((command, args, spawnOptions) =>
				spawn(command, args, {
					...spawnOptions,
					stdio: ["pipe", "pipe", "pipe"],
				}));
		this.spawnTerminalProcess =
			options.spawnTerminalProcess ?? spawnBunTerminalProcess;
	}

	async start(
		options: ProcessSessionStartOptions,
	): Promise<ProcessSessionSnapshot> {
		if (!options.ownerSessionId) {
			throw new Error("ownerSessionId is required");
		}
		if (!options.executable) {
			throw new Error("executable is required");
		}
		this.assertCapacity(options.ownerSessionId);

		const processId = randomUUID();
		const startedAtMs = Date.now();
		const args = [...(options.args ?? [])];
		const preparedEnvironment = prepareProcessEnvironment({
			overrides: options.env,
			inheritEnvironment: this.inheritEnvironment,
			allowedSensitiveEnvironmentVariables:
				this.allowedSensitiveEnvironmentVariables,
		});
		const interactive = options.interactive === true;
		const terminalColumns = positiveInteger(options.columns, 80);
		const terminalRows = positiveInteger(options.rows, 24);
		const output = new BoundedProcessOutput(this.maxOutputBytes);
		const stdoutDecoder = new StringDecoder("utf8");
		const stderrDecoder = new StringDecoder("utf8");
		const stdoutRedactor = createStreamingSecretRedactor(
			preparedEnvironment.secretValues,
		);
		const stderrRedactor = createStreamingSecretRedactor(
			preparedEnvironment.secretValues,
		);
		let managed: ManagedProcessSession | undefined;
		const pendingTerminalData: Uint8Array[] = [];
		const appendTerminalData = (data: Uint8Array): void => {
			if (!managed) {
				pendingTerminalData.push(Uint8Array.from(data));
				return;
			}
			this.appendOutput(
				managed,
				"stdout",
				managed.stdoutRedactor.push(
					managed.stdoutDecoder.write(Buffer.from(data)),
				),
			);
		};
		const terminalProcess = interactive
			? this.spawnTerminalProcess(options.executable, args, {
					cwd: options.cwd,
					env: preparedEnvironment.environment,
					columns: terminalColumns,
					rows: terminalRows,
					onData: appendTerminalData,
				})
			: undefined;
		const child = terminalProcess
			? undefined
			: this.spawnProcess(options.executable, args, {
					cwd: options.cwd,
					env: preparedEnvironment.environment,
					detached: process.platform !== "win32",
					windowsHide: true,
					shell: false,
				});
		managed = {
			snapshot: {
				processId,
				ownerSessionId: options.ownerSessionId,
				...(options.toolCallId ? { toolCallId: options.toolCallId } : {}),
				state: "starting",
				pid: terminalProcess?.pid ?? child?.pid ?? null,
				executable: options.executable,
				args,
				cwd: options.cwd,
				startedAtMs,
				interactive,
				...(interactive
					? {
							terminalColumns,
							terminalRows,
						}
					: {}),
				latestCursor: 0,
				droppedOutputBytes: 0,
			},
			child,
			terminalProcess,
			output,
			stdoutDecoder,
			stderrDecoder,
			stdoutRedactor,
			stderrRedactor,
			secretValues: preparedEnvironment.secretValues,
			cancelRequested: false,
			settled: false,
		};
		this.sessions.set(processId, managed);
		this.bindLifecycle(managed);
		for (const data of pendingTerminalData) appendTerminalData(data);

		if (child) {
			await new Promise<void>((resolve, reject) => {
				const onSpawn = () => {
					child.removeListener("error", onError);
					resolve();
				};
				const onError = (error: Error) => {
					child.removeListener("spawn", onSpawn);
					reject(error);
				};
				child.once("spawn", onSpawn);
				child.once("error", onError);
			}).catch((error: unknown) => {
				// bindLifecycle records the durable failure state before this rejection.
				throw error;
			});
		}

		if (!managed.settled) managed.snapshot.state = "running";
		const pid = managed.snapshot.pid;
		if (pid) {
			try {
				const identity = await this.processStartTokenProbe(pid);
				if (identity.status === "found") {
					managed.snapshot.processStartToken = identity.token;
				}
			} catch {
				// Identity metadata is best effort while the live ChildProcess object
				// remains authoritative. PID-only recovery is never attempted.
			}
		}
		return this.copySnapshot(managed);
	}

	list(ownerSessionId: string): ProcessSessionSnapshot[] {
		return [...this.sessions.values()]
			.filter((session) => session.snapshot.ownerSessionId === ownerSessionId)
			.map((session) => this.copySnapshot(session));
	}

	get(
		ownerSessionId: string,
		processId: string,
	): ProcessSessionSnapshot | undefined {
		const session = this.getOwned(ownerSessionId, processId);
		return session ? this.copySnapshot(session) : undefined;
	}

	read(
		ownerSessionId: string,
		processId: string,
		cursor = 0,
	): ProcessSessionReadResult {
		const session = this.requireOwned(ownerSessionId, processId);
		const output = session.output.read(cursor);
		return {
			session: this.copySnapshot(session),
			...output,
		};
	}

	async writeStdin(
		ownerSessionId: string,
		processId: string,
		input: string,
	): Promise<void> {
		const session = this.requireActive(ownerSessionId, processId);
		if (session.terminalProcess) {
			session.terminalProcess.terminal.write(input);
			return;
		}
		const child = session.child;
		if (!child) throw new Error(`Process session ${processId} has no stdin`);
		if (!child.stdin.writable) {
			throw new Error(`Process session ${processId} stdin is closed`);
		}
		await new Promise<void>((resolve, reject) => {
			child.stdin.write(input, "utf8", (error) => {
				if (error) reject(error);
				else resolve();
			});
		});
	}

	resize(
		ownerSessionId: string,
		processId: string,
		columns: number,
		rows: number,
	): ProcessSessionSnapshot {
		const session = this.requireActive(ownerSessionId, processId);
		if (!session.terminalProcess) {
			throw new Error(`Process session ${processId} is not interactive`);
		}
		const normalizedColumns = positiveInteger(columns, 80);
		const normalizedRows = positiveInteger(rows, 24);
		session.terminalProcess.terminal.resize(normalizedColumns, normalizedRows);
		session.snapshot.terminalColumns = normalizedColumns;
		session.snapshot.terminalRows = normalizedRows;
		return this.copySnapshot(session);
	}

	async signal(
		ownerSessionId: string,
		processId: string,
		signal: ProcessSessionSignal,
	): Promise<void> {
		const session = this.requireActive(ownerSessionId, processId);
		if (signal === "interrupt") {
			if (session.terminalProcess) {
				session.terminalProcess.terminal.write("\u0003");
				if (process.platform !== "win32" && session.snapshot.pid) {
					try {
						process.kill(-session.snapshot.pid, "SIGINT");
					} catch {
						session.terminalProcess.kill("SIGINT");
					}
				}
				return;
			}
			session.cancelRequested = true;
			if (!session.child?.kill("SIGINT")) {
				throw new Error(`Could not interrupt process session ${processId}`);
			}
			return;
		}
		session.cancelRequested = true;
		await this.killProcessTree(
			session,
			signal === "kill" ? "SIGKILL" : "SIGTERM",
		);
	}

	close(ownerSessionId: string, processId: string): boolean {
		const session = this.requireOwned(ownerSessionId, processId);
		if (!session.settled) {
			throw new Error(`Process session ${processId} is still active`);
		}
		if (session.cleanupTimer) clearTimeout(session.cleanupTimer);
		return this.sessions.delete(processId);
	}

	async dispose(): Promise<void> {
		const active = [...this.sessions.values()].filter(
			(session) => !session.settled,
		);
		await Promise.allSettled(
			active.map(async (session) => {
				session.cancelRequested = true;
				await this.killProcessTree(session, "SIGKILL");
			}),
		);
		for (const session of this.sessions.values()) {
			if (session.cleanupTimer) clearTimeout(session.cleanupTimer);
		}
		this.sessions.clear();
	}

	private bindLifecycle(session: ManagedProcessSession): void {
		const child = session.child;
		if (child) {
			child.stdout.on("data", (data: Buffer) => {
				this.appendOutput(
					session,
					"stdout",
					session.stdoutRedactor.push(session.stdoutDecoder.write(data)),
				);
			});
			child.stderr.on("data", (data: Buffer) => {
				this.appendOutput(
					session,
					"stderr",
					session.stderrRedactor.push(session.stderrDecoder.write(data)),
				);
			});
			child.once("error", (error) => {
				session.snapshot.error = redactSensitiveText(
					error.message,
					session.secretValues,
				);
				this.complete(session, "failed", null, null);
			});
			child.once("close", (exitCode, exitSignal) => {
				this.flushOutput(session, true);
				this.complete(
					session,
					session.cancelRequested ? "cancelled" : "exited",
					exitCode,
					exitSignal,
				);
			});
			return;
		}
		const terminalProcess = session.terminalProcess;
		if (!terminalProcess) return;
		void terminalProcess.exited.then(
			(exitCode) => {
				this.flushOutput(session, false);
				this.complete(
					session,
					session.cancelRequested ? "cancelled" : "exited",
					exitCode,
					terminalProcess.signalCode,
				);
			},
			(error: unknown) => {
				session.snapshot.error = redactSensitiveText(
					error instanceof Error ? error.message : String(error),
					session.secretValues,
				);
				this.flushOutput(session, false);
				this.complete(session, "failed", null, terminalProcess.signalCode);
			},
		);
	}

	private appendOutput(
		session: ManagedProcessSession,
		stream: ProcessSessionOutputStream,
		text: string,
	): void {
		session.output.append(stream, text);
		session.snapshot.latestCursor = session.output.cursor;
		session.snapshot.droppedOutputBytes = session.output.omittedBytes;
	}

	private flushOutput(
		session: ManagedProcessSession,
		includeStderr: boolean,
	): void {
		this.appendOutput(
			session,
			"stdout",
			session.stdoutRedactor.push(session.stdoutDecoder.end()) +
				session.stdoutRedactor.finish(),
		);
		if (includeStderr) {
			this.appendOutput(
				session,
				"stderr",
				session.stderrRedactor.push(session.stderrDecoder.end()) +
					session.stderrRedactor.finish(),
			);
		}
		session.secretValues = [];
	}

	private complete(
		session: ManagedProcessSession,
		state: Extract<ProcessSessionState, "exited" | "failed" | "cancelled">,
		exitCode: number | null,
		exitSignal: NodeJS.Signals | null,
	): void {
		if (session.settled) return;
		session.settled = true;
		session.snapshot.state = state;
		session.snapshot.completedAtMs = Date.now();
		session.snapshot.exitCode = exitCode;
		session.snapshot.exitSignal = exitSignal;
		session.snapshot.latestCursor = session.output.cursor;
		session.snapshot.droppedOutputBytes = session.output.omittedBytes;
		session.child?.stdin.destroy();
		if (session.terminalProcess && !session.terminalProcess.terminal.closed) {
			session.terminalProcess.terminal.close();
		}
		session.cleanupTimer = setTimeout(() => {
			this.sessions.delete(session.snapshot.processId);
		}, this.completedRetentionMs);
		session.cleanupTimer.unref();
	}

	private assertCapacity(ownerSessionId: string): void {
		const active = [...this.sessions.values()].filter(
			(session) => !session.settled,
		);
		if (active.length >= this.maxSessions) {
			throw new Error(
				`Process session limit reached (${this.maxSessions} active sessions)`,
			);
		}
		const ownerActive = active.filter(
			(session) => session.snapshot.ownerSessionId === ownerSessionId,
		).length;
		if (ownerActive >= this.maxSessionsPerOwner) {
			throw new Error(
				`Process session limit reached for owner (${this.maxSessionsPerOwner} active sessions)`,
			);
		}
	}

	private getOwned(
		ownerSessionId: string,
		processId: string,
	): ManagedProcessSession | undefined {
		const session = this.sessions.get(processId);
		return session?.snapshot.ownerSessionId === ownerSessionId
			? session
			: undefined;
	}

	private requireOwned(
		ownerSessionId: string,
		processId: string,
	): ManagedProcessSession {
		const session = this.getOwned(ownerSessionId, processId);
		if (!session) throw new Error(`Process session ${processId} was not found`);
		return session;
	}

	private requireActive(
		ownerSessionId: string,
		processId: string,
	): ManagedProcessSession {
		const session = this.requireOwned(ownerSessionId, processId);
		if (session.settled) {
			throw new Error(`Process session ${processId} is not running`);
		}
		return session;
	}

	private copySnapshot(session: ManagedProcessSession): ProcessSessionSnapshot {
		return {
			...session.snapshot,
			args: [...session.snapshot.args],
		};
	}

	private async killProcessTree(
		session: ManagedProcessSession,
		signal: Extract<NodeJS.Signals, "SIGTERM" | "SIGKILL">,
	): Promise<void> {
		const pid = session.snapshot.pid;
		if (!pid) return;
		const killDirect = (): boolean => {
			if (session.child) return session.child.kill(signal);
			if (session.terminalProcess) {
				session.terminalProcess.kill(signal);
				return true;
			}
			return false;
		};
		if (process.platform !== "win32") {
			try {
				process.kill(-pid, signal);
				return;
			} catch {
				if (killDirect()) return;
				throw new Error(`Could not signal process tree ${pid}`);
			}
		}
		await new Promise<void>((resolve) => {
			const killer = spawn("taskkill.exe", ["/PID", String(pid), "/T", "/F"], {
				stdio: "ignore",
				shell: false,
				windowsHide: true,
			});
			let settled = false;
			const finish = () => {
				if (settled) return;
				settled = true;
				clearTimeout(watchdog);
				resolve();
			};
			const watchdog = setTimeout(() => {
				killer.kill();
				killDirect();
				finish();
			}, 5_000);
			killer.once("error", () => {
				killDirect();
				finish();
			});
			killer.once("close", finish);
		});
	}
}
