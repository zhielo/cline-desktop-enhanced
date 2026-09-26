import { describe, expect, it } from "vitest";
import {
	ProcessSessionManager,
	type ProcessSessionSnapshot,
	type ProcessSessionTerminalProcess,
} from "./process-session-manager";

const OWNER = "test-owner";

async function waitForCompletion(
	manager: ProcessSessionManager,
	processId: string,
	timeoutMs = 5_000,
): Promise<ProcessSessionSnapshot> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		const snapshot = manager.get(OWNER, processId);
		if (
			snapshot &&
			["exited", "failed", "cancelled"].includes(snapshot.state)
		) {
			return snapshot;
		}
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
	throw new Error(`Process session ${processId} did not complete`);
}

describe("ProcessSessionManager", () => {
	it("starts a process with a stable ID and exposes cursor-based output", async () => {
		const manager = new ProcessSessionManager();
		try {
			const started = await manager.start({
				ownerSessionId: OWNER,
				executable: process.execPath,
				args: ["-e", 'console.log("ready")'],
				cwd: process.cwd(),
			});
			expect(started.processId).toBeTruthy();
			expect(started.interactive).toBe(false);

			const completed = await waitForCompletion(manager, started.processId);
			expect(completed.state).toBe("exited");
			expect(completed.exitCode).toBe(0);

			const firstRead = manager.read(OWNER, started.processId);
			expect(firstRead.chunks.map((chunk) => chunk.text).join("")).toContain(
				"ready",
			);
			expect(firstRead.nextCursor).toBeGreaterThan(0);
			expect(
				manager.read(OWNER, started.processId, firstRead.nextCursor).chunks,
			).toEqual([]);
		} finally {
			await manager.dispose();
		}
	});

	it("writes multiple values to stdin without advertising PTY semantics", async () => {
		const manager = new ProcessSessionManager();
		try {
			const started = await manager.start({
				ownerSessionId: OWNER,
				executable: process.execPath,
				args: [
					"-e",
					'process.stdin.setEncoding("utf8"); let value=""; process.stdin.on("data", chunk => { value += chunk; if (value.includes("\\n")) { console.log("echo:" + value.trim()); process.exit(0); } });',
				],
				cwd: process.cwd(),
			});
			await manager.writeStdin(OWNER, started.processId, "hel");
			await manager.writeStdin(OWNER, started.processId, "lo\n");
			await waitForCompletion(manager, started.processId);
			expect(
				manager
					.read(OWNER, started.processId)
					.chunks.map((chunk) => chunk.text)
					.join(""),
			).toContain("echo:hello");
		} finally {
			await manager.dispose();
		}
	});

	it("attaches a real terminal, accepts input, and resizes it", async () => {
		let resolveExit: ((exitCode: number) => void) | undefined;
		let resizedTo: [number, number] | undefined;
		const manager = new ProcessSessionManager({
			processStartTokenProbe: async () => ({ status: "missing" }),
			spawnTerminalProcess: (_command, _args, options) => {
				const exited = new Promise<number>((resolve) => {
					resolveExit = resolve;
				});
				const terminal = {
					closed: false,
					write: (data: string | Uint8Array) => {
						const text =
							typeof data === "string"
								? data
								: Buffer.from(data).toString("utf8");
						options.onData(Buffer.from(`input:${text}`, "utf8"));
						resolveExit?.(0);
						return Buffer.byteLength(text);
					},
					resize: (columns: number, rows: number) => {
						resizedTo = [columns, rows];
					},
					close: () => {},
				};
				queueMicrotask(() =>
					options.onData(Buffer.from("tty:true:true\n", "utf8")),
				);
				return {
					pid: 12345,
					terminal,
					exited,
					exitCode: null,
					signalCode: null,
					kill: () => resolveExit?.(137),
				} satisfies ProcessSessionTerminalProcess;
			},
		});
		try {
			const started = await manager.start({
				ownerSessionId: OWNER,
				executable: process.execPath,
				args: ["-e", "interactive fixture"],
				cwd: process.cwd(),
				interactive: true,
				columns: 90,
				rows: 30,
			});
			expect(started).toMatchObject({
				interactive: true,
				terminalColumns: 90,
				terminalRows: 30,
			});
			expect(manager.resize(OWNER, started.processId, 100, 40)).toMatchObject({
				terminalColumns: 100,
				terminalRows: 40,
			});
			expect(resizedTo).toEqual([100, 40]);
			await manager.writeStdin(OWNER, started.processId, "ping");
			await waitForCompletion(manager, started.processId);
			const result = manager.read(OWNER, started.processId);
			const output = result.chunks.map((chunk) => chunk.text).join("");
			expect(output).toContain("tty:true:true");
			expect(output).toContain("input:ping");
			expect(result.chunks.every((chunk) => chunk.stream === "stdout")).toBe(
				true,
			);
		} finally {
			await manager.dispose();
		}
	});

	it("rejects resize for pipe-based sessions", async () => {
		const manager = new ProcessSessionManager();
		try {
			const started = await manager.start({
				ownerSessionId: OWNER,
				executable: process.execPath,
				args: ["-e", "setTimeout(() => {}, 1000)"],
				cwd: process.cwd(),
			});
			expect(() => manager.resize(OWNER, started.processId, 100, 40)).toThrow(
				"is not interactive",
			);
		} finally {
			await manager.dispose();
		}
	});

	it("filters environment secrets and redacts explicitly granted values", async () => {
		const filteredManager = new ProcessSessionManager();
		try {
			const filtered = await filteredManager.start({
				ownerSessionId: OWNER,
				executable: process.execPath,
				args: [
					"-e",
					"console.log(process.env.TEST_API_KEY ?? 'missing'); console.log(process.env.SAFE_FLAG)",
				],
				cwd: process.cwd(),
				env: {
					TEST_API_KEY: "session-secret-value",
					SAFE_FLAG: "enabled",
				},
			});
			await waitForCompletion(filteredManager, filtered.processId);
			const output = filteredManager
				.read(OWNER, filtered.processId)
				.chunks.map((chunk) => chunk.text)
				.join("");
			expect(output).toContain("missing");
			expect(output).toContain("enabled");
			expect(output).not.toContain("session-secret-value");
		} finally {
			await filteredManager.dispose();
		}

		const grantedManager = new ProcessSessionManager({
			allowedSensitiveEnvironmentVariables: ["TEST_API_KEY"],
		});
		try {
			const granted = await grantedManager.start({
				ownerSessionId: OWNER,
				executable: process.execPath,
				args: ["-e", "console.log(process.env.TEST_API_KEY)"],
				cwd: process.cwd(),
				env: { TEST_API_KEY: "session-secret-value" },
			});
			await waitForCompletion(grantedManager, granted.processId);
			const output = grantedManager
				.read(OWNER, granted.processId)
				.chunks.map((chunk) => chunk.text)
				.join("");
			expect(output).toContain("[REDACTED]");
			expect(output).not.toContain("session-secret-value");
		} finally {
			await grantedManager.dispose();
		}
	});

	it("retains a bounded head and tail and reports omitted output", async () => {
		const manager = new ProcessSessionManager({ maxOutputBytes: 80 });
		try {
			const started = await manager.start({
				ownerSessionId: OWNER,
				executable: process.execPath,
				args: ["-e", 'process.stdout.write("A".repeat(100) + "B".repeat(100))'],
				cwd: process.cwd(),
			});
			await waitForCompletion(manager, started.processId);
			const result = manager.read(OWNER, started.processId);
			const output = result.chunks.map((chunk) => chunk.text).join("");
			expect(Buffer.byteLength(output)).toBeLessThanOrEqual(80);
			expect(output).toMatch(/^A+/);
			expect(output).toMatch(/B+$/);
			expect(result.truncated).toBe(true);
			expect(result.droppedOutputBytes).toBe(120);
		} finally {
			await manager.dispose();
		}
	});

	it("isolates sessions by owner", async () => {
		const manager = new ProcessSessionManager();
		try {
			const started = await manager.start({
				ownerSessionId: OWNER,
				executable: process.execPath,
				args: ["-e", "setTimeout(() => {}, 1000)"],
				cwd: process.cwd(),
			});
			expect(manager.list("different-owner")).toEqual([]);
			expect(manager.get("different-owner", started.processId)).toBeUndefined();
			expect(() => manager.read("different-owner", started.processId)).toThrow(
				"was not found",
			);
		} finally {
			await manager.dispose();
		}
	});

	it("enforces global and per-owner active-session limits", async () => {
		const manager = new ProcessSessionManager({
			maxSessions: 2,
			maxSessionsPerOwner: 1,
		});
		try {
			await manager.start({
				ownerSessionId: OWNER,
				executable: process.execPath,
				args: ["-e", "setTimeout(() => {}, 1000)"],
				cwd: process.cwd(),
			});
			await expect(
				manager.start({
					ownerSessionId: OWNER,
					executable: process.execPath,
					args: ["-e", "setTimeout(() => {}, 1000)"],
					cwd: process.cwd(),
				}),
			).rejects.toThrow("limit reached for owner");
			await manager.start({
				ownerSessionId: "second-owner",
				executable: process.execPath,
				args: ["-e", "setTimeout(() => {}, 1000)"],
				cwd: process.cwd(),
			});
			await expect(
				manager.start({
					ownerSessionId: "third-owner",
					executable: process.execPath,
					args: ["-e", "setTimeout(() => {}, 1000)"],
					cwd: process.cwd(),
				}),
			).rejects.toThrow("2 active sessions");
		} finally {
			await manager.dispose();
		}
	});

	it("terminates the process tree and records cancellation", async () => {
		const manager = new ProcessSessionManager();
		try {
			const started = await manager.start({
				ownerSessionId: OWNER,
				executable: process.execPath,
				args: ["-e", "setInterval(() => {}, 1000)"],
				cwd: process.cwd(),
			});
			await manager.signal(OWNER, started.processId, "kill");
			const completed = await waitForCompletion(manager, started.processId);
			expect(completed.state).toBe("cancelled");
		} finally {
			await manager.dispose();
		}
	});

	it("allows only completed sessions to be closed", async () => {
		const manager = new ProcessSessionManager();
		try {
			const started = await manager.start({
				ownerSessionId: OWNER,
				executable: process.execPath,
				args: ["-e", "setTimeout(() => {}, 1000)"],
				cwd: process.cwd(),
			});
			expect(() => manager.close(OWNER, started.processId)).toThrow(
				"is still active",
			);
			await manager.signal(OWNER, started.processId, "kill");
			await waitForCompletion(manager, started.processId);
			expect(manager.close(OWNER, started.processId)).toBe(true);
			expect(manager.get(OWNER, started.processId)).toBeUndefined();
		} finally {
			await manager.dispose();
		}
	});
});
