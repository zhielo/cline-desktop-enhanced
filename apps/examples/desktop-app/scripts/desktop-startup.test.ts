import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import {
	closeSync,
	mkdtempSync,
	openSync,
	readFileSync,
	rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Match the desktop host's endpoint wait. A cold Windows runner can spend
// several seconds starting the embedded Hub before the sidecar publishes its
// own ready line; 15 seconds produced intermittent false negatives after an
// otherwise valid installer had already built and installed successfully.
const SIDECAR_READY_TIMEOUT_MS = 30_000;

// The SDK itself allows 30 seconds for Hub startup. Do not terminate its
// bootstrap subprocess after 20 seconds before that contract can complete.
// Include bounded cold executable/antivirus startup overhead on Windows.
const HUB_BOOTSTRAP_TIMEOUT_MS = 45_000;

// Exercise the actual compiled entrypoint: source-only tests miss mixed SDK
// build identities between the desktop client and its embedded Hub daemon.
test("compiled desktop backend publishes its endpoint with its own Hub", async () => {
	const root = mkdtempSync(join(tmpdir(), "cline-desktop-startup-"));
	const discoveryPath = join(root, "hub.json");
	const stdoutPath = join(root, "stdout.log");
	const stderrPath = join(root, "stderr.log");
	const stdout = openSync(stdoutPath, "w");
	const stderr = openSync(stderrPath, "w");
	let child: ReturnType<typeof Bun.spawn> | undefined;
	let hubPid: number | undefined;
	try {
		const binary = process.env.CLINE_TEST_SIDECAR_BIN
			? resolve(process.env.CLINE_TEST_SIDECAR_BIN)
			: join(root, process.platform === "win32" ? "sidecar.exe" : "sidecar");
		if (!process.env.CLINE_TEST_SIDECAR_BIN) {
			const build = spawnSync(
				process.execPath,
				[
					"build",
					fileURLToPath(new URL("../sidecar/index.ts", import.meta.url)),
					"--compile",
					"--no-compile-autoload-dotenv",
					"--no-compile-autoload-bunfig",
					`--define=process.env.CLINE_DESKTOP_BUILD_COMMIT=${JSON.stringify(process.env.GITHUB_SHA ?? "development")}`,
					"--outfile",
					binary,
				],
				{ cwd: root, encoding: "utf8", timeout: 60_000 },
			);
			expect(build.status, build.stderr || String(build.error)).toBe(0);
		}

		const env = Object.fromEntries(
			Object.entries(process.env).filter(
				([key]) => !/^(CLINE_|OTEL_|TELEMETRY_|ERROR_SERVICE_)/.test(key),
			),
		);
		const dataDir = join(root, "data");
		Object.assign(env, {
			CLINE_DIR: root,
			CLINE_DATA_DIR: dataDir,
			CLINE_HUB_DISCOVERY_PATH: discoveryPath,
		});
		// Bootstrap on an OS-assigned port using the same executable. Pin the
		// desktop to that port so this test cannot touch a developer's real Hub,
		// even if a regression makes it reject its own discovery record.
		const bootstrap = spawnSync(
			binary,
			["--remote-hub-ensure", "--discovery-path", discoveryPath, "--cwd", root],
			{ cwd: root, env, encoding: "utf8", timeout: HUB_BOOTSTRAP_TIMEOUT_MS },
		);
		expect(bootstrap.status, bootstrap.stderr || String(bootstrap.error)).toBe(
			0,
		);
		const hub = JSON.parse(readFileSync(discoveryPath, "utf8"));
		hubPid = hub.pid;
		env.CLINE_HUB_PORT = String(hub.port);
		child = Bun.spawn([binary], {
			cwd: root,
			env,
			stdin: "ignore",
			stdout,
			stderr,
		});
		let endpoint: string | undefined;
		let wsEndpoint: string | undefined;
		const deadline = Date.now() + SIDECAR_READY_TIMEOUT_MS;
		while (Date.now() < deadline) {
			for (const line of readFileSync(stdoutPath, "utf8").split("\n")) {
				try {
					const message = JSON.parse(line);
					if (message.type === "ready") {
						endpoint = message.endpoint;
						wsEndpoint = message.wsEndpoint;
					}
				} catch {
					/* Ignore other output and incomplete lines. */
				}
			}
			if (endpoint || child.exitCode !== null) break;
			await Bun.sleep(50);
		}
		expect(
			endpoint,
			readFileSync(stderrPath, "utf8") || "Backend never became ready",
		).toBeTruthy();
		const health = await fetch(`${endpoint}/health`, {
			signal: AbortSignal.timeout(5_000),
		});
		expect(health.ok).toBe(true);
		expect(await health.json()).toMatchObject({
			ok: true,
			pid: child.pid,
			transportAuth: "sidecar-capability/v1",
			sourceCommit: process.env.GITHUB_SHA ?? "development",
		});

		// Installed binaries must deny tokenless commands, not just prompt approvals.
		expect(typeof wsEndpoint).toBe("string");
		const privateEndpoint = new URL(wsEndpoint!);
		const capability = privateEndpoint.searchParams.get("approval_token");
		expect(Boolean(capability && capability.length >= 16)).toBe(true);
		// Probe the advertised HTTP endpoint directly. This avoids a Windows Bun
		// URL-object protocol-mutation path and proves the same installed server.
		const denied = await fetch(`${endpoint}/transport`, {
			signal: AbortSignal.timeout(5000),
		});
		expect(denied.status).toBe(401);
		const shutdownDenied = await fetch(`${endpoint}/shutdown`, {
			method: "POST",
			signal: AbortSignal.timeout(5000),
		});
		expect(shutdownDenied.status).toBe(401);
		await new Promise<void>((resolve, reject) => {
			const socket = new WebSocket(privateEndpoint.toString());
			const timer = setTimeout(() => {
				socket.close();
				reject(new Error("Authenticated transport smoke timed out"));
			}, 30000);
			socket.onopen = () =>
				socket.send(
					JSON.stringify({
						type: "command",
						id: "auth-smoke",
						command: "get_process_context",
						args: {},
					}),
				);
			socket.onmessage = (event) => {
				const message = JSON.parse(String(event.data));
				if (message.type !== "response" || message.id !== "auth-smoke") return;
				clearTimeout(timer);
				socket.close();
				if (message.ok === true) resolve();
				else reject(new Error("Authenticated transport command failed"));
			};
			socket.onerror = () => {
				clearTimeout(timer);
				socket.close();
				reject(new Error("Authenticated transport handshake failed"));
			};
		});

		// The installed backend must initialize the same atomic edit-recovery
		// constraint used by source builds. This catches packaging drift where an
		// older embedded Hub silently permits duplicate long-chat edit forks.
		const sessionsDbPath = join(dataDir, "db", "sessions.db");
		const sessionsDb = new Database(sessionsDbPath);
		try {
			const schemaObjects = sessionsDb
				.query(
					"SELECT name FROM sqlite_master WHERE name IN (?, ?) ORDER BY name",
				)
				.all(
					"sessions_fork_operation_id_guard",
					"sessions_fork_operation_id_unique",
				);
			expect(schemaObjects).toEqual([
				{ name: "sessions_fork_operation_id_guard" },
				{ name: "sessions_fork_operation_id_unique" },
			]);

			const insertFork = sessionsDb.prepare(`INSERT OR REPLACE INTO sessions (
				session_id, source, pid, started_at, status, interactive, provider, model, cwd,
				workspace_root, enable_tools, enable_spawn, enable_teams, metadata_json, hook_path, updated_at
			) VALUES (?, 'desktop', 1, '2026-10-01T00:00:00.000Z', 'idle', 1,
				'cline', 'installer-smoke', ?, ?, 1, 1, 1, ?, '', '2026-10-01T00:00:00.000Z')`);
			const editOperationId = "fork:installer-long-chat:edit:message-300:150";
			const forkMetadata = JSON.stringify({
				conversationId: "installer-long-chat",
				fork: {
					operationId: editOperationId,
					forkedFromSessionId: "installer-long-chat",
					beforeRunCount: 150,
				},
			});
			insertFork.run("installer-edit-fork", root, root, forkMetadata);
			expect(() =>
				insertFork.run("installer-duplicate-fork", root, root, forkMetadata),
			).toThrow("duplicate session fork operation id");
		} finally {
			sessionsDb.close();
		}

		// Reboot-equivalent smoke: stop and restart the installed sidecar against
		// the same data directory and detached Hub, then require a fresh ready line
		// and healthy endpoint. Persisted edit identity must survive this boundary.
		child.kill();
		await Promise.race([child.exited, Bun.sleep(6_000)]);
		if (child.exitCode === null) child.kill("SIGKILL");
		await child.exited;
		child = Bun.spawn([binary], {
			cwd: root,
			env,
			stdin: "ignore",
			stdout,
			stderr,
		});
		let restartedEndpoint: string | undefined;
		const restartDeadline = Date.now() + SIDECAR_READY_TIMEOUT_MS;
		while (Date.now() < restartDeadline) {
			const readyLines = readFileSync(stdoutPath, "utf8")
				.split("\n")
				.flatMap((line) => {
					try {
						const message = JSON.parse(line);
						return message.type === "ready" ? [message.endpoint as string] : [];
					} catch {
						return [];
					}
				});
			if (readyLines.length >= 2) restartedEndpoint = readyLines.at(-1);
			if (restartedEndpoint || child.exitCode !== null) break;
			await Bun.sleep(50);
		}
		expect(
			restartedEndpoint,
			"Restarted backend never became ready",
		).toBeTruthy();
		const restartedHealth = await fetch(`${restartedEndpoint}/health`, {
			signal: AbortSignal.timeout(5_000),
		});
		expect(restartedHealth.ok).toBe(true);
		expect(await restartedHealth.json()).toMatchObject({
			ok: true,
			pid: child.pid,
			transportAuth: "sidecar-capability/v1",
			sourceCommit: process.env.GITHUB_SHA ?? "development",
		});
		// A restarted process must not accept the old process's capability.
		const stale = await fetch(
			`${restartedEndpoint}/transport?approval_token=${encodeURIComponent(capability!)}`,
			{ signal: AbortSignal.timeout(5000) },
		);
		expect(stale.status).toBe(401);

		const restartedDb = new Database(sessionsDbPath, { readonly: true });
		try {
			expect(
				restartedDb
					.query(
						`SELECT session_id, json_extract(metadata_json, '$.fork.operationId') AS operation_id
						 FROM sessions WHERE session_id = ?`,
					)
					.get("installer-edit-fork"),
			).toEqual({
				session_id: "installer-edit-fork",
				operation_id: "fork:installer-long-chat:edit:message-300:150",
			});
		} finally {
			restartedDb.close();
		}
	} finally {
		if (child && child.exitCode === null) {
			child.kill();
			await Promise.race([child.exited, Bun.sleep(6_000)]);
			if (child.exitCode === null) child.kill("SIGKILL");
			await child.exited;
		}
		// A failed bootstrap may still have published a discovery record.
		try {
			hubPid ??= JSON.parse(readFileSync(discoveryPath, "utf8")).pid;
			if (hubPid) process.kill(hubPid, "SIGTERM");
		} catch {
			/* The isolated Hub may already have exited. */
		}
		// Windows refuses to remove a directory that is any live process's cwd,
		// and both the Hub and the backend run with `root` as theirs. The kill
		// above only requests termination, so wait for the pid to actually go
		// away; on POSIX the remove would have succeeded regardless, which is
		// why this only ever failed on the Windows runner.
		if (hubPid) {
			const gone = Date.now() + 10_000;
			while (Date.now() < gone) {
				try {
					process.kill(hubPid, 0);
				} catch {
					break;
				}
				await Bun.sleep(50);
			}
		}
		closeSync(stdout);
		closeSync(stderr);
		// Losing a temp directory must never fail a signed release build: this
		// runs after every assertion, so a lingering grandchild holding a
		// handle would otherwise fail the publish over passing tests.
		try {
			rmSync(root, {
				recursive: true,
				force: true,
				maxRetries: 20,
				retryDelay: 100,
			});
		} catch {
			/* The runner discards its temp directory anyway. */
		}
	}
	// Covers bounded source compilation, bootstrap, both ready/health checks,
	// and cleanup. Passing runs still exit as soon as all assertions complete.
}, 225_000);
