import { spawn } from "node:child_process";
import { mkdtemp, writeFile, rm, realpath } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { expect, it } from "vitest";
import {
	observeJavaScriptInspector,
	sameInspectorSourcePath,
	windowsInspectorOwnsListener,
} from "./inspector";
import { probeProcessStartTokenAsync } from "../runtime/process-start-token";
import { byteDigest } from "./contracts";
it("observes exact owned paused Node source without executing it, and rejects a mismatched PID", async () => {
	if (!["linux", "win32"].includes(process.platform)) return;
	const root = await realpath(
			await mkdtemp(join(tmpdir(), "cline-inspector-")),
		),
		file = join(root, "owned.js");
	const text =
		'require("node:fs").writeFileSync(' +
		JSON.stringify(join(root, "MUST_NOT_EXECUTE")) +
		',"executed");';
	await writeFile(file, text);
	// Vitest is hosted by Node even when the repository's test launcher is Bun.
	const child = spawn(process.execPath, ["--inspect-brk=127.0.0.1:0", file], {
		stdio: ["ignore", "ignore", "pipe"],
	});
	let stderr = "";
	child.stderr!.setEncoding("utf8").on("data", (chunk) => (stderr += chunk));
	try {
		const until = Date.now() + 5000;
		while (
			!/ws:\/\/127\.0\.0\.1:\d+\/[a-f0-9-]+/.test(stderr) &&
			Date.now() < until
		)
			await new Promise((r) => setTimeout(r, 25));
		const endpoint = /ws:\/\/127\.0\.0\.1:\d+\/[a-f0-9-]+/.exec(stderr)?.[0];
		expect(endpoint).toBeTruthy();
		const p = await probeProcessStartTokenAsync(child.pid!);
		expect(p.status).toBe("found");
		if (p.status !== "found")
			throw new Error("Owned process probe unavailable");
		const input = {
			operation: "js_inspector_observe",
			target: file,
			pid: child.pid!,
			processToken: p.token,
			endpoint: endpoint!,
			durationMs: 300,
		};
		await expect(
			observeJavaScriptInspector({
				...input,
				pid: process.pid,
				processToken: (
					(await probeProcessStartTokenAsync(process.pid)) as { token: string }
				).token,
			}),
		).rejects.toThrow("listener");
		await expect(
			observeJavaScriptInspector(input, undefined, "f".repeat(64)),
		).rejects.toThrow("changed after approval");
		const result = await observeJavaScriptInspector({
			...input,
			captureConsole: true,
		});
		expect(result.console?.reports).toEqual([]);
		expect(result.input.sha256).toBe(byteDigest(Buffer.from(text)));
		expect(result.verifiedBehavior).toBe(false);
		await expect(
			import("node:fs/promises").then((fs) =>
				fs.stat(join(root, "MUST_NOT_EXECUTE")),
			),
		).rejects.toThrow();
		expect([
			"exact-loaded-source-byte-match",
			"not-observed-in-bounded-window",
		]).toContain(result.reconciliation);
	} finally {
		child.kill("SIGKILL");
		await new Promise<void>((resolve) => {
			if (child.exitCode !== null || child.signalCode !== null) resolve();
			else child.once("exit", () => resolve());
		});
		await rm(root, { recursive: true, force: true });
	}
}, 20000);
it("rejects network endpoints, arbitrary paths and already-cancelled requests", async () => {
	const request = {
		operation: "js_inspector_observe",
		target: "never",
		pid: process.pid,
		processToken: "test",
		endpoint: "ws://outside.invalid:9229/00000000-0000-0000-0000-000000000000",
	};
	await expect(observeJavaScriptInspector(request)).rejects.toThrow("loopback");
	const controller = new AbortController();
	controller.abort();
	await expect(
		observeJavaScriptInspector(
			{
				...request,
				endpoint: "ws://127.0.0.1:9229/00000000-0000-0000-0000-000000000000",
			},
			controller.signal,
		),
	).rejects.toThrow("cancelled");
});

it("reconciles a loaded running owned script by exact source bytes", async () => {
	if (!["linux", "win32"].includes(process.platform)) return;
	const root = await realpath(
			await mkdtemp(join(tmpdir(), "cline-inspector-loaded-")),
		),
		file = join(root, "loaded.js"),
		text = "setInterval(()=>{},1000);";
	await writeFile(file, text);
	const child = spawn(process.execPath, ["--inspect=127.0.0.1:0", file], {
		stdio: ["ignore", "ignore", "pipe"],
	});
	let stderr = "";
	child.stderr!.setEncoding("utf8").on("data", (chunk) => (stderr += chunk));
	try {
		const until = Date.now() + 5000;
		while (
			!/ws:\/\/127\.0\.0\.1:\d+\/[a-f0-9-]+/.test(stderr) &&
			Date.now() < until
		)
			await new Promise((r) => setTimeout(r, 25));
		const endpoint = /ws:\/\/127\.0\.0\.1:\d+\/[a-f0-9-]+/.exec(stderr)?.[0],
			identity = await probeProcessStartTokenAsync(child.pid!);
		if (!endpoint || identity.status !== "found")
			throw new Error("Loaded fixture identity unavailable");
		const result = await observeJavaScriptInspector({
			operation: "js_inspector_observe",
			target: file,
			pid: child.pid!,
			processToken: identity.token,
			endpoint,
			durationMs: 300,
		});
		expect(result.reconciliation).toBe("exact-loaded-source-byte-match");
		expect(
			result.scripts.some(
				(s) => s.staticMatch && s.sha256 === byteDigest(Buffer.from(text)),
			),
		).toBe(true);
		expect(result.verifiedBehavior).toBe(false);
	} finally {
		const done = new Promise<void>((resolve) => {
			if (child.exitCode !== null || child.signalCode !== null) resolve();
			else child.once("exit", () => resolve());
		});
		child.kill("SIGKILL");
		await done;
		await rm(root, { recursive: true, force: true });
	}
}, 20000);

it("normalizes Windows extended source labels without opening label paths", () => {
	expect(
		sameInspectorSourcePath(
			"C:\\owned\\file.js",
			"\\\\?\\C:\\owned\\file.js",
			"win32",
		),
	).toBe(true);
	expect(
		sameInspectorSourcePath(
			"C:\\owned\\different.js",
			"\\\\?\\C:\\owned\\file.js",
			"win32",
		),
	).toBe(false);
	expect(
		sameInspectorSourcePath("/owned/File.js", "/owned/file.js", "linux"),
	).toBe(false);
});

it("captures only opt-in source-bound primitive console reports from a running owned Node fixture", async () => {
	if (!["linux", "win32"].includes(process.platform)) return;
	const root = await realpath(
			await mkdtemp(join(tmpdir(), "cline-console-owned-")),
		),
		file = join(root, "console.js");
	const text =
		'setInterval(()=>console.log("OWNED_REPORT",42,{secret:"DO_NOT_PERSIST"}),40);';
	await writeFile(file, text);
	const child = spawn(process.execPath, ["--inspect=127.0.0.1:0", file], {
		stdio: ["ignore", "ignore", "pipe"],
	});
	let stderr = "";
	child.stderr!.setEncoding("utf8").on("data", (chunk) => (stderr += chunk));
	try {
		const until = Date.now() + 5000;
		while (
			!/ws:\/\/127\.0\.0\.1:\d+\/[a-f0-9-]+/.test(stderr) &&
			Date.now() < until
		)
			await new Promise((r) => setTimeout(r, 25));
		const endpoint = /ws:\/\/127\.0\.0\.1:\d+\/[a-f0-9-]+/.exec(stderr)?.[0],
			identity = await probeProcessStartTokenAsync(child.pid!);
		if (!endpoint || identity.status !== "found")
			throw new Error("Owned console process unavailable");
		const request = {
			operation: "js_inspector_observe",
			target: file,
			pid: child.pid!,
			processToken: identity.token,
			endpoint,
			durationMs: 300,
		};
		const off = await observeJavaScriptInspector(request);
		expect(off.captureConsole).toBe(false);
		expect(off.console).toBeUndefined();
		const on = await observeJavaScriptInspector({
			...request,
			captureConsole: true,
		});
		expect(on.protocol).toBe("cline-js-inspector/2");
		expect(on.console!.reports.length).toBeGreaterThan(0);
		expect(on.console!.reports[0]).toMatchObject({
			sourceSha256: byteDigest(Buffer.from(text)),
			association: "source-bound-protocol-report",
			line: 0,
			arguments: [
				{ type: "string", value: "OWNED_REPORT" },
				{ type: "number", value: 42 },
				{ type: "opaque", opaque: true },
			],
		});
		expect(JSON.stringify(on)).not.toContain("DO_NOT_PERSIST");
		expect(on.verifiedBehavior).toBe(false);
	} finally {
		const done = new Promise<void>((r) => {
			if (child.exitCode !== null || child.signalCode !== null) r();
			else child.once("exit", () => r());
		});
		child.kill("SIGKILL");
		await done;
		await rm(root, { recursive: true, force: true });
	}
}, 20000);

it("enforces the passive command set, drops replay and labels an emulated owned protocol as unverified", async () => {
	if (!["linux", "win32"].includes(process.platform)) return;
	const { WebSocketServer } = await import("ws");
	const root = await realpath(
			await mkdtemp(join(tmpdir(), "cline-console-protocol-")),
		),
		file = join(root, "owned.js"),
		text = 'console.log("owned");';
	await writeFile(file, text);
	const server = new WebSocketServer({ host: "127.0.0.1", port: 0 });
	await new Promise<void>((r) => server.once("listening", r));
	let rejectConsole = false;
	const commands: string[] = [],
		timers: Array<ReturnType<typeof setTimeout>> = [];
	server.on("connection", (ws) =>
		ws.on("message", (data) => {
			const m = JSON.parse(data.toString());
			commands.push(m.method);
			if (rejectConsole && m.method === "Runtime.enable") {
				ws.send(
					JSON.stringify({
						id: m.id,
						error: { code: -32000, message: "denied" },
					}),
				);
				return;
			}
			const event = (value: string, timestamp = Date.now()) => ({
				method: "Runtime.consoleAPICalled",
				params: {
					type: "log",
					timestamp,
					args: [{ type: "string", value }],
					stackTrace: {
						callFrames: [{ scriptId: "owned", lineNumber: 0, columnNumber: 0 }],
					},
				},
			});
			if (m.method === "Debugger.enable")
				ws.send(
					JSON.stringify({
						method: "Debugger.scriptParsed",
						params: { scriptId: "owned", url: file },
					}),
				);
			if (m.method === "Runtime.enable") {
				ws.send(JSON.stringify(event("REPLAY_SECRET", Date.now() - 10000)));
				timers.push(
					setTimeout(() => {
						if (ws.readyState === 1)
							ws.send(JSON.stringify(event("LIVE_PROTOCOL_CLAIM")));
					}, 60),
				);
			}
			ws.send(
				JSON.stringify({
					id: m.id,
					result:
						m.method === "Debugger.getScriptSource"
							? { scriptSource: text }
							: {},
				}),
			);
		}),
	);
	try {
		const identity = await probeProcessStartTokenAsync(process.pid),
			address = server.address();
		if (identity.status !== "found" || !address || typeof address === "string")
			throw new Error("Owned protocol listener unavailable");
		const request = {
			operation: "js_inspector_observe",
			target: file,
			pid: process.pid,
			processToken: identity.token,
			endpoint: `ws://127.0.0.1:${address.port}/00000000-0000-0000-0000-000000000000`,
			durationMs: 300,
		};
		await observeJavaScriptInspector(request);
		expect(commands).toEqual([
			"Debugger.enable",
			"Debugger.getScriptSource",
			"Debugger.disable",
		]);
		commands.length = 0;
		const result = await observeJavaScriptInspector({
			...request,
			captureConsole: true,
		});
		expect(commands).toEqual([
			"Debugger.enable",
			"Runtime.enable",
			"Runtime.disable",
			"Debugger.getScriptSource",
			"Debugger.disable",
		]);
		expect(result.console!.reports).toHaveLength(1);
		expect(result.console!.reports[0].arguments[0].value).toBe(
			"LIVE_PROTOCOL_CLAIM",
		);
		expect(JSON.stringify(result)).not.toContain("REPLAY_SECRET");
		expect(result.verifiedBehavior).toBe(false);
		expect(result.limitations.join(" ")).toContain("emulate Inspector");
		rejectConsole = true;
		commands.length = 0;
		await expect(
			observeJavaScriptInspector({ ...request, captureConsole: true }),
		).rejects.toThrow("command rejected");
		expect(commands).toEqual(["Debugger.enable", "Runtime.enable"]);
	} finally {
		for (const timer of timers) clearTimeout(timer);
		for (const ws of server.clients) ws.terminate();
		await new Promise<void>((r) => server.close(() => r()));
		await rm(root, { recursive: true, force: true });
	}
}, 20000);

it("requires one exact numeric native Windows IPv4 loopback LISTENING owner", () => {
	const row = "  TCP    127.0.0.1:9229    0.0.0.0:0    LISTENING    1234\r\n";
	expect(
		windowsInspectorOwnsListener("Active Connections\r\n" + row, 1234, 9229),
	).toBe(true);
	for (const output of [
		"",
		row + row,
		row.replace("1234", "1235"),
		row.replace("LISTENING", "ESTABLISHED"),
		row.replace("127.0.0.1", "0.0.0.0"),
		row.replace("127.0.0.1:9229", "[::1]:9229"),
		row.replace("127.0.0.1:9229", "127.0.0.1:19229"),
		row.replace("0.0.0.0:0", "1.2.3.4:80"),
		row.replace("1234", "01234"),
		row.replace("1234", "1234x"),
		row.replace("1234", "4294967296"),
		row.replace("LISTENING", "UNKNOWN_LOCALIZED_STATE"),
		row.replace("1234", "1234 extra"),
		"x".repeat(262145) + row,
	])
		expect(windowsInspectorOwnsListener(output, 1234, 9229)).toBe(false);
	for (const [pid, port] of [
		[0, 9229],
		[1234, 0],
		[1234, 65536],
		[1234.5, 9229],
		[1234, 9229.5],
	])
		expect(windowsInspectorOwnsListener(row, pid, port)).toBe(false);
});

it("retains exact listener proof after connected rows appear at the same Inspector port", () => {
	const listener = "TCP 127.0.0.1:9229 0.0.0.0:0 LISTENING 1234\r\n";
	const connection = "TCP 127.0.0.1:9229 127.0.0.1:54321 ESTABLISHED 1234\r\n";
	expect(windowsInspectorOwnsListener(listener + connection, 1234, 9229)).toBe(
		true,
	);
	expect(windowsInspectorOwnsListener(connection + listener, 1234, 9229)).toBe(
		true,
	);
	expect(windowsInspectorOwnsListener(connection, 1234, 9229)).toBe(false);
	expect(windowsInspectorOwnsListener(listener + connection, 54321, 9229)).toBe(
		false,
	);
	expect(
		windowsInspectorOwnsListener(listener + listener + connection, 1234, 9229),
	).toBe(false);
});
