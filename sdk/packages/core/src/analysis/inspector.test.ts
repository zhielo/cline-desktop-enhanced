import { spawn } from "node:child_process";
import { mkdtemp, writeFile, rm, realpath } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { expect, it } from "vitest";
import {
	observeJavaScriptInspector,
	sameInspectorSourcePath,
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
		const result = await observeJavaScriptInspector(input);
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
