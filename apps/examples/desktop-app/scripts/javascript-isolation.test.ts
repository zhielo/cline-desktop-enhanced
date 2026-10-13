import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { probeProcessStartTokenAsync } from "@cline/core";
import { observeNativeModule } from "../sidecar/native-module-observation";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildJavaScriptIsolation } from "./build-javascript-isolation";
import { runIsolatedJavaScript } from "../sidecar/javascript-isolation";
const sha = (v: string) => createHash("sha256").update(v).digest("hex");
const windows = process.platform === "win32" && process.arch === "x64";
describe.skipIf(!windows)(
	"real Windows kernel AppContainer standalone execution",
	() => {
		let root: string, resources: { root: string; manifestDigest: string };
		beforeAll(() => {
			root = mkdtempSync(join(tmpdir(), "cline-isolation-test-"));
			resources = {
				root: join(root, "resources"),
				manifestDigest: buildJavaScriptIsolation(join(root, "resources")),
			};
		}, 180000);
		afterAll(() =>
			rmSync(root, {
				recursive: true,
				force: true,
				maxRetries: 5,
				retryDelay: 100,
			}),
		);
		async function run(
			source: string,
			expected: string,
			options: { timeoutMs?: number; signal?: AbortSignal } = {},
		) {
			const target = join(root, "owned.cjs");
			writeFileSync(target, source);
			return runIsolatedJavaScript(
				{
					operation: "js_isolated_execute",
					target,
					resourceDigest: resources.manifestDigest,
					timeoutMs: options.timeoutMs ?? 5000,
					scenario: {
						id: "owned",
						purpose: "Owned kernel isolation fixture",
						exitCode: 0,
						stdoutSha256: sha(expected),
					},
				},
				{ targetSha256: sha(source), requestHash: sha(source + expected) },
				options.signal,
				resources,
			);
		}
		test("actual zero-capability lowbox token verified before resume and host-observed output", async () => {
			const r = await run("console.log(21*2);", "42\n");
			expect(r.isolation).toMatchObject({
				kind: "appcontainer",
				capabilityCount: 0,
				verifiedBeforeResume: true,
			});
			expect(r.scenario.outcome).toBe("supported");
		}, 30000);
		test("private host read/write denied and inherited secret absent", async () => {
			const canary = join(root, "host-canary"),
				outside = join(root, "outside-write");
			writeFileSync(canary, "secret");
			process.env.CLINE_OWNED_SECRET = "must-not-inherit";
			try {
				const source = `const fs=require('node:fs');let reads=false,writes=false;try{fs.readFileSync(${JSON.stringify(canary)});reads=true;}catch{}try{fs.writeFileSync(${JSON.stringify(outside)},'bad');writes=true;}catch{}console.log(JSON.stringify({reads,writes,secret:process.env.CLINE_OWNED_SECRET??null}));`;
				const r = await run(
					source,
					'{"reads":false,"writes":false,"secret":null}\n',
				);
				expect(r.scenario.outcome).toBe("supported");
				expect(readFileSync(canary, "utf8")).toBe("secret");
			} finally {
				delete process.env.CLINE_OWNED_SECRET;
			}
		}, 30000);
		test("actual loopback TCP connection denied", async () => {
			const server = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				fetch: () => new Response("host-secret"),
			});
			try {
				const r = await run(
					`const net=require('node:net');const c=net.connect(${server.port},'127.0.0.1');c.on('connect',()=>{console.log('CONNECTED');c.destroy();});c.on('error',()=>console.log('DENIED'));c.setTimeout(1000,()=>{console.log('DENIED');c.destroy();});`,
					"DENIED\n",
				);
				expect(r.scenario.outcome).toBe("supported");
			} finally {
				server.stop(true);
			}
		}, 30000);
		test("timeout and descendants release private runtime before cleanup, no false scenario pass", async () => {
			const r = await run(
				`const cp=require('node:child_process'),fs=require('node:fs'),path=require('node:path');const marker=path.join(process.cwd(),'owned-child-ready');if(process.env.OWNED_CHILD){fs.writeFileSync(marker,'ready');setInterval(()=>{},1000);}else{cp.spawn(process.execPath,[__filename],{env:{...process.env,OWNED_CHILD:'1'},stdio:'ignore'});const poll=setInterval(()=>{if(fs.existsSync(marker)){console.log('child-ready');clearInterval(poll);}},10);setInterval(()=>{},1000);}`,
				"child-ready\n",
				{ timeoutMs: 5000 },
			);
			expect(r.stdout.sha256).toBe(sha("child-ready\n"));
			expect(r.timedOut).toBe(true);
			expect(r.scenario.outcome).toBe("inconclusive");
		}, 30000);
		test("output overflow terminates the job and cannot reconcile success", async () => {
			const r = await run(
				"process.stdout.write('x'.repeat(70000));setInterval(()=>{},1000);",
				"",
			);
			expect(r.overflow).toBe(true);
			expect(r.scenario.outcome).toBe("inconclusive");
		}, 30000);
		test("aborted request and mutated approved source fail closed", async () => {
			const controller = new AbortController();
			controller.abort();
			await expect(
				run("console.log(1)", "1\n", { signal: controller.signal }),
			).rejects.toThrow("cancelled");
			const target = join(root, "changed.cjs");
			writeFileSync(target, "console.log(2)");
			await expect(
				runIsolatedJavaScript(
					{
						operation: "js_isolated_execute",
						target,
						resourceDigest: resources.manifestDigest,
						scenario: {
							id: "changed",
							purpose: "deny mutation",
							exitCode: 0,
							stdoutSha256: sha(""),
						},
					},
					{ targetSha256: sha("console.log(1)"), requestHash: sha("owned") },
					undefined,
					resources,
				),
			).rejects.toThrow("changed");
		}, 30000);
		test("actual process-bound native PE base/RVA and memory/file bytes", async () => {
			const powershell = join(
				process.env.ProgramFiles ?? "C:/Program Files",
				"PowerShell",
				"7",
				"pwsh.exe",
			);
			const command = existsSync(powershell)
				? powershell
				: join(
						process.env.SystemRoot ?? "C:/Windows",
						"System32",
						"WindowsPowerShell",
						"v1.0",
						"powershell.exe",
					);
			const output = spawnSync(
				command,
				[
					"-NoProfile",
					"-NonInteractive",
					"-Command",
					`[Console]::Write((Get-Process -Id ${process.pid}).MainModule.BaseAddress.ToInt64().ToString('x'))`,
				],
				{ encoding: "utf8", timeout: 10000 },
			);
			expect(output.status).toBe(0);
			expect(output.stdout).toMatch(/^[a-f0-9]+$/);
			const birth = await probeProcessStartTokenAsync(process.pid);
			if (birth.status !== "found")
				throw new Error("Owned native birth unavailable");
			const hash = createHash("sha256")
				.update(readFileSync(process.execPath))
				.digest("hex");
			const r = await observeNativeModule(
				{
					operation: "native_module_observe",
					target: process.execPath,
					pid: process.pid,
					processToken: birth.token,
					runtimeAddress: `0x${output.stdout}`,
					resourceDigest: resources.manifestDigest,
				},
				hash,
				undefined,
				resources,
			);
			expect(r.moduleObservation).toMatchObject({
				pid: process.pid,
				processToken: birth.token,
				rva: "0x0",
				observedBytes: 32,
				byteMatch: true,
			});
			await expect(
				observeNativeModule(
					{
						operation: "native_module_observe",
						target: process.execPath,
						pid: process.pid,
						processToken: "win32:638000000000000000",
						runtimeAddress: `0x${output.stdout}`,
						resourceDigest: resources.manifestDigest,
					},
					hash,
					undefined,
					resources,
				),
			).rejects.toThrow("unavailable");
		}, 30000);
		test("cancellation after launch kills the host job and cleans private stage/profile", async () => {
			const controller = new AbortController(),
				timer = setTimeout(() => controller.abort(), 1000);
			try {
				await expect(
					run("setInterval(()=>{},1000);", "", {
						timeoutMs: 5000,
						signal: controller.signal,
					}),
				).rejects.toThrow("cancelled");
			} finally {
				clearTimeout(timer);
			}
		}, 30000);
	},
);
