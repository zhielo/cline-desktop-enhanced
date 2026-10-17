import { gunzipSync } from "node:zlib";
/**
 * Windows CI only: attach to the installed app's own WebView2.
 * No dev web server, model credential, browser download, or production test bypass.
 */

import {OWNED_MANAGED_BASE64,OWNED_MANAGED_SHA256,OWNED_EH_BASE64,OWNED_EH_SHA256} from "../../../sdk/packages/core/scripts/owned-managed-fixture.mjs";
import { createHash,randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { appendFile, mkdir, mkdtemp, open, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { basename, isAbsolute, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { type Browser, chromium, type Locator, type Page } from "playwright";

/** Newly produced receipts must match the shipped parser, not a stale test literal.
 * Persisted historical receipts remain governed by their own immutable profile. */
export function verifyInstalledAnalysisProfile(profile: string) {
  // This Node strip-types driver is also checked by a project which disallows
  // .ts imports. Read only the trusted checkout's exact constant declaration;
  // never load target code or accept a caller-selected expected profile.
  const contract = readFileSync(new URL("../../../sdk/packages/core/src/analysis/contracts.ts", import.meta.url), "utf8");
  const current = /^export const ANALYSIS_PROFILE = "(cline-js-static\/[1-9][0-9]*)";$/m.exec(contract);
  if (!current) throw new Error("Shipped analysis profile declaration unavailable");
  if (profile !== current[1]) throw new Error("Installed analysis profile is stale");
}

export function startAcceptanceProcess(
  executable: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
) {
  const startedAt = new Date().toISOString();
  const child = spawn(executable, args, {
    cwd,
    env,
    shell: false,
    windowsHide: false,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const diagnostics = { stdoutTail: "", stderrTail: "", launchError: "" };
  const limit = 16 * 1024;
  child.stdout?.setEncoding("utf8");
  child.stderr?.setEncoding("utf8");
	child.stdout?.on("data", (data: string) => {
    diagnostics.stdoutTail = (diagnostics.stdoutTail + data).slice(-limit);
  });
	child.stderr?.on("data", (data: string) => {
    diagnostics.stderrTail = (diagnostics.stderrTail + data).slice(-limit);
  });
	const exited = new Promise<number | null>((done) => {
		child.once("error", (error) => {
      diagnostics.launchError = error.message;
      done(null);
    });
    child.once("exit", (code) => done(code));
  });
  const closed = new Promise<void>((done) => child.once("close", () => done()));
  return { child, exited, closed, diagnostics, startedAt };
}

/** Keep native process-tree termination authoritative and independent of CDP
 * teardown: a disconnected transport is not proof of native process exit.
 * Still attempt disconnect after a failed stop and preserve both failures;
 * never retry a kill or accept an unconfirmed termination. */
export async function stopOwnedApplication(
  terminate: () => Promise<void>,
  disconnect: () => Promise<void>,
) {
  const failures: unknown[] = [];
  try { await terminate(); } catch (error) { failures.push(error); }
  try { await disconnect(); } catch (error) { failures.push(error); }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1)
    throw new AggregateError(failures, "Owned application termination and disconnect failed");
}

/** Node-owned deadline: renderer timers can stop while a WebView/IPC call is stuck.
 * Timeout fails acceptance, never retries or claims a submitted operation was undone. */
export async function withInstalledActionDeadline<T>(
  phase: string,
  operation: () => Promise<T>,
  timeoutMs = 95_000,
): Promise<T> {
  if (!/^[a-z][a-z0-9_-]{0,95}$/.test(phase) || !Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 180_000)
    throw new Error("Invalid installed action deadline");
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      Promise.resolve().then(operation),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`Installed action deadline exceeded: ${phase}; no replay`)), timeoutMs);
      }),
    ]);
  } finally { clearTimeout(timer); }
}

// A settings textbox is disabled until the asynchronous persisted-settings read settles.
// Trial click waits for that actual UI readiness, not an arbitrary sleep or value retry.
export async function verifyRestartInstructions(
  instructions: Locator,
  expected: string,
) {
  await instructions.click({ trial: true, timeout: 30_000 });
  if ((await instructions.inputValue()) !== expected)
    throw new Error("Installed UI setting did not survive restart");
}

/** Reattach through the authoritative Hub recovery path before opening a new
 * local SQLite discovery connection. Neither operation is replayed on error. */
export async function verifyRecoveredHubSession(
  attach: () => Promise<unknown>,
  readSessions: () => Promise<Array<{ sessionId: string }>>,
  sessionId: string,
) {
  await attach();
  const sessions = await readSessions();
  if (!sessions.some((item) => item.sessionId === sessionId))
    throw new Error("Saved session missing after Hub restart");
}

/** Retry only endpoint discovery, never a submitted command or accepted prompt.
 * Full-pack integrity checks can outlast one native 30s readiness window. */
export async function waitForInstalledBackendEndpoint(
	readEndpoint: () => Promise<string>,
	options: { timeoutMs?: number; pollMs?: number; maxAttempts?: number } = {},
) {
	const timeoutMs = options.timeoutMs ?? 90_000;
	const pollMs = options.pollMs ?? 200;
	const maxAttempts = options.maxAttempts ?? 3;
	if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || !Number.isFinite(pollMs) || pollMs < 0 ||
		!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 3)
		throw new Error("Invalid installed backend readiness budget");
	const deadline = Date.now() + timeoutMs;
	for (let attempt = 0; attempt < maxAttempts && Date.now() < deadline; attempt++) {
		let timer: ReturnType<typeof setTimeout> | undefined;
		try {
			const endpoint = await Promise.race([
				readEndpoint(),
				new Promise<never>((_, reject) => {
					timer = setTimeout(() => reject(new Error("Installed backend readiness deadline exceeded")), Math.max(1, deadline - Date.now()));
				}),
			]);
			const url = new URL(endpoint);
			if (!["ws:", "wss:"].includes(url.protocol) ||
				!["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) || url.username || url.password)
				throw new Error("Installed backend did not publish a local WebSocket endpoint");
			return endpoint;
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			if (!/desktop backend endpoint not ready/i.test(message)) throw error;
		} finally {
			clearTimeout(timer);
		}
		if (attempt + 1 < maxAttempts && Date.now() < deadline)
			await delay(Math.min(pollMs, Math.max(0, deadline - Date.now())));
	}
	throw new Error("Installed backend did not become ready within the bounded discovery budget");
}

type ProcessMetadata = {
  name: string;
  pid: number;
  parentPid: number;
  createdAt: string;
  debuggingArgumentObserved: boolean;
  ownedProfileObserved: boolean;
};
export function ownedDescendantMetadata(
  snapshot: ProcessMetadata[],
  rootPid: number,
  startedAt: string,
  rootName: string,
) {
  const root = snapshot.find((p) => p.pid === rootPid);
	if (
		!root ||
		root.name.toLowerCase() !== rootName.toLowerCase() ||
		!Number.isFinite(Date.parse(root.createdAt)) ||
		!Number.isFinite(Date.parse(startedAt)) ||
		Date.parse(root.createdAt) < Date.parse(startedAt) - 1000
	)
    return [];
  const seen = new Set([rootPid]);
  let parents = [root];
  const owned: ProcessMetadata[] = [];
	for (let depth = 0; depth < 5 && parents.length; depth++) {
		const children = snapshot.filter(
			(p) =>
				!seen.has(p.pid) &&
				parents.some(
					(parent) =>
						p.parentPid === parent.pid &&
						Number.isFinite(Date.parse(p.createdAt)) &&
						Date.parse(p.createdAt) >= Date.parse(parent.createdAt),
				),
    );
		for (const child of children) {
      seen.add(child.pid);
      owned.push(child);
		}
    parents = children;
	}
  return owned.slice(0, 64);
}

function redactedLaunchText(text: string) {
	return text
		.replace(/approval_token=[^&\s]+/gi, "approval_token=[REDACTED]")
		.replace(/Bearer\s+\S+/gi, "Bearer [REDACTED]")
    .replace(
      /("(?:authToken|token|apiKey|password|secret)"\s*:\s*")[^"]*"/gi,
      '$1[REDACTED]"',
    )
    .replace(/\b[0-9a-f]{32,}\b/gi, "[REDACTED]");
}

export async function main() {
  const executable = process.env.CLINE_TEST_INSTALLED_APP;
  const sidecar = process.env.CLINE_TEST_INSTALLED_SIDECAR;
	if (process.platform !== "win32" || !executable || !isAbsolute(executable))
    throw new Error("Absolute installed Windows application path required");
  if (!sidecar || !isAbsolute(sidecar))
    throw new Error(
      "Absolute installed sidecar path required for isolated Hub bootstrap",
    );
  const root = await mkdtemp(join(tmpdir(), "cline-installed-ui-"));
  const workspace = join(root, "owned-workspace");
  const evidence = join(process.cwd(), "dist", "installed-ui-evidence");
  await mkdir(workspace);
  await mkdir(evidence, { recursive: true });
  await writeFile(
    join(workspace, "OWNED_FIXTURE.txt"),
    "Deterministic installer acceptance fixture.\n",
  );
  await writeFile(join(workspace, "owned-triage.exe"), "MZCLINE_OWNED_TRIAGE_FIXTURE_V1");
  await writeFile(join(workspace, "OWNED_SCROLL_REPORT.md"), Array.from({length: 240}, (_, i) => `Owned Markdown scroll line ${i}`).join("\n"));
  await writeFile(join(workspace,"owned-main.js"),'import {ipcMain} from "electron"; ipcMain.handle("owned:fixture", () => 42);');
  await writeFile(join(workspace,"owned-renderer.js"),'import {ipcRenderer} from "electron"; ipcRenderer.invoke("owned:fixture");');
  const analysisCurrent=join(workspace,"owned-analysis-current"), analysisPrevious=join(workspace,"owned-analysis-previous");
  await mkdir(analysisCurrent);await mkdir(analysisPrevious);
  const hybridExpectedOutput="owned-hybrid\n";
  const hybridFixtureTarget=join(analysisCurrent,"hybrid-owned.js");
  await writeFile(hybridFixtureTarget,`process.stdout.write(${JSON.stringify(hybridExpectedOutput)});`);
  for(const [directory,route] of [[analysisCurrent,"/v2"],[analysisPrevious,"/v1"]]) {
    await writeFile(join(directory,"config.ts"),`export const config={host:"https://owned.invalid",route:${JSON.stringify(route)}};`);
    await writeFile(join(directory,"main.js"),`import {ipcMain} from "electron"; ipcMain.handle("owned:fixture", () => 42); import {config} from "./config"; function endpoint(h,r){return h+r;} fetch(endpoint(config.host,config.route));`);
    await writeFile(join(directory,"renderer.js"),'import {ipcRenderer} from "electron"; ipcRenderer.invoke("owned:fixture");');
  }
  await writeFile(join(analysisCurrent,"main.js.map"),JSON.stringify({version:3,file:"main.js",sources:["original.ts"],sourcesContent:["export const owned=42;"],names:[],mappings:"AAAA"}));
  const managedFixture=Buffer.from(OWNED_MANAGED_BASE64,"base64");
  if(createHash("sha256").update(managedFixture).digest("hex")!==OWNED_MANAGED_SHA256)throw new Error("Owned managed fixture hash drift");
  await writeFile(join(analysisCurrent,"owned.dll"),managedFixture);
  const exceptionFixture=Buffer.from(OWNED_EH_BASE64,"base64");
  if(createHash("sha256").update(exceptionFixture).digest("hex")!==OWNED_EH_SHA256)throw new Error("Owned exception fixture hash drift");
  await writeFile(join(analysisCurrent,"owned-eh.dll"),exceptionFixture);
  await writeFile(join(analysisCurrent,"preload.js"),'const {contextBridge:cb,ipcRenderer:ir}=require("electron");const addon=require("./owned.node");const api={read:(x)=>ir.invoke("owned:fixture",x),hash:(x)=>addon.hash(x)};cb.exposeInMainWorld("ownedApi",api);');
  await writeFile(join(analysisCurrent,"renderer.js"),'import {ipcRenderer} from "electron";ipcRenderer.invoke("owned:fixture");window.ownedApi.read(42);window.ownedApi.hash(42);');

  let port = 0;
  const discoveryPath = join(root, "hub.json");
	const environment = Object.fromEntries(
		Object.entries(process.env).filter(
			([key]) =>
				!/^(CLINE_|OTEL_|TELEMETRY_|ERROR_SERVICE_)/.test(key) &&
				!/(API_KEY|TOKEN|PASSWORD|SECRET|PRIVATE_KEY|CREDENTIAL)/i.test(key),
		),
  );
	Object.assign(environment, {
		CLINE_INSTALLED_ACCEPTANCE: "1",
		CLINE_DIR: root,
		CLINE_DATA_DIR: join(root, "data"),
		CLINE_HUB_DISCOVERY_PATH: discoveryPath,
		WEBVIEW2_USER_DATA_FOLDER: join(root, "webview-profile"),
  });
  let app: ReturnType<typeof startAcceptanceProcess> | undefined;
  let browser: Browser | undefined;
  const stages: string[] = [];
  let actionSequence = 0;
  let lastAction = { phase: "setup", status: "running" };
  async function acceptanceAction<T>(phase: string, operation: () => Promise<T>, timeoutMs = 95_000) {
    const sequence = ++actionSequence;
    if (sequence > 256) throw new Error("Installed action evidence budget reached");
    lastAction = { phase, status: "running" };
    const startedAt = new Date().toISOString();
    const persist = async () => {
      await appendFile(join(evidence, "action-progress.jsonl"), JSON.stringify({sequence, ...lastAction, at: new Date().toISOString()}) + "\n");
      await writeFile(join(evidence, "phase.json"), JSON.stringify({
        schemaVersion: 1, sourceCommit: process.env.GITHUB_SHA, sequence, lastAction, startedAt, stages,
      }, null, 2));
    };
    await persist();
    try {
      const result = await withInstalledActionDeadline(phase, operation, timeoutMs);
      lastAction = { phase, status: "completed" };
      await persist();
      return result;
    } catch (error) {
      lastAction = { phase, status: "failed" };
      await persist();
      throw error;
    }
  }
  let launchNumber = 0;
  const startupSamples: number[] = [];
  const appWorkingSetSamples: number[] = [];
  const transcriptScrollSamples: number[] = [];
  const taskkill = join(
    process.env.SystemRoot ?? "C:\\Windows",
    "System32",
    "taskkill.exe",
  );

	async function killOwnedProcess(pid: number) {
    const killer = startAcceptanceProcess(
      taskkill,
      ["/PID", String(pid), "/T", "/F"],
      workspace,
      environment,
    );
    const code = await withInstalledActionDeadline("owned-process-tree-stop", () => killer.exited, 10_000).catch((error) => { killer.child.kill(); throw error; });
    if (code !== 0)
      throw new Error(
        `Owned process-tree cleanup was not confirmed (taskkill exit ${code}): ${
          redactedLaunchText(killer.diagnostics.stderrTail || killer.diagnostics.stdoutTail ||
            killer.diagnostics.launchError).slice(-1200)
        }`,
      );
	}

  async function retainLaunchReceipt(
    lastConnectionError: string,
    lastHttpStatus: number | null,
  ) {
    if (!app) return;
		// Read-only diagnostics about this launched app's descendants. Never emit
		// raw command lines, other processes or environment values.
		const command = `
$all = @(Get-CimInstance Win32_Process -ErrorAction Stop)
# Only bounded candidate metadata is transferred; never command lines.
# Parent PID alone is not ownership: Windows can reuse an old process PID.
$candidates = @($all | Where-Object { $_.ProcessId -eq [int]$env:ACCEPTANCE_APP_PID })
$candidates += @($all | Where-Object { $_.Name -in @('msedgewebview2.exe', 'code-sidecar.exe', 'conhost.exe') -and $_.ProcessId -ne [int]$env:ACCEPTANCE_APP_PID } | Select-Object -First 32)
$rows = @($candidates | ForEach-Object {
  [ordered]@{ name = $_.Name; pid = $_.ProcessId; parentPid = $_.ParentProcessId;
    createdAt = $_.CreationDate.ToUniversalTime().ToString('o');
    debuggingArgumentObserved = [bool]($_.CommandLine -like "*--remote-debugging-port=$env:ACCEPTANCE_CDP_PORT*");
    ownedProfileObserved = [bool]($_.CommandLine -like "*$env:ACCEPTANCE_PROFILE*") }
})
ConvertTo-Json -InputObject @($rows) -Compress
`;
		const powershell = join(
			process.env.SystemRoot ?? "C:\\Windows",
			"System32",
			"WindowsPowerShell",
			"v1.0",
			"powershell.exe",
    );
    const probe = startAcceptanceProcess(
      powershell,
      ["-NoProfile", "-NonInteractive", "-Command", command],
      workspace,
      {
			...environment,
			ACCEPTANCE_APP_PID: String(app.child.pid),
			ACCEPTANCE_CDP_PORT: String(port),
			ACCEPTANCE_PROFILE: environment.WEBVIEW2_USER_DATA_FOLDER,
      },
    );
    const probeCode = await Promise.race([
      probe.exited,
      delay(10_000, null, { ref: false }),
    ]);
    if (probeCode === null && probe.child.pid)
      await killOwnedProcess(probe.child.pid);
    let descendants: unknown = [];
		try {
			if (probeCode === 0)
				descendants = ownedDescendantMetadata(
					JSON.parse(probe.diagnostics.stdoutTail),
					app.child.pid!,
					app.startedAt,
					basename(executable!),
        );
		} catch {
			/* Mark probe unavailable below. */
		}
		await writeFile(
			join(evidence, `launch-${launchNumber}.json`),
			JSON.stringify(
				{
					nodeVersion: process.version,
					pid: app.child.pid,
					exitCode: app.child.exitCode,
					debuggingPort: port,
					lastHttpStatus,
					lastConnectionError: redactedLaunchText(lastConnectionError),
					stdoutTail: redactedLaunchText(app.diagnostics.stdoutTail),
					stderrTail: redactedLaunchText(app.diagnostics.stderrTail),
					launchError: redactedLaunchText(app.diagnostics.launchError),
					descendantProbeExitCode: probeCode,
					descendantCandidateLimit: 32,
					descendants,
				},
				null,
				2,
			),
    );
	}

	async function launch() {
    const startupStarted = performance.now();
		// Allocate only after Hub bootstrap, immediately before app launch. The
		// isolated Hub must not claim a port reserved and released much earlier.
    const listener = createServer();
    await new Promise<void>((done) => listener.listen(0, "127.0.0.1", done));
    port = (listener.address() as { port: number }).port;
    await new Promise<void>((done) => listener.close(() => done()));
    environment.WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = `--remote-debugging-port=${port} --remote-debugging-address=127.0.0.1`;
    launchNumber++;
    app = startAcceptanceProcess(executable!, [], workspace, environment);
    let lastConnectionError = "";
    let lastHttpStatus: number | null = null;
    const deadline = Date.now() + 60_000;
		while (Date.now() < deadline) {
			if (app.diagnostics.launchError || app.child.exitCode !== null) {
        await retainLaunchReceipt(lastConnectionError, lastHttpStatus);
        throw new Error(
          "Installed app launch failed; inspect the bounded launch receipt",
        );
			}
			try {
        const response = await fetch(`http://127.0.0.1:${port}/json/version`, {
          signal: AbortSignal.timeout(1000),
        });
        lastHttpStatus = response.status;
				if (response.ok) {
          browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, {
            timeout: 10_000,
          });
          break;
				}
			} catch (error) {
        lastConnectionError =
          error instanceof Error ? error.message : String(error);
			}
      await delay(250);
		}
    await retainLaunchReceipt(lastConnectionError, lastHttpStatus);
    if (!browser)
      throw new Error(
        "Installed WebView2 did not expose its test-only CDP port",
      );
    const pageDeadline = Date.now() + 30_000;
    let page: Page | undefined;
		while (!page && Date.now() < pageDeadline) {
			page = browser
				.contexts()
				.flatMap((context) => context.pages())
        .find((candidate) =>
          /tauri\.localhost|tauri:\/\/localhost/.test(candidate.url()),
        );
      if (!page) await delay(100);
		}
    if (!page) throw new Error("Installed app webview page unavailable");
    page.setDefaultTimeout(30_000);
    await page.waitForFunction(() =>
      Boolean(
        (window as unknown as { __TAURI_INTERNALS__?: unknown })
          .__TAURI_INTERNALS__,
      ),
    );
		// Skip only first-run onboarding in an empty test profile, not app authentication.
		await acceptanceAction("launch-onboarding-profile", () => page.evaluate(() =>
      localStorage.setItem(
        "cline.code.onboarding.v1",
        JSON.stringify({ completedAt: new Date().toISOString() }),
      ),
    ), 30_000);
    await page.reload();
    await page
      .getByRole("button", { name: "Settings", exact: true })
      .first()
      .waitFor();
    // Visible settings are not proof that the restarted sidecar is ready.
    // Require one actual authenticated read; no command or prompt is replayed.
    await rpc(page, "get_desktop_settings");
    startupSamples.push(performance.now() - startupStarted);
    // Sample only this launched native app, never arbitrary user processes.
    // WebView/Hub/worker descendants are deliberately not called whole-app RAM.
    const powershell = join(process.env.SystemRoot ?? "C:\\Windows",
      "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    const probe = startAcceptanceProcess(powershell, ["-NoProfile", "-NonInteractive", "-Command",
      `[Console]::Write((Get-Process -Id ${app.child.pid} -ErrorAction Stop).WorkingSet64)`], workspace, environment);
    const probeCode = await Promise.race([probe.exited, delay(10000, null, {ref:false})]);
    if (probeCode === null && probe.child.pid) await killOwnedProcess(probe.child.pid);
    if (probeCode !== 0) throw new Error("Owned installed app memory probe failed");
    await probe.closed;
    const bytes = Number(probe.diagnostics.stdoutTail.trim());
    if (!Number.isFinite(bytes) || bytes <= 0) throw new Error("Invalid owned app working-set observation");
    appWorkingSetSamples.push(bytes / 1024 / 1024);
    return page;
	}

  async function rpc<T>(
    page: Page,
    command: string,
    args: Record<string, unknown> = {},
  ): Promise<T> {
		const endpoint = await acceptanceAction("backend-endpoint-discovery", () => waitForInstalledBackendEndpoint(() => page.evaluate(async () => {
			const native = (window as unknown as {
				__TAURI_INTERNALS__: { invoke: (name: string) => Promise<string> };
			}).__TAURI_INTERNALS__;
			return await native.invoke("get_desktop_backend_endpoint");
		})), 95_000);
		return (await acceptanceAction(`rpc-${command}`, () => page.evaluate(
			async ({ command, args, endpoint }) => {
				return await new Promise((resolve, reject) => {
          const socket = new WebSocket(endpoint);
          const id = crypto.randomUUID();
					const timer = setTimeout(() => {
            socket.close();
            reject(new Error(`Installed RPC timed out: ${command}`));
          }, 90_000);
					const finish = () => {
            clearTimeout(timer);
            socket.close();
          };
          socket.onopen = () =>
            socket.send(JSON.stringify({ type: "command", id, command, args }));
          socket.onmessage = (event) => {
            const reply = JSON.parse(String(event.data));
            if (reply.type !== "response" || reply.id !== id) return;
            finish();
            if (reply.ok) resolve(reply.result);
            else {
              const detail = String(reply.error ?? "Unknown backend error")
                .replace(
                  /approval_token=[^&\s]+/gi,
                  "approval_token=[REDACTED]",
                )
                .replace(/Bearer\s+\S+/gi, "Bearer [REDACTED]")
                .replace(/\b[0-9a-f]{32,}\b/gi, "[REDACTED]")
                .slice(0, 1500);
              reject(
                new Error(`Installed command failed: ${command}: ${detail}`),
              );
					}
          };
					socket.onerror = () => {
            finish();
            reject(new Error("Installed authenticated transport failed"));
          };
        });
			},
      { command, args, endpoint },
    ))) as T;
	}
	async function settings(page: Page, section: string) {
    await page
      .getByRole("button", { name: "Settings", exact: true })
      .first()
      .click();
		await page
			.getByRole("navigation", { name: "Settings sections" })
			.getByRole("button", { name: section, exact: true })
      .click();
	}
	async function stop() {
    const ownedBrowser = browser;
    const ownedApp = app;
    try {
      await stopOwnedApplication(
        async () => {
          if (ownedApp && ownedApp.child.exitCode === null && ownedApp.child.pid) {
            await killOwnedProcess(ownedApp.child.pid);
            await withInstalledActionDeadline("owned-app-exit", () => ownedApp.exited, 10_000);
          }
        },
        async () => {
          if (ownedBrowser)
            await withInstalledActionDeadline("owned-browser-disconnect", () => ownedBrowser.close(), 10_000);
        },
      );
    } finally {
      browser = undefined;
      app = undefined;
    }
	}

	try {
		// Use the installed sidecar to bootstrap an isolated Hub on an OS-assigned port.
		// A default Hub left by the earlier GUI smoke must never satisfy this fixture.
		const bootstrap = startAcceptanceProcess(
			sidecar,
      [
        "--remote-hub-ensure",
        "--discovery-path",
        discoveryPath,
        "--cwd",
        workspace,
      ],
			workspace,
			environment,
    );
    const bootCode = await Promise.race([
      bootstrap.exited,
      delay(45_000, null, { ref: false }),
    ]);
    if (bootCode === null) {
      if (bootstrap.child.pid) await killOwnedProcess(bootstrap.child.pid);
      throw new Error("Installed sidecar isolated Hub bootstrap timed out");
    }
    if (bootCode !== 0)
      throw new Error(
        `Installed sidecar isolated Hub bootstrap failed: ${bootCode}`,
      );
    const isolatedHub = JSON.parse(await readFile(discoveryPath, "utf8"));
    if (
      !Number.isInteger(isolatedHub.port) ||
      isolatedHub.port < 1 ||
      isolatedHub.port > 65535
		)
      throw new Error("Isolated Hub did not publish a valid port");
    environment.CLINE_HUB_PORT = String(isolatedHub.port);
    stages.push("installed-sidecar-isolated-hub-bootstrapped");
    let page = await launch();
    stages.push("installed-webview-rendered");
    // Fresh composer: choosing a mode configures only the unsent draft. No model
    // call, target execution, software install or permission expansion is needed.
    const freshAnalysis = page.getByLabel("Draft Analysis mode", { exact: true });
    await freshAnalysis.waitFor({ state: "visible", timeout: 30_000 });
    if ((await freshAnalysis.inputValue()) !== "off") throw new Error("Fresh draft Analysis must start Off");
    await freshAnalysis.selectOption("static");
    if ((await freshAnalysis.inputValue()) !== "static") throw new Error("Pre-task Analysis selection did not stick");
    const analysisToggle = page.getByRole("button", { name: "Toggle Analysis workspace", exact: true });
    await analysisToggle.click();
    await page.getByRole("region", { name: "Pre-task Analysis workspace", exact: true }).waitFor();
    const preTaskWorkspace = page.getByRole("region", { name: "Pre-task Analysis workspace", exact: true });
    await preTaskWorkspace.getByRole("button", { name: "AI commands", exact: true }).click();
    const advancedPanel = preTaskWorkspace.getByRole("region", { name: "Advanced AI commands", exact: true });
    await advancedPanel.getByLabel("Advanced command", { exact: true }).selectOption("preview_smali_patch", { timeout: 30000 });
    if (!(await advancedPanel.getByLabel("Exact command parameters (JSON)", { exact: true }).inputValue()).includes("expected_sha256")) throw new Error("Installed advanced command template missing hash guard");
    if (!(await advancedPanel.textContent())?.includes("Not available in this command pack")) throw new Error("Installed advanced catalog hid unavailable capabilities");
    stages.push("installed-fresh-advanced-command-catalog-visible-without-execution");
    await analysisToggle.click();
    await freshAnalysis.selectOption("off");
    stages.push("installed-fresh-draft-analysis-visible-before-first-task");

    // Exercise the installed app's actual event receivers against our own blank
    // WebView. Never attach to user browsers or execute a supplied target.
    const captureBrowserId=randomUUID();
    const nativeCaptureInvoke=<T,>(name:string,args:Record<string,unknown>)=>acceptanceAction(`native-${name}`, () => page.evaluate(async({name,args})=>{
      const native=(window as unknown as {__TAURI_INTERNALS__:{invoke:(name:string,args:Record<string,unknown>)=>Promise<unknown>}}).__TAURI_INTERNALS__;
      return await native.invoke(name,args);
    },{name,args}), 40_000) as Promise<T>;
    try {
      await nativeCaptureInvoke("built_in_browser_start",{sessionId:captureBrowserId,url:"about:blank"});
      await nativeCaptureInvoke("built_in_browser_capture",{sessionId:captureBrowserId,action:"start"});
      await nativeCaptureInvoke("built_in_browser_cdp",{sessionId:captureBrowserId,method:"Runtime.enable",params:{}});
      await nativeCaptureInvoke("built_in_browser_cdp",{sessionId:captureBrowserId,method:"Runtime.evaluate",params:{expression:"console.log('owned-capture-secret-fixture')",returnByValue:true}});
      await delay(100);
      const captured=await nativeCaptureInvoke<{cleanupVerified:boolean;events:Array<{kind:string;argumentCount?:number}>}>("built_in_browser_capture",{sessionId:captureBrowserId,action:"stop"});
      if(!captured.cleanupVerified||!captured.events.some(e=>e.kind==="console-event"&&e.argumentCount===1))throw new Error("Installed native browser capture failed");
      if(JSON.stringify(captured).includes("owned-capture-secret-fixture"))throw new Error("Installed native capture retained console argument values");
      stages.push("installed-browser-native-metadata-capture-cleanup-verified");
    } finally {
      await nativeCaptureInvoke("built_in_browser_stop",{sessionId:captureBrowserId});
    }

		// Create an idle session with explicit local configuration: no paid/live model turn.
    const session = await rpc<{ sessionId: string }>(
      page,
      "chat_session_command",
      {
			request: {
				action: "start",
				config: {
					sessionId: "installer-ui-owned-session",
					environmentId: "local",
					cwd: workspace,
					workspaceRoot: workspace,
					provider: "openai",
					model: "gpt-4.1-mini",
					apiKey: "owned-offline-fixture",
					baseUrl: "http://127.0.0.1:1/v1",
					enableTools: false,
					permissionProfile: "read-only",
					// Empty new sessions intentionally persist lazily. Seed an owned
					// transcript to exercise the existing durable recovery contract.
            initialMessages: Array.from({length:120}, (_, index) => ({
              id: `installer-owned-message-${index}`,
              role: "user",
              content: `Installer owned history row ${index}. ${"Owned offline transcript fixture. ".repeat(8)}`,
            })).concat([{id: "installer-owned-artifact", role: "assistant", content: "Owned report: `./OWNED_SCROLL_REPORT.md`"}]),
				},
			},
      },
    );
    if (!session.sessionId)
      throw new Error("Installed session creation failed");
		await rpc(page, "update_chat_session_title", {
			sessionId: session.sessionId,
			environmentId: "local",
			title: "Installer owned session",
    });
    await page.reload();
		await page
			.getByRole("button", { name: /Installer owned session/ })
			.first()
      .click();
    stages.push("owned-workspace-idle-session-opened");
    const analysisArgs={sessionId:session.sessionId,environmentId:"local"};
    const beforeAnalysis=await rpc<{mode:string}>(page,"first_party_analysis_status",analysisArgs);
    if(beforeAnalysis.mode!=="off")throw new Error("New session analysis must default Off");
    await page.getByLabel("Session Analysis mode",{exact:true}).selectOption("static");
    await page.waitForFunction(()=>{const select=document.querySelector<HTMLSelectElement>('select[aria-label="Session Analysis mode"]');return select?.value==="static"&&!select.disabled;});
    const parsed=await rpc<{id:string;status:string}>(page,"first_party_analysis_run",{...analysisArgs,input:{target:"owned-analysis-current",compareTarget:"owned-analysis-previous"}});
    if(!["completed","partial"].includes(parsed.status))throw new Error("Installed static parser failed");
    const allEvidence=async(view:string,filter?:string)=>{
      const items:Array<{kind:string;value:string}>=[];let offset=0;
      for(let count=0;count<20;count++) {
        const result=await rpc<{items:Array<{kind:string;value:string}>;nextOffset:number|null}>(page,"first_party_analysis_evidence",{...analysisArgs,query:{receiptId:parsed.id,view,filter,offset,limit:50}});
        items.push(...result.items);if(result.nextOffset===null)return {items};
        if(!Number.isSafeInteger(result.nextOffset)||result.nextOffset<=offset)throw new Error("Installed evidence pagination stalled");offset=result.nextOffset;
      }
      throw new Error("Installed owned evidence exceeded fixture budget");
    };
    const graph=await allEvidence("graph");
    if(!graph.items.some(e=>e.kind==="ipc-candidate"))throw new Error("Installed parser omitted owned IPC candidate");
    const values=await rpc<{items:Array<{kind:string;value:string}>}>(page,"first_party_analysis_evidence",{...analysisArgs,query:{receiptId:parsed.id,view:"findings",filter:"resolved-endpoint"}});
    if(!values.items.some(f=>f.kind==="resolved-endpoint"&&f.value==="https://owned.invalid/v2"))throw new Error("Installed cross-module object/value/return reduction failed");
    const preloadMembers=await allEvidence("findings","preload-member");
    if(!preloadMembers.items.some(f=>f.kind==="preload-member"&&JSON.parse(f.value).channel==="owned:fixture")||!graph.items.some(e=>e.kind==="preload-candidate")||!graph.items.some(e=>e.kind==="native-boundary-candidate"))throw new Error("Installed lexical preload/native-boundary candidate inspection failed");
    const exceptionRegions=await allEvidence("findings","managed-exception-region");
    const exceptionKinds=exceptionRegions.items.filter(f=>f.kind==="managed-exception-region").map(f=>JSON.parse(f.value).record.kind);
    if(!exceptionKinds.includes("catch")||!exceptionKinds.includes("finally")||!graph.items.some(e=>e.kind==="managed-exception-candidate"))throw new Error("Installed managed exception region inspection failed");
    const managedDeclarations=await allEvidence("findings","managed-method");
    const managedAdd=managedDeclarations.items.filter(f=>f.kind==="managed-method").map(f=>JSON.parse(f.value).record).find(f=>f.name==="Add");
    if(managedAdd?.declaringType?.name!=="Fixture"||managedAdd?.declaringType?.namespace!=="ClineOwned"||managedAdd?.signature?.status!=="completed"||managedAdd?.signature?.display!=="int32 (int32, int32)")throw new Error("Installed declaring-type/signature inspection failed");
    const managed=await allEvidence("findings","managed-il-instruction");
    const managedInstructions=managed.items.filter(f=>f.kind==="managed-il-instruction").map(f=>JSON.parse(f.value).record);
    if(!managedInstructions.some(f=>f.opcode==="call"&&f.resolution?.name==="Add")||!managedInstructions.some(f=>f.opcode==="ldstr"&&f.resolution?.preview==="https://owned.invalid/managed")||!managedInstructions.some(f=>f.opcode==="ldc.i8"&&f.operand==="9007199254740993"))throw new Error("Installed managed IL inspection failed");
    if(!graph.items.some(f=>f.kind==="managed-flow"))throw new Error("Installed managed normal-flow graph unavailable");
    const mappings=await rpc<{items:Array<{kind:string}>}>(page,"first_party_analysis_evidence",{...analysisArgs,query:{receiptId:parsed.id,view:"findings",filter:"source-map-location"}});
    if(!mappings.items.some(f=>f.kind==="source-map-location"))throw new Error("Installed source-map inspection failed");
    const verification=await rpc<{profile:string}>(page,"first_party_analysis_evidence",{...analysisArgs,query:{receiptId:parsed.id,view:"verification"}});
    verifyInstalledAnalysisProfile(verification.profile);
    const unified=await rpc<{items:unknown[]}>(page,"first_party_analysis_cross_domain",{...analysisArgs,receiptId:parsed.id});
    if(!Array.isArray(unified.items))throw new Error("Installed unified evidence route unavailable");
    const dossiers=await rpc<{items:unknown[]}>(page,"first_party_analysis_cross_domain",{...analysisArgs,view:"dossiers"});
    if(!Array.isArray(dossiers.items))throw new Error("Installed native dossier route unavailable");

    const changes=await rpc<{items:Array<{kind:string;value:string;change:string}>}>(page,"first_party_analysis_evidence",{...analysisArgs,query:{receiptId:parsed.id,view:"comparison",filter:"resolved-endpoint"}});
    if(!changes.items.some(f=>f.change==="removed"&&f.value==="https://owned.invalid/v1")||!changes.items.some(f=>f.change==="added"&&f.value==="https://owned.invalid/v2"))throw new Error("Installed endpoint finding comparison failed");
    page.once("dialog",dialog=>dialog.accept());
    await page.getByLabel("Session Analysis mode",{exact:true}).selectOption("hybrid");
    await page.waitForFunction(()=>{const select=document.querySelector<HTMLSelectElement>('select[aria-label="Session Analysis mode"]');return select?.value==="hybrid"&&!select.disabled;});
    await page.reload();
    await page.getByRole("button", {name:/Installer owned session/}).first().click();
    const hybridStatus=await rpc<{mode:string;receipts:Array<{id:string}>}>(page,"first_party_analysis_status",analysisArgs);
    if(hybridStatus.mode!=="hybrid"||!hybridStatus.receipts.some(r=>r.id===parsed.id))throw new Error("Installed Hybrid mode/evidence did not persist");
    const hybridBasis=await rpc<{relation:string;evidenceHash:string}>(page,"analysis_workflow_hybrid_prepare",{...analysisArgs,input:{baselineKind:"receipt",baselineId:parsed.id,question:"Which owned browser event occurs?"}});
    if(hybridBasis.relation!=="investigation-context-only"||!/^[a-f0-9]{64}$/.test(hybridBasis.evidenceHash))throw new Error("Installed Hybrid static preflight failed");
    let missingBasisDenied=false;
    try{await rpc(page,"analysis_workflow_hybrid_prepare",{...analysisArgs,input:{baselineKind:"receipt",baselineId:"11111111-1111-4111-8111-111111111111",question:"Missing basis must deny"}});}catch{missingBasisDenied=true;}
    if(!missingBasisDenied)throw new Error("Installed Hybrid accepted missing static evidence");
    stages.push("installed-hybrid-mode-persistence-static-preflight-passed");
    const hybridExecutePlan=await rpc<{id:string;requestHash:string;requirements:string[];request:Record<string,unknown>}>(page,"first_party_analysis_execute_prepare",{
      ...analysisArgs,
      hybridProposal:{baselineKind:"receipt",baselineId:parsed.id,question:"Does this owned isolated fixture exit 0 and emit the expected bytes?"},
      input:{operation:"js_isolated_execute",target:hybridFixtureTarget,timeoutMs:5000,scenario:{id:"installed-hybrid-owned",purpose:"Owned installed Hybrid process-interface assertion only",exitCode:0,stdoutSha256:createHash("sha256").update(hybridExpectedOutput).digest("hex")}},
    });
    if((hybridExecutePlan.request.hybrid as {relation?:string})?.relation!=="exact-artifact-hash")throw new Error("Installed Hybrid execution plan lacks exact static basis");
    const hybridApproval=await rpc<{executionToken:string}>(page,"approve_analysis_task",{...analysisArgs,cwd:workspace,planId:hybridExecutePlan.id,requestHash:hybridExecutePlan.requestHash,requirements:hybridExecutePlan.requirements});
    const hybridExecuted=await rpc<{result:{hybrid?:{evidenceHash:string};isolation:{verifiedBeforeResume:boolean};scenario:{outcome:string}}}>(page,"first_party_analysis_execute_run",{...analysisArgs,planId:hybridExecutePlan.id,executionToken:hybridApproval.executionToken,input:hybridExecutePlan.request,confirmExecution:true});
    if(hybridExecuted.result.isolation.verifiedBeforeResume!==true||hybridExecuted.result.scenario.outcome!=="supported"||hybridExecuted.result.hybrid?.evidenceHash!==hybridBasis.evidenceHash)throw new Error("Installed Hybrid owned isolated execution failed scoped assertions");
    const hybridBundle=await rpc<{payload:{records:unknown[]}}>(page,"get_evidence_bundle",{...analysisArgs,input:{receiptIds:[parsed.id],taskIds:[hybridExecutePlan.id]}});
    if(hybridBundle.payload.records.length!==2)throw new Error("Installed Hybrid selected static/runtime export incomplete");
    stages.push("installed-hybrid-owned-isolated-execution-and-export-passed");

    await page.getByLabel("Session Analysis mode",{exact:true}).selectOption("off");
    await page.waitForFunction(()=>{const select=document.querySelector<HTMLSelectElement>('select[aria-label="Session Analysis mode"]');return select?.value==="off"&&!select.disabled;});
    await page.getByRole("button",{name:"Open Analysis Workspace",exact:true}).click();
    const guide = page.getByRole("region", {name:"Guided investigation",exact:true});
    await guide.waitFor({timeout:30000});
    const androidBefore=await rpc<{state:string}>(page,"setup_center_android_status",{environmentId:"local"});
    if(androidBefore.state!=="installed-not-tested")throw new Error("Installed Android pack did not start honestly untested");
    await guide.getByRole("button",{name:"Analyze / rebuild an owned Android app",exact:true}).click();
    const androidPanel=page.getByRole("region",{name:"Android Analysis and Rebuild Pack",exact:true});
    await androidPanel.waitFor({timeout:30000});
    page.once("dialog",async dialog=>{if(dialog.message().includes("fixed owned Android"))await dialog.accept();else await dialog.dismiss();});
    await androidPanel.getByRole("button",{name:"Test owned Android fixtures",exact:true}).click();
    await page.waitForFunction(()=>{const panel=document.querySelector('[aria-label="Android Analysis and Rebuild Pack"]');return !!panel?.querySelector('[role="alert"]')||panel?.textContent?.includes("Pack status: ready");},undefined,{timeout:600000});
    if(await androidPanel.getByRole("alert").count())throw new Error("Installed Android fixture acceptance failed; no readiness claimed");
    const androidAfter=await rpc<{state:string;receipt:unknown}>(page,"setup_center_android_status",{environmentId:"local"});
    if(androidAfter.state!=="ready")throw new Error("Installed Android pack fixture did not pass");
    await writeFile(join(evidence,"android-toolchain-readiness.json"),JSON.stringify(androidAfter,null,2));
    stages.push("installed-android-owned-resource-multidex-smali-jadx-signature-and-native-tools-passed");
    await page.getByRole("button",{name:"Start here",exact:true}).click();


    await guide.getByRole("button",{name:"Understand a JS / Electron application",exact:true}).click();
    stages.push("installed-guided-entry-navigation-passed");
    await page.getByLabel("First-party Analysis Workspace",{exact:true}).waitFor();
    await page.getByLabel("Saved analysis receipt",{exact:true}).selectOption(parsed.id);
    if(await page.getByRole("button",{name:"Inspect static sources",exact:true}).isEnabled())throw new Error("Off analysis must block new inspection");
    await page.getByRole("button",{name:"verification",exact:true}).click();
    await page.getByText("Receipt integrity and static inspection are not behavioral certification.",{exact:false}).waitFor();
    stages.push("installed-first-party-mode-parser-evidence-passed");
    await page.getByRole("button",{name:"Close diff view",exact:true}).click();

    await page.waitForFunction(() => document.querySelectorAll('[data-message-role="user"]').length >= 120);
    for (let sample = 0; sample < 3; sample++) {
      const started = performance.now();
      await page.locator('[data-message-role="user"]').first().scrollIntoViewIfNeeded();
      await page.locator('[data-message-role="user"]').last().scrollIntoViewIfNeeded();
      await acceptanceAction("owned-transcript-frame", () => page.evaluate(() => new Promise<void>(done => requestAnimationFrame(() => requestAnimationFrame(() => done())))), 30_000);
      transcriptScrollSamples.push(performance.now() - started);
    }
    stages.push("owned-120-row-transcript-scroll-acceptance-passed");
    await page.locator('a[data-cline-file-reference="./OWNED_SCROLL_REPORT.md"]').last().click();
    const preview = page.getByTestId("artifact-preview-scroll");
    await preview.waitFor({state: "visible"});
    if (!(await preview.evaluate(el => el.scrollHeight > el.clientHeight))) throw new Error("Owned Markdown preview is not independently scrollable");
    const box = await preview.boundingBox();
    if (!box || box.y < 0 || box.y + box.height > (page.viewportSize()?.height ?? await acceptanceAction("owned-viewport-read", () => page.evaluate(() => innerHeight), 30_000))) throw new Error("Markdown preview exceeds viewport");
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.wheel(0, 700);
    await page.waitForFunction(() => (document.querySelector('[data-testid="artifact-preview-scroll"]')?.scrollTop ?? 0) > 0);
    await preview.focus();
    await page.keyboard.press("Control+End");
    await page.keyboard.press("End");
    await page.waitForFunction(() => { const el = document.querySelector('[data-testid="artifact-preview-scroll"]'); return !!el && el.scrollTop + el.clientHeight >= el.scrollHeight - 2; });
    await page.keyboard.press("Home");
    await page.waitForFunction(() => (document.querySelector('[data-testid="artifact-preview-scroll"]')?.scrollTop ?? -1) === 0);
    await page.keyboard.press("Escape");
    await preview.waitFor({state: "hidden"});
    stages.push("owned-markdown-preview-wheel-keyboard-scroll-passed");

    await settings(page, "General");
    const instructions = page.getByRole("textbox", {
      name: "Custom AI instructions",
      exact: true,
    });
    await instructions.fill(
      "Installer acceptance: preserve this owned local setting.",
    );
    await page
      .getByRole("button", { name: "Save instructions", exact: true })
      .click();
    await page.getByText(/Saved permanently/).waitFor();
    stages.push("local-setting-persisted-through-ui");
    await settings(page, "Analysis environment");
    await page
      .getByRole("button", { name: "Check analysis readiness", exact: true })
      .click();
    const ready = await rpc<{
      configured: boolean;
      runtime: { source: string };
      readiness: { status: string };
      interpreter: { executable: string };
      setupCenter: {desktopBuild:{sourceCommit:string; capabilitySchema:string}};
    }>(page, "get_analysis_environment", { environmentId: "local" });
    await writeFile(
      join(evidence, "analysis-readiness.json"),
      JSON.stringify(ready, null, 2),
    );
    await page.screenshot({ path: join(evidence, "readiness.png") });
		if (
			!ready.configured ||
			ready.readiness.status !== "completed" ||
      ready.runtime?.source !== "bundled" ||
      !ready.interpreter.executable
        .replaceAll("\\", "/")
        .toLowerCase()
        .includes("/resources/analysis-runtime/python.exe")
		)
      throw new Error(
        "Installed application did not validate its bundled interpreter without CLINE_RE_PYTHON",
      );
    await page
      .getByText("Fixture execution: completed.", { exact: false })
      .waitFor({ timeout: 90_000 });
    stages.push("installed-interpreter-owned-fixtures-passed");
    if (ready.setupCenter.desktopBuild.sourceCommit !== process.env.GITHUB_SHA ||
        ready.setupCenter.desktopBuild.capabilitySchema !== "setup-center/processor-acceptance-v2")
      throw new Error("Installed setup UI build identity mismatch");
    await page.screenshot({ path: join(evidence, "readiness.png") });

    await page.getByRole("button", {name:"Open Setup Center",exact:true}).click();
    await page.getByLabel("IDA acceptance processor",{exact:true}).selectOption("arm64");
    // UI selection is not a commercial-license test; never launch licensed IDA in hosted CI.
    stages.push("installed-setup-navigation-and-arm64-selection-passed");
    await settings(page,"Analysis environment");
    await page.getByRole("button",{name:"Open Setup Center",exact:true}).click();
    if (await page.getByLabel("IDA acceptance processor",{exact:true}).inputValue() !== "arm64")
      throw new Error("Installed Setup Center forgot the selected processor after navigation");
    if (!await page.getByRole("button",{name:"Test IDA integration (optional)",exact:true}).isVisible())
      throw new Error("Installed IDA test is not clearly optional");
    stages.push("installed-setup-processor-remount-and-optional-test-passed");
    const triagePanel = page.getByRole("region", { name: "Binary Triage Pack readiness", exact: true });
    await triagePanel.waitFor({timeout: 30000});
    const triageBefore = await rpc<{capabilities:Array<{id:string;state:string}>}>(page,"binary_triage_status",{environmentId:"local"});
    if (triageBefore.capabilities.length !== 4 || triageBefore.capabilities.some(c=>c.state!=="installed-not-tested")) throw new Error("Installed triage pack must start installed but untested");
    page.once("dialog", async dialog => { if(dialog.message().includes("fixed project-owned PE fixtures")) await dialog.accept(); else await dialog.dismiss(); });
    await triagePanel.getByRole("button",{name:"Test triage fixtures",exact:true}).click();
    // Four sequential workers each have a 90-second budget; observe the existing
    // UI terminal result (success OR bounded error), never replay the test.
    await page.waitForFunction(() => {
      const panel = document.querySelector('[aria-label="Binary Triage Pack readiness"]');
      return !!panel?.querySelector('[role="alert"]') ||
        panel?.textContent?.includes("Owned fixture passed for this pack/interpreter; target compatibility remains separate") &&
        !panel?.textContent?.includes("Testing owned fixtures…");
    }, undefined, { timeout: 425000 });
    const triageError = await triagePanel.getByRole("alert").textContent({timeout:1000}).catch(()=>null);
    if (triageError) {
      await writeFile(join(evidence,"binary-triage-readiness-error.json"),JSON.stringify({message:triageError.slice(0,1000)},null,2));
      throw new Error(`Installed triage owned acceptance: ${triageError.slice(0,1000)}`);
    }
    const triageAfter=await rpc<{capabilities:Array<{id:string;state:string}>}>(page,"binary_triage_status",{environmentId:"local"});
    if(triageAfter.capabilities.length!==4||triageAfter.capabilities.some(c=>c.state!=="ready")) throw new Error("Installed triage engine fixture did not pass");
    await writeFile(join(evidence,"binary-triage-readiness.json"),JSON.stringify(triageAfter,null,2));
    stages.push("installed-binary-triage-four-owned-engines-passed");

    const triageInput={operation:"scan_yara",target:"owned-triage.exe",question:"Does the owned neutral marker match?"};
    let restrictedTriageDenied=false;
    try { await rpc(page,"binary_triage_run",{...analysisArgs,confirmed:true,requestId:randomUUID(),input:triageInput}); }
    catch { restrictedTriageDenied=true; }
    if(!restrictedTriageDenied)throw new Error("Binary triage widened the Read Only session");
    const triageSession=await rpc<{sessionId:string}>(page,"chat_session_command",{request:{action:"start",config:{sessionId:"installer-owned-triage",environmentId:"local",cwd:workspace,workspaceRoot:workspace,provider:"openai",model:"gpt-4.1-mini",apiKey:"owned-offline-fixture",baseUrl:"http://127.0.0.1:1/v1",enableTools:false,permissionProfile:"full-access",initialMessages:[{id:"owned-triage-start",role:"user",content:"Owned offline static triage fixture"}]}}});

    // Exercise exact preview -> separately approved write through the installed SDK/sidecar.
    const ownedSmaliBefore = ".method public value()I\n    .locals 1\n    const/4 v0, 0x0\n    return v0\n.end method";
    const ownedSmaliAfter = ownedSmaliBefore.replace("0x0", "0x1");
    const ownedSmaliText = `.class public Lowned/Sample;\n.super Ljava/lang/Object;\n\n${ownedSmaliBefore}\n`;
    const ownedSmaliSource = join(workspace, "owned-source.smali");
    const ownedSmaliOutput = join(workspace, "owned-candidate.smali");
    await writeFile(ownedSmaliSource, ownedSmaliText);
    const ownedPatchArgs = {sessionId:triageSession.sessionId,environmentId:"local",cwd:workspace};
    const ownedPatch = {expected_sha256:createHash("sha256").update(ownedSmaliText).digest("hex"),class_descriptor:"Lowned/Sample;",method_signature:"value()I",expected_method:ownedSmaliBefore,replacement_method:ownedSmaliAfter};
    async function runOwnedAdvanced(request:Record<string,unknown>) {
      const plan=await rpc<{id:string;requestHash:string;requirements:string[];request:Record<string,unknown>}>(page,"prepare_analysis_task",{...ownedPatchArgs,kind:"static",request});
      const approval=await rpc<{executionToken:string}>(page,"approve_analysis_task",{...ownedPatchArgs,planId:plan.id,requestHash:plan.requestHash,requirements:plan.requirements});
      return rpc<{result:{published:boolean;previewSha256:string;projectSha256?:string;sourceUnchanged?:boolean;validation?:string;outputSha256?:string;batchPreviewSha256?:string;status?:string;comparison?:{changed:string[]};resolvedEvidence?:{resolved:{name:string;version:string}[]};result?:{status:string;evidence:{boundaryAgreement:boolean;rangeSha256:string;decoders:{engine:string;version:string;decodedBytes:number}[]}};results?:{status:string}[];verifiedStageIds?:string[];remainingStageIds?:string[];witnesses?:{sourceId:string;sinkId:string;route:string[]}[];observedExecution?:boolean;selectedFunction?:{sha256:string;text:string};conclusion?:string;executed?:boolean;stages?:{id:string;dependsOn:string[]}[]};plan:{status:string}}>(page,"run_static_analysis",{...ownedPatchArgs,planId:plan.id,executionToken:approval.executionToken,input:plan.request});
    }
    const previewRequest={operation:"preview_smali_patch",target:ownedSmaliSource,output_file:ownedSmaliOutput,smali_patch:ownedPatch,timeout_ms:120000};
    const ownedPreview=await runOwnedAdvanced(previewRequest);
    if(ownedPreview.result.published||ownedPreview.plan.status!=="completed")throw new Error("Installed Smali preview unexpectedly published or failed");
    const ownedApplied=await runOwnedAdvanced({...previewRequest,operation:"patch_smali_method",smali_patch:{...ownedPatch,preview_sha256:ownedPreview.result.previewSha256}});
    if(!ownedApplied.result.published||ownedApplied.plan.status!=="completed"||await readFile(ownedSmaliSource,"utf8")!==ownedSmaliText||await readFile(ownedSmaliOutput,"utf8")!==ownedSmaliText.replace(ownedSmaliBefore,ownedSmaliAfter))throw new Error("Installed hash-bound Smali candidate patch failed");
    stages.push("installed-advanced-smali-preview-approved-candidate-original-preserved");

    const ownedProject=join(workspace,"owned-apk-project"), ownedProjectSmali=join(ownedProject,"smali/owned");
    await mkdir(ownedProjectSmali,{recursive:true});await mkdir(join(ownedProject,"smali_classes2/owned"),{recursive:true});await mkdir(join(ownedProject,"res/values"),{recursive:true});
    await writeFile(join(ownedProjectSmali,"Sample.smali"),ownedSmaliText);
    await writeFile(join(ownedProject,"smali_classes2/owned/Second.smali"),".class public Lowned/Second;\n.super Ljava/lang/Object;\n.method public static value()I\n .registers 1\n const/4 v0, 0x7\n return v0\n.end method\n");
    await writeFile(join(ownedProject,"AndroidManifest.xml"),'<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.cline.owned" android:versionCode="1" android:versionName="1"><uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/><application android:label="@string/app_name" android:hasCode="true"/></manifest>');
    await writeFile(join(ownedProject,"res/values/strings.xml"),'<resources><string name="app_name">Owned installed candidate</string></resources>');
    await writeFile(join(ownedProject,"apktool.yml"),'version: 3.0.3\napkFileName: owned.apk\nusesFramework:\n  ids:\n  - 1\nsdkInfo:\n  minSdkVersion: 23\n  targetSdkVersion: 35\nversionInfo:\n  versionCode: 1\n  versionName: "1"\n');
    const ownedProjectPatch={patches:[{path:"smali/owned/Sample.smali",patch:ownedPatch}]};
    const projectPreviewRequest={operation:"preview_android_candidate",target:ownedProject,output_file:join(workspace,"owned-project-candidate.apk"),android_project_patch:ownedProjectPatch,timeout_ms:120000,smali_api_level:28};
    const projectPreview=await runOwnedAdvanced(projectPreviewRequest);
    if(projectPreview.plan.status!=="completed"||projectPreview.result.executed!==false||projectPreview.result.published||!projectPreview.result.projectSha256)throw new Error("Installed project preview failed or wrote output");
    const projectApplied=await runOwnedAdvanced({...projectPreviewRequest,operation:"build_android_candidate",android_project_patch:{...ownedProjectPatch,expected_project_sha256:projectPreview.result.projectSha256,preview_sha256:projectPreview.result.previewSha256}});
    if(projectApplied.plan.status!=="completed"||projectApplied.result.status!=="completed"||!projectApplied.result.published||!projectApplied.result.sourceUnchanged||!projectApplied.result.outputSha256||!["assemble-smali","assemble-smali_classes2","rebuild-apk"].every(id=>projectApplied.result.stages?.some(stage=>stage.id===id))||await readFile(join(ownedProjectSmali,"Sample.smali"),"utf8")!==ownedSmaliText)throw new Error("Installed approved Android project pipeline failed or altered its source");
    stages.push("installed-approved-android-project-patch-assemble-rebuild-originals-preserved");

    const batchBinary=join(workspace,"owned-candidate-input.bin"),batchAst=join(workspace,"owned-candidate-input.ts"),batchManifest=join(workspace,"owned-candidate-batch.json");
    const batchBinaryBefore=Buffer.from([0,1,2,3]),batchAstBefore="export const owned = 1; export const enabled = false;\n";
    await writeFile(batchBinary,batchBinaryBefore);await writeFile(batchAst,batchAstBefore);
    const ownedBatch={schemaVersion:1,stages:[
      {id:"bytes",operation:"patch_binary",target:"owned-candidate-input.bin",output_file:"owned-candidate-output.bin",candidate:{expected_sha256:createHash("sha256").update(batchBinaryBefore).digest("hex"),byte_patches:[{offset:0,expected_hex:"00",replacement_hex:"aa"},{offset:1,expected_hex:"01",replacement_hex:"ff"}]}},
      {id:"literal",operation:"apply_ast_transform",target:"owned-candidate-input.ts",output_file:"owned-candidate-output.ts",candidate:{expected_sha256:createHash("sha256").update(batchAstBefore).digest("hex"),literals:[{start:batchAstBefore.indexOf("1"),expected:"1",replacement:"200"},{start:batchAstBefore.indexOf("false"),expected:"false",replacement:"true"}]}}
    ]};
    await writeFile(batchManifest,JSON.stringify(ownedBatch));
    const batchPreview=await runOwnedAdvanced({operation:"preview_candidate_batch",target:batchManifest,acknowledge_external_output:true,timeout_ms:120000});
    if(batchPreview.plan.status!=="completed"||!batchPreview.result.batchPreviewSha256)throw new Error("Installed candidate batch preview failed");
    const batchApply=await runOwnedAdvanced({operation:"apply_candidate_batch",target:batchManifest,batch_preview_sha256:batchPreview.result.batchPreviewSha256,acknowledge_external_output:true,timeout_ms:120000});
    if(batchApply.plan.status!=="completed"||batchApply.result.status!=="completed"||batchApply.result.results?.length!==2||!batchApply.result.results.every(s=>s.status==="completed")||!(await readFile(batchBinary)).equals(batchBinaryBefore)||await readFile(batchAst,"utf8")!==batchAstBefore||!(await readFile(join(workspace,"owned-candidate-output.bin"))).equals(Buffer.from([170,255,2,3]))||await readFile(join(workspace,"owned-candidate-output.ts"),"utf8")!==batchAstBefore.replace("= 1","= 200").replace("false","true"))throw new Error("Installed approved candidate batch did not preserve inputs or publish exact candidates");
    stages.push("installed-preview-approved-binary-ast-batch-originals-preserved");
    const batchAudit=await runOwnedAdvanced({operation:"audit_candidate_batch",target:batchManifest,timeout_ms:120000});
    if(batchAudit.plan.status!=="completed"||batchAudit.result.status!=="completed"||batchAudit.result.published!==false||batchAudit.result.verifiedStageIds?.join(",")!=="bytes,literal"||batchAudit.result.remainingStageIds?.length!==0)throw new Error("Installed read-only candidate audit failed");
    const witnessGraph=join(workspace,"owned-source-sink-graph.json");
    await writeFile(witnessGraph,JSON.stringify({schemaVersion:1,nodes:["a","b"].map(id=>({id,kind:"native-symbol",label:id,artifactSha256:"a".repeat(64),confidence:"candidate",evidenceIndex:0})),edges:[{source:"a",target:"b",relation:"references-candidate",confidence:"candidate"}],sourceHashes:["a".repeat(64)],coverage:["owned declared candidate fixture only"]}));
    const witness=await runOwnedAdvanced({operation:"trace_source_sink",target:witnessGraph,source_sink:{source_ids:["a"],sink_ids:["b"],relation:"declared-relationships"},timeout_ms:120000});
    if(witness.plan.status!=="completed"||witness.result.status!=="completed"||witness.result.observedExecution!==false||witness.result.witnesses?.length!==1||witness.result.witnesses[0].route.join(",")!=="a,b"||!(await readFile(batchBinary)).equals(batchBinaryBefore)||await readFile(batchAst,"utf8")!==batchAstBefore)throw new Error("Installed source/sink or multi-edit preservation failed");
    stages.push("installed-multiedit-audit-source-sink-originals-preserved");
    const workflowCatalog=await rpc<{recommendations:{command:string;scope:string}[];releaseStatus:string}>(page,"analysis_command_catalog",{environmentId:"local"});
    if(workflowCatalog.recommendations.length!==55||new Set(workflowCatalog.recommendations.map(r=>r.command)).size!==55||workflowCatalog.releaseStatus!=="not-certified-by-catalog")throw new Error("Installed original recommendation ledger is incomplete or falsely certified");
    const ownedWorkflowSource=join(workspace,"owned-workflow.ts"),ownedWorkflowText='export function ownedWorkflow(){ return "owned evidence"; }\n';
    await writeFile(ownedWorkflowSource,ownedWorkflowText);
    const explanation=await runOwnedAdvanced({operation:"explain_behavior",target:ownedWorkflowSource,workflow_query:{symbol:"ownedWorkflow"},timeout_ms:120000});
    if(explanation.plan.status!=="completed"||explanation.result.status!=="partial"||explanation.result.observedExecution!==false||explanation.result.selectedFunction?.sha256!==createHash("sha256").update(ownedWorkflowText).digest("hex")||!explanation.result.selectedFunction?.text.includes('return "owned evidence"')||await readFile(ownedWorkflowSource,"utf8")!==ownedWorkflowText)throw new Error("Installed exact-function evidence failed or changed the original");
    const hypothesis=await runOwnedAdvanced({operation:"verify_hypothesis",target:witnessGraph,hypothesis:{statement:"Owned declared relationship only",kind:"declared-edge",node_id:"a",target_id:"b",relation:"references-candidate",expected:true},timeout_ms:120000});
    if(hypothesis.plan.status!=="completed"||hypothesis.result.status!=="completed"||hypothesis.result.conclusion!=="supported")throw new Error("Installed declared hypothesis verification failed");
    const ownedNotebook=join(workspace,"owned-workflow-notebook.json");
    await writeFile(ownedNotebook,JSON.stringify({schemaVersion:1,title:"Owned preview",cells:[{id:"triage",action:"triage",target:"owned-candidate-input.bin"},{id:"inventory",action:"native_inventory",target:"owned-candidate-input.bin",dependsOn:["triage"]}]}));
    const notebookPreview=await runOwnedAdvanced({operation:"preview_batch",target:ownedNotebook,timeout_ms:120000});
    if(notebookPreview.plan.status!=="completed"||notebookPreview.result.status!=="completed"||notebookPreview.result.executed!==false||notebookPreview.result.stages?.length!==2||notebookPreview.result.stages[1].dependsOn.join(",")!=="triage")throw new Error("Installed static notebook preview failed");
    stages.push("installed-integrated-source-hypothesis-notebook-coverage-passed");
    const ownedApiAfter=join(workspace,"owned-workflow-after.ts");
    await writeFile(ownedApiAfter,'export function ownedWorkflow(x: number): string { return "owned evidence"; }\n');
    const ownedApiComparison=await runOwnedAdvanced({operation:"compare_public_api",target:ownedWorkflowSource,compare_target:ownedApiAfter,timeout_ms:120000});
    if(ownedApiComparison.plan.status!=="completed"||ownedApiComparison.result.comparison?.changed.join(",")!=="<entry>:ownedWorkflow")throw new Error("Installed explicit API signature comparison failed");
    const ownedPackage=join(workspace,"owned-package.json"),ownedLock=join(workspace,"owned-package-lock.json"),ownedLockText=JSON.stringify({lockfileVersion:3,packages:{"node_modules/owned-fixture":{version:"1.2.3"}}});
    await writeFile(ownedPackage,JSON.stringify({dependencies:{"owned-fixture":"^1.0.0"}}));await writeFile(ownedLock,ownedLockText);
    const ownedDependencies=await runOwnedAdvanced({operation:"inspect_dependency_risk",target:ownedPackage,dependency_evidence:{lockfile:ownedLock,lockfile_sha256:createHash("sha256").update(ownedLockText).digest("hex")},timeout_ms:120000});
    if(ownedDependencies.plan.status!=="completed"||ownedDependencies.result.resolvedEvidence?.resolved[0]?.version!=="1.2.3")throw new Error("Installed hash-bound lockfile resolution failed");
    stages.push("installed-explicit-api-signatures-lockfile-evidence-passed");
    const ownedArchiveManifest=join(workspace,"owned-evidence-manifest.json"),ownedArchiveOutput=join(workspace,"owned-evidence.json.gz"),ownedArchiveManifestText=JSON.stringify({schemaVersion:1,title:"Owned installed evidence",entries:[{id:"source",path:"owned-workflow.ts",sha256:createHash("sha256").update(ownedWorkflowText).digest("hex"),kind:"finding",format:"text"}]});
    await writeFile(ownedArchiveManifest,ownedArchiveManifestText);
    const ownedArchive=await runOwnedAdvanced({operation:"export_evidence_bundle",target:ownedArchiveManifest,output_file:ownedArchiveOutput,evidence_archive:{manifest_sha256:createHash("sha256").update(ownedArchiveManifestText).digest("hex")},acknowledge_external_output:true,timeout_ms:120000});
    const ownedArchiveDocument=JSON.parse(gunzipSync(await readFile(ownedArchiveOutput)).toString("utf8"));
    if(ownedArchive.plan.status!=="completed"||ownedArchive.result.published!==true||ownedArchiveDocument.protocol!=="cline-evidence-archive/v1"||ownedArchiveDocument.entries[0]?.sourceSha256!==createHash("sha256").update(ownedWorkflowText).digest("hex")||ownedArchiveDocument.entries[0]?.content!==ownedWorkflowText||await readFile(ownedWorkflowSource,"utf8")!==ownedWorkflowText)throw new Error("Installed approved provenance archive failed");
    stages.push("installed-approved-provenance-archive-originals-preserved");





    const triageScope={sessionId:triageSession.sessionId,environmentId:"local"};
    await rpc(page,"first_party_analysis_mode",{...triageScope,mode:"static"});
    const triageRequestId=randomUUID();
    const triageReceipt=await rpc<{id:string;status:string;resultHash:string;evidence:{data:unknown}}>(page,"binary_triage_run",{...triageScope,confirmed:true,requestId:triageRequestId,input:triageInput});
    if(triageReceipt.status!=="completed"||!JSON.stringify(triageReceipt.evidence.data).includes("cline_owned_fixture")||!/^[a-f0-9]{64}$/.test(triageReceipt.resultHash))throw new Error("Installed owned YARA target receipt failed");
    const report=await rpc<{observed:{targetSha256:string};receipt:{id:string}}>(page,"binary_triage_report",{...triageScope,id:triageReceipt.id});
    if(report.receipt.id!==triageReceipt.id||!/^[a-f0-9]{64}$/.test(report.observed.targetSha256))throw new Error("Installed scoped triage report failed");
    let crossScopeDenied=false;
    try { await rpc(page,"binary_triage_report",{...analysisArgs,id:triageReceipt.id}); } catch { crossScopeDenied=true; }
    if(!crossScopeDenied)throw new Error("Installed report leaked across sessions");
    let replayDenied=false;
    try { await rpc(page,"binary_triage_run",{...triageScope,confirmed:true,requestId:triageRequestId,input:triageInput}); } catch { replayDenied=true; }
    if(!replayDenied)throw new Error("Installed analysis replay was not blocked");
    await writeFile(join(evidence,"binary-triage-owned-report.json"),JSON.stringify(report,null,2));
    stages.push("installed-binary-triage-target-report-scope-and-replay-passed");


    page.once("dialog", async (dialog) => {
      if (dialog.message().includes("reviewed and accept"))
        await dialog.accept();
      else await dialog.dismiss();
    });
    await page
      .getByRole("button", {
        name: "Install all supported components",
        exact: true,
      })
      .click();
    await page.getByLabel("Full capability pack status", { exact: true }).filter({ hasText: /^Ready$/ }).waitFor({ timeout: 240000 });
    const full = await rpc<{
      fullStatus: string;
      features: Array<{ id: string; status: string }>;
      runtime: { runtimeId: string; integrity: string };
    }>(page, "setup_center_status", { environmentId: "local" });
    await writeFile(
      join(evidence, "full-capability-readiness.json"),
      JSON.stringify(full, null, 2),
    );
    const required = [
      "lief",
      "capstone",
      "z3",
      "triton",
      "qbindiff",
      "androguard",
      "miasm",
      "unicorn",
      "angr",
      "qbdi",
      "cryptography",
    ];
    if (
      full.fullStatus !== "Ready" ||
      full.runtime.integrity !== "verified" ||
      !full.runtime.runtimeId.includes("-full-") ||
      full.features.length !== 11 ||
      !required.every(
        (id) =>
          full.features.filter((f) => f.id === id && f.status === "Ready")
            .length === 1,
      )
    )
      throw new Error(
        "Installed full pack did not execute all eleven owned engine fixtures",
      );
    const setupJob = await rpc<{job:{id:string;command:string;status:string}|null}>(page,"setup_center_job_status");
    if (!setupJob.job?.id || setupJob.job.command !== "setup_center_install_full" || setupJob.job.status !== "completed")
      throw new Error("Installed full pack did not retain its completed background setup job");
    if (!(await page.getByLabel("Setup operation status",{exact:true}).textContent())?.includes(setupJob.job.id))
      throw new Error("Installed Setup Center did not show its tracked job beside the actions");
    stages.push("installed-tracked-full-setup-job-passed");
    stages.push("installed-full-eleven-engine-owned-fixtures-passed");
    const ownedDualDecoder=join(workspace,"owned-dual-decoder.bin"),ownedDualBytes=Buffer.from([0x31,0xc0,0x90,0xc3]);
    await writeFile(ownedDualDecoder,ownedDualBytes);
    const ownedCrosscheck=await runOwnedAdvanced({operation:"crosscheck_disassembly",target:ownedDualDecoder,advanced_options:{architecture:"x86_64",offset:0,address:4096,bytes:4},timeout_ms:120000});
    const ownedCrosscheckResult=ownedCrosscheck.result.result;
    if(ownedCrosscheck.plan.status!=="completed"||ownedCrosscheckResult?.status!=="completed"||ownedCrosscheckResult.evidence.boundaryAgreement!==true||ownedCrosscheckResult.evidence.rangeSha256!==createHash("sha256").update(ownedDualBytes).digest("hex")||ownedCrosscheckResult.evidence.decoders.map(d=>d.engine).join(",")!=="capstone,miasm"||!ownedCrosscheckResult.evidence.decoders.every(d=>d.version&&d.decodedBytes===4)||!(await readFile(ownedDualDecoder)).equals(ownedDualBytes))throw new Error("Installed exact-range Capstone/Miasm evidence failed");
    stages.push("installed-full-pack-exact-range-dual-decoder-passed");

    await page.screenshot({ path: join(evidence, "full-capabilities.png") });
    await stop();
    page = await launch();
    await settings(page, "General");
    const persisted = await rpc<{ customAiInstructions?: string }>(
      page,
      "get_desktop_settings",
    );
    if (
      persisted.customAiInstructions !==
      "Installer acceptance: preserve this owned local setting."
    )
      throw new Error("Installed backend setting did not survive restart");
		await verifyRestartInstructions(
      page.getByRole("textbox", {
        name: "Custom AI instructions",
        exact: true,
      }),
			"Installer acceptance: preserve this owned local setting.",
    );

    const resumedFull = await rpc<{
      fullStatus: string;
      runtime: { runtimeId: string };
    }>(page, "setup_center_status", { environmentId: "local" });
    if (
      resumedFull.fullStatus !== "Ready" ||
      !resumedFull.runtime.runtimeId.includes("-full-")
		)
      throw new Error(
        "Full private interpreter selection or actual fixture receipt did not survive restart",
      );
    stages.push("full-pack-selection-and-receipts-survived-restart");
    const sessions = await rpc<Array<{ sessionId: string }>>(
      page,
      "list_chat_sessions",
    );
		if (!sessions.some((item) => item.sessionId === session.sessionId))
      throw new Error("Owned session did not survive installed-app restart");
		await rpc(page, "chat_session_command", {
      request: {
        action: "attach",
        sessionId: session.sessionId,
        config: { environmentId: "local" },
      },
    });
    stages.push("restart-setting-and-session-persistence-passed");
    const beforeHub = JSON.parse(await readFile(discoveryPath, "utf8"));
    if (!Number.isInteger(beforeHub.pid) || beforeHub.pid < 1)
      throw new Error("Owned isolated Hub PID unavailable");
  // This discovery belongs only to this fixture. No user Hub is killed.
    await killOwnedProcess(beforeHub.pid);
    // list_chat_sessions is local SQLite discovery, not a Hub readiness probe.
    // First exercise the real registration/reattachment recovery contract.
    await verifyRecoveredHubSession(
      () => rpc(page, "chat_session_command", {
        request: {
          action: "attach",
          sessionId: session.sessionId,
          config: { environmentId: "local" },
        },
      }),
      () => rpc<Array<{ sessionId: string }>>(page, "list_chat_sessions"),
      session.sessionId,
    );
    const afterHub = JSON.parse(await readFile(discoveryPath, "utf8"));
    if (
      afterHub.pid === beforeHub.pid &&
      afterHub.authToken === beforeHub.authToken
    )
      throw new Error("Hub restart did not refresh discovery identity");
    stages.push("hub-restart-saved-session-reattached-without-prompt-replay");

    await settings(page, "Setup Center");
    page.once("dialog", async (dialog) => await dialog.accept());
    await page
      .getByRole("button", { name: "Roll back to core", exact: true })
      .click();
    await page
      .getByLabel("Full capability pack status", { exact: true }).filter({ hasText: /^Setup needed$/ })
      .waitFor({ timeout: 90000 });
    const rollback = await rpc<{
      runtime: { runtimeId: string; integrity: string };
    }>(page, "setup_center_status", { environmentId: "local" });
    if (
      rollback.runtime.integrity !== "verified" ||
      rollback.runtime.runtimeId.includes("-full-")
    )
      throw new Error(
        "Core rollback failed to select its verified interpreter",
      );
    stages.push("full-to-core-rollback-preserved-owned-session");
    await stop();
    page = await launch();
    await rpc(page, "chat_session_command", {
      request: {
        action: "attach",
        sessionId: session.sessionId,
        config: { environmentId: "local" },
      },
    });
    await writeFile(
      join(evidence, "performance.json"),
      JSON.stringify(
        {
          schemaVersion: 1,
          sourceCommit: process.env.GITHUB_SHA,
          environmentId: `${process.platform}-${process.arch}-${process.env.RUNNER_OS ?? "local"}`,
          workloadVersion: "installed-owned-ui/processor-setup-core-full-core-120-row-v9",
          runtimeProfiles: ["core", "full", "core-after-rollback"],
          metrics: { installedReadyMs: startupSamples, nativeAppWorkingSetMB: appWorkingSetSamples,
            ownedTranscriptScrollRoundTripMs: transcriptScrollSamples },
          units: {installedReadyMs:"milliseconds",nativeAppWorkingSetMB:"MiB",ownedTranscriptScrollRoundTripMs:"milliseconds"},
          baselineStatus: "not-established",
          limitations: [
            "Three candidate observations per metric; no controlled before/after improvement claim.",
            "Includes bounded acceptance phase-journal I/O; earlier v6 runs are not comparable.",
            "Working set includes the launched native app only, not WebView, Hub or analysis worker memory and not a peak-memory benchmark.",
            "Scroll measurements use 120 owned offline rows and two animation frames, not live model work or proof of all long-session workloads.",
          ],
        },
        null,
        2,
      ),
    );
    await stop();
    stages.push("installed-owned-app-cleanup-confirmed");
		await writeFile(
			join(evidence, "summary.json"),
			JSON.stringify(
				{
					status: "passed",
					sourceCommit: process.env.GITHUB_SHA,
					stages,
					modelTurn: "not-requested-idle-session-only",
					idaLicense: "not-validated",
				},
				null,
				2,
			),
    );
    console.log("Installed WebView acceptance passed.");
	} catch (error) {
		const reason = (error instanceof Error ? error.message : String(error))
			.replace(/approval_token=[^&\s]+/g, "approval_token=[REDACTED]")
      .slice(0, 2000);
		// Read only two fixed fixture-owned logs, each at most 64 KiB, redacted.
    let hubStartupDiagnostic = "";
    for (const [leaf, evidenceLeaf] of [["code.log", "owned-backend-tail.log"],
      ["hub-daemon.log", "owned-hub-daemon-tail.log"]] as const) {
  try {
   const log = await open(join(root, "data", "logs", leaf), "r");
   try {
    const info = await log.stat();
    if (info.isFile() && info.size <= 50 * 1024 * 1024) {
     const buffer = Buffer.alloc(Math.min(info.size, 64 * 1024));
          const { bytesRead } = await log.read(
            buffer,
            0,
            buffer.length,
            Math.max(0, info.size - buffer.length),
          );
          const tail = redactedLaunchText(buffer.subarray(0, bytesRead).toString("utf8"));
          await writeFile(join(evidence, evidenceLeaf), tail);
          if (leaf === "hub-daemon.log") hubStartupDiagnostic = tail.slice(-1600);
    }
	} finally {
        await log.close();
      }
    } catch {
      /* Diagnostics do not substitute for the strict acceptance result. */
    }
    }
    await writeFile(
      join(evidence, "summary.json"),
      JSON.stringify({ status: "failed", stages, lastAction, reason, hubStartupDiagnostic }, null, 2),
    );
    throw new Error(reason);
  } finally {
    await stop();
		// This fixture created the discovery directory; no arbitrary user PID is read.
		try {
      const hub = JSON.parse(await readFile(discoveryPath, "utf8"));
      if (Number.isInteger(hub.pid) && hub.pid > 0)
        await killOwnedProcess(hub.pid);
		} catch {
			/* Empty isolated fixture; retain files for runner diagnostics. */
		}
	}
}
export async function runAcceptance() {
	try {
    await main();
	} catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
	}
}
if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
)
  void runAcceptance();
