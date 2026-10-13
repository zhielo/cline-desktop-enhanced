/**
 * Windows CI only: attach to the installed app's own WebView2.
 * No dev web server, model credential, browser download, or production test bypass.
 */

import {OWNED_MANAGED_BASE64,OWNED_MANAGED_SHA256,OWNED_EH_BASE64,OWNED_EH_SHA256} from "../../../sdk/packages/core/scripts/owned-managed-fixture.mjs";
import { createHash,randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, open, readFile, writeFile } from "node:fs/promises";
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
  await writeFile(join(workspace, "OWNED_SCROLL_REPORT.md"), Array.from({length: 240}, (_, i) => `Owned Markdown scroll line ${i}`).join("\n"));
  await writeFile(join(workspace,"owned-main.js"),'import {ipcMain} from "electron"; ipcMain.handle("owned:fixture", () => 42);');
  await writeFile(join(workspace,"owned-renderer.js"),'import {ipcRenderer} from "electron"; ipcRenderer.invoke("owned:fixture");');
  const analysisCurrent=join(workspace,"owned-analysis-current"), analysisPrevious=join(workspace,"owned-analysis-previous");
  await mkdir(analysisCurrent);await mkdir(analysisPrevious);
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
    await killer.exited;
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
		await page.evaluate(() =>
      localStorage.setItem(
        "cline.code.onboarding.v1",
        JSON.stringify({ completedAt: new Date().toISOString() }),
      ),
    );
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
		const endpoint = await waitForInstalledBackendEndpoint(() => page.evaluate(async () => {
			const native = (window as unknown as {
				__TAURI_INTERNALS__: { invoke: (name: string) => Promise<string> };
			}).__TAURI_INTERNALS__;
			return await native.invoke("get_desktop_backend_endpoint");
		}));
		return (await page.evaluate(
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
    )) as T;
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
		if (browser) {
      await browser.close();
      browser = undefined;
		}
		if (app && app.child.exitCode === null && app.child.pid) {
      await killOwnedProcess(app.child.pid);
      await app.exited;
		}
    app = undefined;
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
    // Exercise the installed app's actual event receivers against our own blank
    // WebView. Never attach to user browsers or execute a supplied target.
    const captureBrowserId=randomUUID();
    const nativeCaptureInvoke=<T,>(name:string,args:Record<string,unknown>)=>page.evaluate(async({name,args})=>{
      const native=(window as unknown as {__TAURI_INTERNALS__:{invoke:(name:string,args:Record<string,unknown>)=>Promise<unknown>}}).__TAURI_INTERNALS__;
      return await native.invoke(name,args);
    },{name,args}) as Promise<T>;
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
    await page.waitForFunction(()=>{const select=document.querySelector<HTMLSelectElement>('#session-analysis-mode');return select?.value==="static"&&!select.disabled;});
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
    await page.getByLabel("Session Analysis mode",{exact:true}).selectOption("off");
    await page.waitForFunction(()=>{const select=document.querySelector<HTMLSelectElement>('#session-analysis-mode');return select?.value==="off"&&!select.disabled;});
    await page.getByRole("button",{name:"Open Analysis Workspace",exact:true}).click();
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
      await page.evaluate(() => new Promise<void>(done => requestAnimationFrame(() => requestAnimationFrame(() => done()))));
      transcriptScrollSamples.push(performance.now() - started);
    }
    stages.push("owned-120-row-transcript-scroll-acceptance-passed");
    await page.locator('a[data-cline-file-reference="./OWNED_SCROLL_REPORT.md"]').last().click();
    const preview = page.getByTestId("artifact-preview-scroll");
    await preview.waitFor({state: "visible"});
    if (!(await preview.evaluate(el => el.scrollHeight > el.clientHeight))) throw new Error("Owned Markdown preview is not independently scrollable");
    const box = await preview.boundingBox();
    if (!box || box.y < 0 || box.y + box.height > (page.viewportSize()?.height ?? await page.evaluate(() => innerHeight))) throw new Error("Markdown preview exceeds viewport");
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
          workloadVersion: "installed-owned-ui/processor-setup-core-full-core-120-row-v6",
          runtimeProfiles: ["core", "full", "core-after-rollback"],
          metrics: { installedReadyMs: startupSamples, nativeAppWorkingSetMB: appWorkingSetSamples,
            ownedTranscriptScrollRoundTripMs: transcriptScrollSamples },
          units: {installedReadyMs:"milliseconds",nativeAppWorkingSetMB:"MiB",ownedTranscriptScrollRoundTripMs:"milliseconds"},
          baselineStatus: "not-established",
          limitations: [
            "Three candidate observations per metric; no controlled before/after improvement claim.",
            "Working set includes the launched native app only, not WebView, Hub or analysis worker memory and not a peak-memory benchmark.",
            "Scroll measurements use 120 owned offline rows and two animation frames, not live model work or proof of all long-session workloads.",
          ],
        },
        null,
        2,
      ),
    );
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
      JSON.stringify({ status: "failed", stages, reason, hubStartupDiagnostic }, null, 2),
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
