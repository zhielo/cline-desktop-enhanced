/**
 * Windows CI only: attach to the installed app's own WebView2.
 * No dev web server, model credential, browser download, or production test bypass.
 */

import { spawn } from "node:child_process"
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises"
import { createServer } from "node:net"
import { tmpdir } from "node:os"
import { basename, isAbsolute, join, resolve } from "node:path"
import { setTimeout as delay } from "node:timers/promises"
import { fileURLToPath } from "node:url"
import { type Browser, chromium, type Locator, type Page } from "playwright"

export function startAcceptanceProcess(executable: string, args: string[], cwd: string, env: NodeJS.ProcessEnv) {
	const startedAt = new Date().toISOString()
	const child = spawn(executable, args, { cwd, env, shell: false, windowsHide: false, stdio: ["ignore", "pipe", "pipe"] })
	const diagnostics = { stdoutTail: "", stderrTail: "", launchError: "" }
	const limit = 16 * 1024
	child.stdout?.setEncoding("utf8")
	child.stderr?.setEncoding("utf8")
	child.stdout?.on("data", (data: string) => {
		diagnostics.stdoutTail = (diagnostics.stdoutTail + data).slice(-limit)
	})
	child.stderr?.on("data", (data: string) => {
		diagnostics.stderrTail = (diagnostics.stderrTail + data).slice(-limit)
	})
	const exited = new Promise<number | null>((done) => {
		child.once("error", (error) => {
			diagnostics.launchError = error.message
			done(null)
		})
		child.once("exit", (code) => done(code))
	})
	const closed = new Promise<void>((done) => child.once("close", () => done()))
	return { child, exited, closed, diagnostics, startedAt }
}

// A settings textbox is disabled until the asynchronous persisted-settings read settles.
// Trial click waits for that actual UI readiness, not an arbitrary sleep or value retry.
export async function verifyRestartInstructions(instructions: Locator, expected: string) {
	await instructions.click({ trial: true, timeout: 30_000 })
	if ((await instructions.inputValue()) !== expected) throw new Error("Installed UI setting did not survive restart")
}

type ProcessMetadata = {
	name: string
	pid: number
	parentPid: number
	createdAt: string
	debuggingArgumentObserved: boolean
	ownedProfileObserved: boolean
}
export function ownedDescendantMetadata(snapshot: ProcessMetadata[], rootPid: number, startedAt: string, rootName: string) {
	const root = snapshot.find((p) => p.pid === rootPid)
	if (
		!root ||
		root.name.toLowerCase() !== rootName.toLowerCase() ||
		!Number.isFinite(Date.parse(root.createdAt)) ||
		!Number.isFinite(Date.parse(startedAt)) ||
		Date.parse(root.createdAt) < Date.parse(startedAt) - 1000
	)
		return []
	const seen = new Set([rootPid])
	let parents = [root]
	const owned: ProcessMetadata[] = []
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
		)
		for (const child of children) {
			seen.add(child.pid)
			owned.push(child)
		}
		parents = children
	}
	return owned.slice(0, 64)
}

function redactedLaunchText(text: string) {
	return text
		.replace(/approval_token=[^&\s]+/gi, "approval_token=[REDACTED]")
		.replace(/Bearer\s+\S+/gi, "Bearer [REDACTED]")
		.replace(/("(?:authToken|token|apiKey|password|secret)"\s*:\s*")[^"]*"/gi, '$1[REDACTED]"')
		.replace(/\b[0-9a-f]{32,}\b/gi, "[REDACTED]")
}

export async function main() {
	const executable = process.env.CLINE_TEST_INSTALLED_APP
	const sidecar = process.env.CLINE_TEST_INSTALLED_SIDECAR
	if (process.platform !== "win32" || !executable || !isAbsolute(executable))
		throw new Error("Absolute installed Windows application path required")
	if (!sidecar || !isAbsolute(sidecar)) throw new Error("Absolute installed sidecar path required for isolated Hub bootstrap")
	const root = await mkdtemp(join(tmpdir(), "cline-installed-ui-"))
	const workspace = join(root, "owned-workspace")
	const evidence = join(process.cwd(), "dist", "installed-ui-evidence")
	await mkdir(workspace)
	await mkdir(evidence, { recursive: true })
	await writeFile(join(workspace, "OWNED_FIXTURE.txt"), "Deterministic installer acceptance fixture.\n")
	let port = 0
	const discoveryPath = join(root, "hub.json")
	const environment = Object.fromEntries(
		Object.entries(process.env).filter(
			([key]) =>
				!/^(CLINE_|OTEL_|TELEMETRY_|ERROR_SERVICE_)/.test(key) &&
				!/(API_KEY|TOKEN|PASSWORD|SECRET|PRIVATE_KEY|CREDENTIAL)/i.test(key),
		),
	)
	Object.assign(environment, {
		CLINE_INSTALLED_ACCEPTANCE: "1",
		CLINE_DIR: root,
		CLINE_DATA_DIR: join(root, "data"),
		CLINE_HUB_DISCOVERY_PATH: discoveryPath,
		WEBVIEW2_USER_DATA_FOLDER: join(root, "webview-profile"),
	})
	let app: ReturnType<typeof startAcceptanceProcess> | undefined
	let browser: Browser | undefined
	const stages: string[] = []
	let launchNumber = 0
 const startupSamples:number[]=[]
	const taskkill = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "taskkill.exe")

	async function killOwnedProcess(pid: number) {
		const killer = startAcceptanceProcess(taskkill, ["/PID", String(pid), "/T", "/F"], workspace, environment)
		await killer.exited
	}

	async function retainLaunchReceipt(lastConnectionError: string, lastHttpStatus: number | null) {
		if (!app) return
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
`
		const powershell = join(
			process.env.SystemRoot ?? "C:\\Windows",
			"System32",
			"WindowsPowerShell",
			"v1.0",
			"powershell.exe",
		)
		const probe = startAcceptanceProcess(powershell, ["-NoProfile", "-NonInteractive", "-Command", command], workspace, {
			...environment,
			ACCEPTANCE_APP_PID: String(app.child.pid),
			ACCEPTANCE_CDP_PORT: String(port),
			ACCEPTANCE_PROFILE: environment.WEBVIEW2_USER_DATA_FOLDER,
		})
		const probeCode = await Promise.race([probe.exited, delay(10_000, null, { ref: false })])
		if (probeCode === null && probe.child.pid) await killOwnedProcess(probe.child.pid)
		let descendants: unknown = []
		try {
			if (probeCode === 0)
				descendants = ownedDescendantMetadata(
					JSON.parse(probe.diagnostics.stdoutTail),
					app.child.pid!,
					app.startedAt,
					basename(executable!),
				)
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
		)
	}

	async function launch() {
  const startupStarted=performance.now()
		// Allocate only after Hub bootstrap, immediately before app launch. The
		// isolated Hub must not claim a port reserved and released much earlier.
		const listener = createServer()
		await new Promise<void>((done) => listener.listen(0, "127.0.0.1", done))
		port = (listener.address() as { port: number }).port
		await new Promise<void>((done) => listener.close(() => done()))
		environment.WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = `--remote-debugging-port=${port} --remote-debugging-address=127.0.0.1`
		launchNumber++
		app = startAcceptanceProcess(executable!, [], workspace, environment)
		let lastConnectionError = ""
		let lastHttpStatus: number | null = null
		const deadline = Date.now() + 60_000
		while (Date.now() < deadline) {
			if (app.diagnostics.launchError || app.child.exitCode !== null) {
				await retainLaunchReceipt(lastConnectionError, lastHttpStatus)
				throw new Error("Installed app launch failed; inspect the bounded launch receipt")
			}
			try {
				const response = await fetch(`http://127.0.0.1:${port}/json/version`, { signal: AbortSignal.timeout(1000) })
				lastHttpStatus = response.status
				if (response.ok) {
					browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, { timeout: 10_000 })
					break
				}
			} catch (error) {
				lastConnectionError = error instanceof Error ? error.message : String(error)
			}
			await delay(250)
		}
		await retainLaunchReceipt(lastConnectionError, lastHttpStatus)
		if (!browser) throw new Error("Installed WebView2 did not expose its test-only CDP port")
		const pageDeadline = Date.now() + 30_000
		let page: Page | undefined
		while (!page && Date.now() < pageDeadline) {
			page = browser
				.contexts()
				.flatMap((context) => context.pages())
				.find((candidate) => /tauri\.localhost|tauri:\/\/localhost/.test(candidate.url()))
			if (!page) await delay(100)
		}
		if (!page) throw new Error("Installed app webview page unavailable")
		page.setDefaultTimeout(30_000)
		await page.waitForFunction(() => Boolean((window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__))
		// Skip only first-run onboarding in an empty test profile, not app authentication.
		await page.evaluate(() =>
			localStorage.setItem("cline.code.onboarding.v1", JSON.stringify({ completedAt: new Date().toISOString() })),
		)
		await page.reload()
		await page.getByRole("button", { name: "Settings", exact: true }).first().waitFor()
  startupSamples.push(performance.now()-startupStarted)
		return page
	}

	async function rpc<T>(page: Page, command: string, args: Record<string, unknown> = {}): Promise<T> {
		return (await page.evaluate(
			async ({ command, args }) => {
				const native = (window as unknown as { __TAURI_INTERNALS__: { invoke: (name: string) => Promise<string> } })
					.__TAURI_INTERNALS__
				const endpoint = await native.invoke("get_desktop_backend_endpoint")
				return await new Promise((resolve, reject) => {
					const socket = new WebSocket(endpoint)
					const id = crypto.randomUUID()
					const timer = setTimeout(() => {
						socket.close()
						reject(new Error(`Installed RPC timed out: ${command}`))
					}, 90_000)
					const finish = () => {
						clearTimeout(timer)
						socket.close()
					}
					socket.onopen = () => socket.send(JSON.stringify({ type: "command", id, command, args }))
					socket.onmessage = (event) => {
						const reply = JSON.parse(String(event.data))
						if (reply.type !== "response" || reply.id !== id) return
						finish()
						if (reply.ok) resolve(reply.result)
						else reject(new Error(`Installed command failed: ${command}`))
					}
					socket.onerror = () => {
						finish()
						reject(new Error("Installed authenticated transport failed"))
					}
				})
			},
			{ command, args },
		)) as T
	}
	async function settings(page: Page, section: string) {
		await page.getByRole("button", { name: "Settings", exact: true }).first().click()
		await page
			.getByRole("navigation", { name: "Settings sections" })
			.getByRole("button", { name: section, exact: true })
			.click()
	}
	async function stop() {
		if (browser) {
			await browser.close()
			browser = undefined
		}
		if (app && app.child.exitCode === null && app.child.pid) {
			await killOwnedProcess(app.child.pid)
			await app.exited
		}
		app = undefined
	}

	try {
		// Use the installed sidecar to bootstrap an isolated Hub on an OS-assigned port.
		// A default Hub left by the earlier GUI smoke must never satisfy this fixture.
		const bootstrap = startAcceptanceProcess(
			sidecar,
			["--remote-hub-ensure", "--discovery-path", discoveryPath, "--cwd", workspace],
			workspace,
			environment,
		)
		const bootCode = await Promise.race([bootstrap.exited, delay(45_000, null, { ref: false })])
		if (bootCode === null) {
			if (bootstrap.child.pid) await killOwnedProcess(bootstrap.child.pid)
			throw new Error("Installed sidecar isolated Hub bootstrap timed out")
		}
		if (bootCode !== 0) throw new Error(`Installed sidecar isolated Hub bootstrap failed: ${bootCode}`)
		const isolatedHub = JSON.parse(await readFile(discoveryPath, "utf8"))
		if (!Number.isInteger(isolatedHub.port) || isolatedHub.port < 1 || isolatedHub.port > 65535)
			throw new Error("Isolated Hub did not publish a valid port")
		environment.CLINE_HUB_PORT = String(isolatedHub.port)
		stages.push("installed-sidecar-isolated-hub-bootstrapped")
		let page = await launch()
		stages.push("installed-webview-rendered")
		// Create an idle session with explicit local configuration: no paid/live model turn.
		const session = await rpc<{ sessionId: string }>(page, "chat_session_command", {
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
					initialMessages: [{ id: "installer-owned-message", role: "user", content: "Installer owned session" }],
				},
			},
		})
		if (!session.sessionId) throw new Error("Installed session creation failed")
		await rpc(page, "update_chat_session_title", {
			sessionId: session.sessionId,
			environmentId: "local",
			title: "Installer owned session",
		})
		await page.reload()
		await page
			.getByRole("button", { name: /Installer owned session/ })
			.first()
			.click()
		stages.push("owned-workspace-idle-session-opened")
		await settings(page, "General")
		const instructions = page.getByRole("textbox", { name: "Custom AI instructions", exact: true })
		await instructions.fill("Installer acceptance: preserve this owned local setting.")
		await page.getByRole("button", { name: "Save instructions", exact: true }).click()
		await page.getByText(/Saved permanently/).waitFor()
		stages.push("local-setting-persisted-through-ui")
		await settings(page, "Analysis environment")
		await page.getByRole("button", { name: "Check analysis readiness", exact: true }).click()
		await page.getByText("Fixture execution: completed.", { exact: false }).waitFor({ timeout: 90_000 })
		const ready = await rpc<{ configured: boolean; runtime: { source: string }; readiness: { status: string }; interpreter: { executable: string } }>(
			page,
			"get_analysis_environment",
			{ environmentId: "local" },
		)
		if (
			!ready.configured ||
			ready.readiness.status !== "completed" ||
			ready.runtime?.source !== "bundled" || !ready.interpreter.executable.replaceAll("\\", "/").toLowerCase().includes("/resources/analysis-runtime/python.exe")
		)
			throw new Error("Installed application did not validate its bundled interpreter without CLINE_RE_PYTHON")
		stages.push("installed-interpreter-owned-fixtures-passed")
		await page.screenshot({ path: join(evidence, "readiness.png") })
		await stop()
		page = await launch()
		await settings(page, "General")
		const persisted = await rpc<{ customAiInstructions?: string }>(page, "get_desktop_settings")
		if (persisted.customAiInstructions !== "Installer acceptance: preserve this owned local setting.")
			throw new Error("Installed backend setting did not survive restart")
		await verifyRestartInstructions(
			page.getByRole("textbox", { name: "Custom AI instructions", exact: true }),
			"Installer acceptance: preserve this owned local setting.",
		)
		const sessions = await rpc<Array<{ sessionId: string }>>(page, "list_chat_sessions")
		if (!sessions.some((item) => item.sessionId === session.sessionId))
			throw new Error("Owned session did not survive installed-app restart")
		await rpc(page, "chat_session_command", {
			request: { action: "attach", sessionId: session.sessionId, config: { environmentId: "local" } },
		})
		stages.push("restart-setting-and-session-persistence-passed")
  const beforeHub=JSON.parse(await readFile(discoveryPath,"utf8"))
  if(!Number.isInteger(beforeHub.pid)||beforeHub.pid<1)throw new Error("Owned isolated Hub PID unavailable")
  // This discovery belongs only to this fixture. No user Hub is killed.
  await killOwnedProcess(beforeHub.pid)
  const recoveredSessions=await rpc<Array<{sessionId:string}>>(page,"list_chat_sessions")
  if(!recoveredSessions.some(item=>item.sessionId===session.sessionId))throw new Error("Saved session missing after Hub restart")
  await rpc(page,"chat_session_command",{request:{action:"attach",sessionId:session.sessionId,config:{environmentId:"local"}}})
  const afterHub=JSON.parse(await readFile(discoveryPath,"utf8"))
  if(afterHub.pid===beforeHub.pid&&afterHub.authToken===beforeHub.authToken)throw new Error("Hub restart did not refresh discovery identity")
  stages.push("hub-restart-saved-session-reattached-without-prompt-replay")
  await stop();page=await launch()
  await rpc(page,"chat_session_command",{request:{action:"attach",sessionId:session.sessionId,config:{environmentId:"local"}}})
  await writeFile(join(evidence,"performance.json"),JSON.stringify({schemaVersion:1,sourceCommit:process.env.GITHUB_SHA,environmentId:`${process.platform}-${process.arch}-${process.env.RUNNER_OS??"local"}`,workloadVersion:"installed-owned-ui-startup/v1",metrics:{installedReadyMs:startupSamples},baselineStatus:"not-established",limitations:["Three candidate startup samples, not an improvement claim or idle/peak RAM benchmark."]},null,2))
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
		)
		console.log("Installed WebView acceptance passed.")
	} catch (error) {
		const reason = (error instanceof Error ? error.message : String(error))
			.replace(/approval_token=[^&\s]+/g, "approval_token=[REDACTED]")
			.slice(0, 2000)
		await writeFile(join(evidence, "summary.json"), JSON.stringify({ status: "failed", stages, reason }, null, 2))
		throw new Error(reason)
	} finally {
		await stop()
		// This fixture created the discovery directory; no arbitrary user PID is read.
		try {
			const hub = JSON.parse(await readFile(discoveryPath, "utf8"))
			if (Number.isInteger(hub.pid) && hub.pid > 0) await killOwnedProcess(hub.pid)
		} catch {
			/* Empty isolated fixture; retain files for runner diagnostics. */
		}
	}
}
export async function runAcceptance() {
	try {
		await main()
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error))
		process.exitCode = 1
	}
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) void runAcceptance()
