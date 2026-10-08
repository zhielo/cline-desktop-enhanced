/**
 * Windows CI only: attach to the installed app's own WebView2.
 * No dev web server, model credential, browser download, or production test bypass.
 */
import { chromium, type Browser, type Page } from "playwright"
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, isAbsolute } from "node:path"
import { createServer } from "node:net"

async function main() {
	const executable = process.env.CLINE_TEST_INSTALLED_APP
	const sidecar = process.env.CLINE_TEST_INSTALLED_SIDECAR
	if (process.platform !== "win32" || !executable || !isAbsolute(executable))
		throw new Error("Absolute installed Windows application path required")
	if (!process.env.CLINE_RE_PYTHON || !isAbsolute(process.env.CLINE_RE_PYTHON))
		throw new Error("Installed-app readiness requires a trusted absolute CLINE_RE_PYTHON")
	if (!sidecar || !isAbsolute(sidecar)) throw new Error("Absolute installed sidecar path required for isolated Hub bootstrap")
	const root = await mkdtemp(join(tmpdir(), "cline-installed-ui-"))
	const workspace = join(root, "owned-workspace")
	const evidence = join(process.cwd(), "dist", "installed-ui-evidence")
	await mkdir(workspace)
	await mkdir(evidence, { recursive: true })
	await writeFile(join(workspace, "OWNED_FIXTURE.txt"), "Deterministic installer acceptance fixture.\n")
	const listener = createServer()
	await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve))
	const port = (listener.address() as { port: number }).port
	await new Promise<void>((resolve) => listener.close(() => resolve()))
	const discoveryPath = join(root, "hub.json")
	const environment = Object.fromEntries(
		Object.entries(process.env).filter(
			([key]) =>
				!/^(CLINE_|OTEL_|TELEMETRY_|ERROR_SERVICE_)/.test(key) &&
				!/(API_KEY|TOKEN|PASSWORD|SECRET|PRIVATE_KEY|CREDENTIAL)/i.test(key),
		),
	)
	Object.assign(environment, {
		CLINE_DIR: root,
		CLINE_DATA_DIR: join(root, "data"),
		CLINE_HUB_DISCOVERY_PATH: discoveryPath,
		CLINE_RE_PYTHON: process.env.CLINE_RE_PYTHON,
		WEBVIEW2_USER_DATA_FOLDER: join(root, "webview-profile"),
		WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${port} --remote-debugging-address=127.0.0.1`,
	})
	let app: ReturnType<typeof Bun.spawn> | undefined
	let browser: Browser | undefined
	const stages: string[] = []

	async function launch() {
		app = Bun.spawn([executable!], { cwd: workspace, env: environment, stdout: "ignore", stderr: "ignore" })
		const deadline = Date.now() + 60_000
		while (Date.now() < deadline) {
			if (app.exitCode !== null) throw new Error(`Installed app exited: ${app.exitCode}`)
			try {
				const response = await fetch(`http://127.0.0.1:${port}/json/version`, { signal: AbortSignal.timeout(1000) })
				if (response.ok) {
					browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, { timeout: 10_000 })
					break
				}
			} catch {
				/* Bounded cold WebView2 startup. No unbounded retries. */
			}
			await Bun.sleep(250)
		}
		if (!browser) throw new Error("Installed WebView2 did not expose its test-only CDP port")
		const pageDeadline = Date.now() + 30_000
		let page: Page | undefined
		while (!page && Date.now() < pageDeadline) {
			page = browser
				.contexts()
				.flatMap((context) => context.pages())
				.find((candidate) => /tauri\.localhost|tauri:\/\/localhost/.test(candidate.url()))
			if (!page) await Bun.sleep(100)
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
		if (app && app.exitCode === null) {
			await Bun.spawn(["taskkill", "/PID", String(app.pid), "/T", "/F"], { stdout: "ignore", stderr: "ignore" }).exited
			await app.exited
		}
		app = undefined
	}

	try {
		// Use the installed sidecar to bootstrap an isolated Hub on an OS-assigned port.
		// A default Hub left by the earlier GUI smoke must never satisfy this fixture.
		const bootstrap = Bun.spawn([sidecar, "--remote-hub-ensure", "--discovery-path", discoveryPath, "--cwd", workspace], {
			cwd: workspace,
			env: environment,
			stdin: "ignore",
			stdout: "ignore",
			stderr: "ignore",
		})
		const bootCode = await Promise.race([bootstrap.exited, Bun.sleep(45_000).then(() => null)])
		if (bootCode === null) {
			await Bun.spawn(["taskkill", "/PID", String(bootstrap.pid), "/T", "/F"], { stdout: "ignore", stderr: "ignore" })
				.exited
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
		const ready = await rpc<{ configured: boolean; readiness: { status: string }; interpreter: { executable: string } }>(
			page,
			"get_analysis_environment",
			{ environmentId: "local" },
		)
		if (
			!ready.configured ||
			ready.readiness.status !== "completed" ||
			ready.interpreter.executable.replaceAll("\\", "/").toLowerCase() !== process.env.CLINE_RE_PYTHON!.replaceAll("\\", "/").toLowerCase()
		)
			throw new Error("Installed application did not validate its configured interpreter")
		stages.push("installed-interpreter-owned-fixtures-passed")
		await page.screenshot({ path: join(evidence, "readiness.png") })
		await stop()
		page = await launch()
		await settings(page, "General")
		if (
			(await page.getByRole("textbox", { name: "Custom AI instructions", exact: true }).inputValue()) !==
			"Installer acceptance: preserve this owned local setting."
		)
			throw new Error("Installed UI setting did not survive restart")
		const sessions = await rpc<Array<{ sessionId: string }>>(page, "list_chat_sessions")
		if (!sessions.some((item) => item.sessionId === session.sessionId))
			throw new Error("Owned session did not survive installed-app restart")
		await rpc(page, "chat_session_command", {
			request: { action: "attach", sessionId: session.sessionId, config: { environmentId: "local" } },
		})
		stages.push("restart-setting-and-session-persistence-passed")
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
			if (Number.isInteger(hub.pid) && hub.pid > 0)
				await Bun.spawn(["taskkill", "/PID", String(hub.pid), "/T", "/F"], { stdout: "ignore", stderr: "ignore" }).exited
		} catch {
			/* Empty isolated fixture; retain files for runner diagnostics. */
		}
	}
}
void main().catch((error) => {
	console.error(error instanceof Error ? error.message : String(error))
	process.exitCode = 1
})
