import { gunzipSync } from "node:zlib"
/**
 * Windows CI only: attach to the installed app's own WebView2.
 * No dev web server, model credential, browser download, or production test bypass.
 */

import {
	OWNED_MANAGED_BASE64,
	OWNED_MANAGED_SHA256,
	OWNED_EH_BASE64,
	OWNED_EH_SHA256,
} from "../../../sdk/packages/core/scripts/owned-managed-fixture.mjs"
import { createHash, randomUUID } from "node:crypto"
import { readFileSync, realpathSync } from "node:fs"
import { spawn } from "node:child_process"
import { appendFile, mkdir, mkdtemp, open, readFile, stat, writeFile } from "node:fs/promises"
import { createServer } from "node:net"
import { tmpdir } from "node:os"
import { basename, isAbsolute, join, resolve } from "node:path"
import { setTimeout as delay } from "node:timers/promises"
import { fileURLToPath } from "node:url"
import { type Browser, chromium, type Locator, type Page } from "playwright"

const INSTALLED_INVESTIGATION_PLUGIN = "cline-investigation"
const INSTALLED_INVESTIGATION_NAMES = [
	"investigate-artifact",
	"analyze-electron",
	"compare-applications",
	"investigate-native",
	"investigate-android",
	"review-candidate",
]
type InstalledInvestigationCatalog = {
	bundledInvestigationSkills: { status: string; root?: string; paths: string[]; skills: string[] }
	skills: Array<{
		id: string
		description?: string
		instructions?: string
		enabled?: boolean
		agentPlugin?: boolean
		pluginName?: string
	}>
	runtimeCommands: Array<{ id: string; name: string; kind: string; instructions: string }>
	plugins: Array<{
		name: string
		path: string
		enabled: boolean
		agentPlugin: boolean
		toggleable: boolean
		loadError?: string
	}>
}
/** Assertions consume only catalog metadata/instructions, never invoke a model or target. */
export function verifyInstalledInvestigationCatalog(
	catalog: InstalledInvestigationCatalog,
	enabled: boolean,
	expectedRoot: string,
) {
	const pack = catalog.bundledInvestigationSkills
	if (
		pack.status !== "available" ||
		pack.root !== expectedRoot ||
		JSON.stringify(pack.paths) !== JSON.stringify([expectedRoot]) ||
		JSON.stringify(pack.skills) !== JSON.stringify(INSTALLED_INVESTIGATION_NAMES)
	)
		throw new Error("Installed investigation resource identity missing or changed")
	const plugins = catalog.plugins.filter((p) => p.name === INSTALLED_INVESTIGATION_PLUGIN)
	if (
		plugins.length !== 1 ||
		plugins[0].path !== expectedRoot ||
		!plugins[0].agentPlugin ||
		!plugins[0].toggleable ||
		plugins[0].enabled !== enabled ||
		plugins[0].loadError
	)
		throw new Error("Installed investigation plugin state mismatch")
	const expected = INSTALLED_INVESTIGATION_NAMES.map((name) => `${INSTALLED_INVESTIGATION_PLUGIN}:${name}`)
	const skills = catalog.skills.filter((s) => s.id.startsWith(`${INSTALLED_INVESTIGATION_PLUGIN}:`))
	const commands = catalog.runtimeCommands.filter((s) => s.id.startsWith(`${INSTALLED_INVESTIGATION_PLUGIN}:`))
	if (!enabled) {
		if (skills.length || commands.length) throw new Error("Disabled installed investigation skills remained available")
	} else {
		if (
			JSON.stringify(skills.map((s) => s.id).sort()) !== JSON.stringify([...expected].sort()) ||
			JSON.stringify(commands.map((s) => s.id).sort()) !== JSON.stringify([...expected].sort()) ||
			skills.some(
				(s) =>
					s.enabled === false ||
					s.agentPlugin !== true ||
					s.pluginName !== INSTALLED_INVESTIGATION_PLUGIN ||
					!s.description ||
					!s.instructions?.includes("receipt"),
			) ||
			commands.some((s) => s.kind !== "skill" || !s.instructions.includes("receipt"))
		)
			throw new Error("Installed investigation instruction catalog incomplete")
	}
	return plugins[0].path
}

/** Page-local acceptance transport. Reuse one authenticated socket rather than
 * opening hundreds during the full journey. Correlate responses, never replay a
 * request after errors, endpoint changes, timeouts or page/native restarts. This
 * is a test driver only; product authentication and approvals are unchanged. */
export function installedBrowserRpc({
	command,
	args,
	endpoint,
}: {
	command: string
	args: Record<string, unknown>
	endpoint: string
}): Promise<unknown> {
	type Pending = {
		resolve: (value: unknown) => void
		reject: (error: Error) => void
		timer: ReturnType<typeof setTimeout>
		message: string
		sent: boolean
	}
	type Transport = {
		endpoint: string
		socket: WebSocket
		pending: Map<string, Pending>
		retired: boolean
		retire: (error: Error) => void
	}
	const host = globalThis as typeof globalThis & { __clineInstalledAcceptanceRpcV1?: Transport }
	const sanitize = (value: unknown) =>
		String(value ?? "Unknown backend error")
			.replace(/approval_token=[^&\s]+/gi, "approval_token=[REDACTED]")
			.replace(/Bearer\s+\S+/gi, "Bearer [REDACTED]")
			.replace(/\b[0-9a-f]{32,}\b/gi, "[REDACTED]")
			.slice(0, 1500)
	let state = host.__clineInstalledAcceptanceRpcV1
	if (state && state.endpoint !== endpoint) {
		state.retire(new Error("Installed endpoint changed; outstanding RPC was not replayed"))
		state = undefined
	}
	if (state?.retired || state?.socket.readyState === WebSocket.CLOSED || state?.socket.readyState === WebSocket.CLOSING)
		state = undefined
	if (!state) {
		const socket = new WebSocket(endpoint)
		const created: Transport = { endpoint, socket, pending: new Map(), retired: false, retire: () => {} }
		created.retire = (error) => {
			if (created.retired) return
			created.retired = true
			for (const entry of created.pending.values()) {
				clearTimeout(entry.timer)
				entry.reject(error)
			}
			created.pending.clear()
			try {
				socket.close()
			} catch {
				/* failure still rejects; never retry */
			}
		}
		const send = (entry: Pending) => {
			if (entry.sent || created.retired) return
			entry.sent = true // Mark before send: a throwing send must not be replayed.
			try {
				socket.send(entry.message)
			} catch {
				created.retire(new Error("Installed RPC send failed; request was not replayed"))
			}
		}
		socket.onopen = () => {
			for (const entry of created.pending.values()) send(entry)
		}
		socket.onmessage = (event) => {
			let reply: { type?: string; id?: string; ok?: boolean; result?: unknown; error?: unknown }
			try {
				reply = JSON.parse(String(event.data))
			} catch {
				created.retire(new Error("Installed RPC received malformed transport data"))
				return
			}
			if (!reply || reply.type !== "response" || typeof reply.id !== "string") return
			const entry = created.pending.get(reply.id)
			if (!entry) return
			created.pending.delete(reply.id)
			clearTimeout(entry.timer)
			if (reply.ok === true) entry.resolve(reply.result)
			else entry.reject(new Error(`Installed command failed: ${sanitize(reply.error)}`))
		}
		socket.onerror = () =>
			created.retire(new Error("Installed authenticated transport failed; outstanding requests were not replayed"))
		socket.onclose = (event) =>
			created.retire(
				new Error(
					`Installed authenticated transport closed (code ${event.code}, clean ${event.wasClean}); outstanding requests were not replayed`,
				),
			)
		host.__clineInstalledAcceptanceRpcV1 = created
		state = created
	}
	if (state.pending.size >= 32) return Promise.reject(new Error("Installed RPC pending-request budget reached"))
	const current = state,
		id = crypto.randomUUID()
	let message: string
	try {
		message = JSON.stringify({ type: "command", id, command, args })
	} catch {
		return Promise.reject(new Error("Installed RPC arguments could not be serialized"))
	}
	return new Promise((resolve, reject) => {
		const timer = setTimeout(
			() => current.retire(new Error(`Installed RPC timed out: ${command}; outstanding requests were not replayed`)),
			90_000,
		)
		const entry: Pending = { resolve, reject, timer, message, sent: false }
		current.pending.set(id, entry)
		if (current.socket.readyState === WebSocket.OPEN) {
			entry.sent = true
			try {
				current.socket.send(message)
			} catch {
				current.retire(new Error("Installed RPC send failed; request was not replayed"))
			}
		}
	})
}

/** The expanded v12 journey exceeded 384 RPC/native actions before its final
 * restart. Reserve bounded headroom for the complete journey, not dropped records
 * or skipped acceptance steps. At most 768 actions / 1536 running+terminal progress
 * records, no child log payloads. Native process cleanup is independent of this cap. */
export const INSTALLED_ACTION_LIMIT = 768
export function assertInstalledActionSequence(sequence: number) {
	if (!Number.isSafeInteger(sequence) || sequence < 1 || sequence > INSTALLED_ACTION_LIMIT)
		throw new Error("Installed action evidence budget reached")
}

/** Newly produced receipts must match the shipped parser, not a stale test literal.
 * Persisted historical receipts remain governed by their own immutable profile. */
export function verifyInstalledAnalysisProfile(profile: string) {
	// This Node strip-types driver is also checked by a project which disallows
	// .ts imports. Read only the trusted checkout's exact constant declaration;
	// never load target code or accept a caller-selected expected profile.
	const contract = readFileSync(new URL("../../../sdk/packages/core/src/analysis/profile.ts", import.meta.url), "utf8")
	const current = /^export const ANALYSIS_PROFILE = "(cline-js-static\/[1-9][0-9]*)";$/m.exec(contract)
	if (!current) throw new Error("Shipped analysis profile declaration unavailable")
	if (profile !== current[1]) throw new Error("Installed analysis profile is stale")
}

/** Settings replaces the sidebar session list. Exit through the visible Home
 * control before selecting a saved session; no reload, force click or RPC bypass. */
export async function openInstalledSavedSession(page: Pick<Page, "getByRole">, title: RegExp) {
	await page.getByRole("button", { name: "Cline home", exact: true }).click()
	await page.getByRole("button", { name: title }).first().click()
}

/** Read-only restart check. Never reconstruct or inject a lost device reference. */
export function verifyInstalledSourceReferenceStorage(expected: unknown, raw: unknown) {
	if (typeof raw !== "string" || raw.length > 32768)
		throw new Error("Installed source reference missing after native restart; no reference restored or injected")
	let actual: unknown
	try {
		actual = JSON.parse(raw)
	} catch {
		throw new Error("Installed source reference malformed after native restart")
	}
	if (JSON.stringify(actual) !== JSON.stringify(expected))
		throw new Error("Installed source reference changed across native restart; no fallback selection allowed")
}

export function startAcceptanceProcess(executable: string, args: string[], cwd: string, env: NodeJS.ProcessEnv) {
	const startedAt = new Date().toISOString()
	const child = spawn(executable, args, {
		cwd,
		env,
		shell: false,
		windowsHide: false,
		stdio: ["ignore", "pipe", "pipe"],
	})
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

/** Keep native process-tree termination authoritative and independent of CDP
 * teardown: a disconnected transport is not proof of native process exit.
 * Still attempt disconnect after a failed stop and preserve both failures;
 * never retry a kill or accept an unconfirmed termination. */
export async function stopOwnedApplication(terminate: () => Promise<void>, disconnect: () => Promise<void>) {
	const failures: unknown[] = []
	try {
		await terminate()
	} catch (error) {
		failures.push(error)
	}
	try {
		await disconnect()
	} catch (error) {
		failures.push(error)
	}
	if (failures.length === 1) throw failures[0]
	if (failures.length > 1) throw new AggregateError(failures, "Owned application termination and disconnect failed")
}

/** Normal restart is not a crash test. Ask the existing native Quit command once,
 * then require clean exit of the exact launched child before disconnecting CDP.
 * An exit can close the invoke transport before its response: the native exit,
 * not that response, is authoritative. A timeout/nonzero exit fails; no force-kill
 * fallback may turn it into a successful restart. Failure cleanup stays separate. */
export async function quitOwnedApplicationForRestart(
	requestQuit: () => Promise<unknown>,
	waitForExit: () => Promise<number | null>,
	disconnect: () => Promise<void>,
	timeoutMs = 30_000,
) {
	const request = Promise.resolve()
		.then(requestQuit)
		.then(
			() => "acknowledged" as const,
			() => "transport-closed-or-rejected" as const,
		)
	const code = await withInstalledActionDeadline("owned-native-quit-exit", waitForExit, timeoutMs)
	if (code !== 0) throw new Error("Owned normal restart requires confirmed native exit code zero")
	await withInstalledActionDeadline("owned-native-quit-disconnect", disconnect, timeoutMs)
	// The request can be pending after exit if its renderer was destroyed. Do not
	// wait on it or replay it; it has a rejection handler and grants no authority.
	void request
}

/** A single taskkill can report a WebView child already exiting as an error.
 * Neither its exit code nor CDP disconnect proves cleanup. Capture creation-time
 * identities first, issue one native tree stop, then require a fresh CIM snapshot
 * with every observed identity absent. Observation errors/survivors fail closed;
 * PID reuse is never grounds for killing an additional process. */
export const OWNED_WINDOWS_TREE_STOP = String.raw`
$ErrorActionPreference = 'Stop'
$rootPid = [int]$env:ACCEPTANCE_STOP_PID
if ($rootPid -le 0) { throw 'Invalid owned root PID' }
$known = @{}
function Add-OwnedTree($rows) {
  $expanded = $true
  while ($expanded) {
    $expanded = $false
    foreach ($row in $rows) {
      $key = [string]$row.ProcessId
      if ($known.ContainsKey($key)) { continue }
      $parent = $known[[string]$row.ParentProcessId]
      if ($null -ne $parent -and $row.CreationDate -ge $parent.CreationDate) {
        if ($known.Count -ge 256) { throw 'Owned tree identity budget exceeded' }
        $known[$key] = $row
        $expanded = $true
      }
    }
  }
}
$rows = @(Get-CimInstance Win32_Process -ErrorAction Stop)
$root = @($rows | Where-Object { $_.ProcessId -eq $rootPid })
if ($root.Count -ne 1) { throw 'Owned root identity unavailable before stop' }
$known[[string]$rootPid] = $root[0]
Add-OwnedTree $rows
$taskkill = Join-Path $env:SystemRoot 'System32\taskkill.exe'
# Capture the native diagnostic without interpreting localized error strings.
# A nonzero status is accepted only after independent identity absence proof.
$ErrorActionPreference = 'Continue'
try { $nativeDiagnostic = (& $taskkill /PID $rootPid /T /F 2>&1 | Out-String); $nativeExit = $LASTEXITCODE }
finally { $ErrorActionPreference = 'Stop' }
for ($attempt = 0; $attempt -lt 20; $attempt++) {
  $rows = @(Get-CimInstance Win32_Process -ErrorAction Stop)
  Add-OwnedTree $rows
  $survivors = @($rows | Where-Object {
    $previous = $known[[string]$_.ProcessId]
    $null -ne $previous -and $_.CreationDate -eq $previous.CreationDate
  })
  if ($survivors.Count -eq 0) {
    [Console]::Write((ConvertTo-Json -Compress -InputObject @{
      schema = 'cline-owned-tree-stop/v1'; confirmed = $true;
      taskkillExitCode = $nativeExit; observedIdentities = $known.Count;
      remainingIdentities = 0
    }))
    exit 0
  }
  Start-Sleep -Milliseconds 100
}
throw 'Owned process-tree identity absence not confirmed'
`

export function verifyOwnedTreeStopReceipt(value: unknown) {
	const row = value as Record<string, unknown> | null
	if (
		!row ||
		row.schema !== "cline-owned-tree-stop/v1" ||
		row.confirmed !== true ||
		!Number.isInteger(row.taskkillExitCode) ||
		!Number.isInteger(row.observedIdentities) ||
		(row.observedIdentities as number) < 1 ||
		(row.observedIdentities as number) > 256 ||
		row.remainingIdentities !== 0
	)
		throw new Error("Owned process-tree cleanup receipt unavailable or invalid")
}

export async function stopOwnedWindowsTree(pid: number, cwd: string, env: NodeJS.ProcessEnv) {
	if (process.platform !== "win32" || !Number.isSafeInteger(pid) || pid <= 0)
		throw new Error("Owned Windows process PID required")
	const powershell = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	const probe = startAcceptanceProcess(
		powershell,
		["-NoProfile", "-NonInteractive", "-Command", OWNED_WINDOWS_TREE_STOP],
		cwd,
		{ ...env, ACCEPTANCE_STOP_PID: String(pid) },
	)
	const code = await withInstalledActionDeadline("owned-process-tree-stop", () => probe.exited, 30_000).catch((error) => {
		probe.child.kill()
		throw error
	})
	await withInstalledActionDeadline("owned-process-tree-stop-output", () => probe.closed, 5_000)
	if (code !== 0) throw new Error(`Owned process-tree cleanup was not confirmed (probe exit ${code})`)
	let receipt: unknown
	try {
		receipt = JSON.parse(probe.diagnostics.stdoutTail)
	} catch {
		throw new Error("Owned process-tree cleanup receipt unavailable or invalid")
	}
	verifyOwnedTreeStopReceipt(receipt)
}

/** Node-owned deadline: renderer timers can stop while a WebView/IPC call is stuck.
 * Timeout fails acceptance, never retries or claims a submitted operation was undone. */
export async function withInstalledActionDeadline<T>(phase: string, operation: () => Promise<T>, timeoutMs = 95_000): Promise<T> {
	if (!/^[a-z][a-z0-9_-]{0,95}$/.test(phase) || !Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 180_000)
		throw new Error("Invalid installed action deadline")
	let timer: ReturnType<typeof setTimeout> | undefined
	try {
		return await Promise.race([
			Promise.resolve().then(operation),
			new Promise<never>((_, reject) => {
				timer = setTimeout(() => reject(new Error(`Installed action deadline exceeded: ${phase}; no replay`)), timeoutMs)
			}),
		])
	} finally {
		clearTimeout(timer)
	}
}

// A settings textbox is disabled until the asynchronous persisted-settings read settles.
// Trial click waits for that actual UI readiness, not an arbitrary sleep or value retry.
export async function verifyRestartInstructions(instructions: Locator, expected: string) {
	await instructions.click({ trial: true, timeout: 30_000 })
	if ((await instructions.inputValue()) !== expected) throw new Error("Installed UI setting did not survive restart")
}

/** Reattach through the authoritative Hub recovery path before opening a new
 * local SQLite discovery connection. Neither operation is replayed on error. */
export async function verifyRecoveredHubSession(
	attach: () => Promise<unknown>,
	readSessions: () => Promise<Array<{ sessionId: string }>>,
	sessionId: string,
) {
	await attach()
	const sessions = await readSessions()
	if (!sessions.some((item) => item.sessionId === sessionId)) throw new Error("Saved session missing after Hub restart")
}

/** Retry only endpoint discovery, never a submitted command or accepted prompt.
 * Full-pack integrity checks can outlast one native 30s readiness window. */
export async function waitForInstalledBackendEndpoint(
	readEndpoint: () => Promise<string>,
	options: { timeoutMs?: number; pollMs?: number; maxAttempts?: number } = {},
) {
	const timeoutMs = options.timeoutMs ?? 90_000
	const pollMs = options.pollMs ?? 200
	const maxAttempts = options.maxAttempts ?? 3
	if (
		!Number.isFinite(timeoutMs) ||
		timeoutMs <= 0 ||
		!Number.isFinite(pollMs) ||
		pollMs < 0 ||
		!Number.isInteger(maxAttempts) ||
		maxAttempts < 1 ||
		maxAttempts > 3
	)
		throw new Error("Invalid installed backend readiness budget")
	const deadline = Date.now() + timeoutMs
	for (let attempt = 0; attempt < maxAttempts && Date.now() < deadline; attempt++) {
		let timer: ReturnType<typeof setTimeout> | undefined
		try {
			const endpoint = await Promise.race([
				readEndpoint(),
				new Promise<never>((_, reject) => {
					timer = setTimeout(
						() => reject(new Error("Installed backend readiness deadline exceeded")),
						Math.max(1, deadline - Date.now()),
					)
				}),
			])
			const url = new URL(endpoint)
			if (
				!["ws:", "wss:"].includes(url.protocol) ||
				!["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
				url.username ||
				url.password
			)
				throw new Error("Installed backend did not publish a local WebSocket endpoint")
			return endpoint
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error)
			if (!/desktop backend endpoint not ready/i.test(message)) throw error
		} finally {
			clearTimeout(timer)
		}
		if (attempt + 1 < maxAttempts && Date.now() < deadline) await delay(Math.min(pollMs, Math.max(0, deadline - Date.now())))
	}
	throw new Error("Installed backend did not become ready within the bounded discovery budget")
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
	// Resolve only the trusted newly created fixture root before launching owned Node.
	// Inspector labels remain lexical; never resolve paths supplied by a target.
	const root = realpathSync.native(await mkdtemp(join(tmpdir(), "cline-installed-ui-")))
	const workspace = join(root, "owned-workspace")
	const evidence = join(process.cwd(), "dist", "installed-ui-evidence")
	await mkdir(workspace)
	await mkdir(evidence, { recursive: true })
	await writeFile(join(workspace, "OWNED_FIXTURE.txt"), "Deterministic installer acceptance fixture.\n")
	await writeFile(join(workspace, "owned-triage.exe"), "MZCLINE_OWNED_TRIAGE_FIXTURE_V1")
	await writeFile(
		join(workspace, "OWNED_SCROLL_REPORT.md"),
		Array.from({ length: 240 }, (_, i) => `Owned Markdown scroll line ${i}`).join("\n"),
	)
	await writeFile(
		join(workspace, "owned-main.js"),
		'import {ipcMain} from "electron"; ipcMain.handle("owned:fixture", () => 42);',
	)
	await writeFile(
		join(workspace, "owned-renderer.js"),
		'import {ipcRenderer} from "electron"; ipcRenderer.invoke("owned:fixture");',
	)
	const analysisCurrent = join(workspace, "owned-analysis-current"),
		analysisPrevious = join(workspace, "owned-analysis-previous")
	await mkdir(analysisCurrent)
	await mkdir(analysisPrevious)
	const sourceSelectionText = 'export const ownedSelection = "NEVER_EXECUTE_SOURCE_SELECTION";\n'
	const sourceSelectionTarget = join(analysisCurrent, "selection-owned.ts")
	await writeFile(sourceSelectionTarget, sourceSelectionText)
	const hybridExpectedOutput = "owned-hybrid\n"
	const hybridFixtureTarget = join(analysisCurrent, "hybrid-owned.js")
	await writeFile(hybridFixtureTarget, `process.stdout.write(${JSON.stringify(hybridExpectedOutput)});`)
	for (const [directory, route] of [
		[analysisCurrent, "/v2"],
		[analysisPrevious, "/v1"],
	]) {
		await writeFile(
			join(directory, "config.ts"),
			`export const config={host:"https://owned.invalid",route:${JSON.stringify(route)}};`,
		)
		await writeFile(
			join(directory, "main.js"),
			`import {ipcMain} from "electron"; ipcMain.handle("owned:fixture", () => 42); import {config} from "./config"; function endpoint(h,r){return h+r;} fetch(endpoint(config.host,config.route));`,
		)
		await writeFile(
			join(directory, "renderer.js"),
			'import {ipcRenderer} from "electron"; ipcRenderer.invoke("owned:fixture");',
		)
	}
	await writeFile(
		join(analysisCurrent, "main.js.map"),
		JSON.stringify({
			version: 3,
			file: "main.js",
			sources: ["original.ts"],
			sourcesContent: ["export const owned=42;"],
			names: [],
			mappings: "AAAA",
		}),
	)
	const managedFixture = Buffer.from(OWNED_MANAGED_BASE64, "base64")
	if (createHash("sha256").update(managedFixture).digest("hex") !== OWNED_MANAGED_SHA256)
		throw new Error("Owned managed fixture hash drift")
	await writeFile(join(analysisCurrent, "owned.dll"), managedFixture)
	const exceptionFixture = Buffer.from(OWNED_EH_BASE64, "base64")
	if (createHash("sha256").update(exceptionFixture).digest("hex") !== OWNED_EH_SHA256)
		throw new Error("Owned exception fixture hash drift")
	await writeFile(join(analysisCurrent, "owned-eh.dll"), exceptionFixture)
	await writeFile(
		join(analysisCurrent, "preload.js"),
		'const {contextBridge:cb,ipcRenderer:ir}=require("electron");const addon=require("./owned.node");const api={read:(x)=>ir.invoke("owned:fixture",x),hash:(x)=>addon.hash(x)};cb.exposeInMainWorld("ownedApi",api);',
	)
	await writeFile(
		join(analysisCurrent, "renderer.js"),
		'import {ipcRenderer} from "electron";ipcRenderer.invoke("owned:fixture");window.ownedApi.read(42);window.ownedApi.hash(42);',
	)

	const applicationSentinel = join(workspace, "APPLICATION_MUST_NOT_EXECUTE")
	const applicationRoot = join(workspace, "owned-application-graph")
	await mkdir(applicationRoot)
	await writeFile(join(applicationRoot, "package.json"), '{"name":"owned-installed-app","main":"main.cjs"}')
	await writeFile(
		join(applicationRoot, "main.cjs"),
		`const {BrowserWindow,ipcMain}=require('electron');require('node:fs').writeFileSync(${JSON.stringify(applicationSentinel)},'BAD');const win=new BrowserWindow({webPreferences:{preload:__dirname+'/preload.cjs'}});win.loadFile('index.html');ipcMain.handle('owned:application',(_event,value)=>({count:value+1}));throw new Error('MUST_NOT_EXECUTE');`,
	)
	await writeFile(
		join(applicationRoot, "preload.cjs"),
		"const {contextBridge,ipcRenderer}=require('electron');contextBridge.exposeInMainWorld('owned',{read:(value)=>ipcRenderer.invoke('owned:application',value)});",
	)
	await writeFile(join(applicationRoot, "index.html"), '<script src="renderer.js"></script>')
	await writeFile(join(applicationRoot, "renderer.js"), "window.owned.read(41);")

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
	let actionSequence = 0
	let lastAction = { phase: "setup", status: "running" }
	async function acceptanceAction<T>(phase: string, operation: () => Promise<T>, timeoutMs = 95_000) {
		const sequence = ++actionSequence
		assertInstalledActionSequence(sequence)
		lastAction = { phase, status: "running" }
		const startedAt = new Date().toISOString()
		const persist = async () => {
			await appendFile(
				join(evidence, "action-progress.jsonl"),
				JSON.stringify({ sequence, ...lastAction, at: new Date().toISOString() }) + "\n",
			)
			await writeFile(
				join(evidence, "phase.json"),
				JSON.stringify(
					{
						schemaVersion: 1,
						sourceCommit: process.env.GITHUB_SHA,
						sequence,
						lastAction,
						startedAt,
						stages,
					},
					null,
					2,
				),
			)
		}
		await persist()
		try {
			const result = await withInstalledActionDeadline(phase, operation, timeoutMs)
			lastAction = { phase, status: "completed" }
			await persist()
			return result
		} catch (error) {
			lastAction = { phase, status: "failed" }
			await persist()
			throw error
		}
	}
	let launchNumber = 0
	const startupSamples: number[] = []
	const appWorkingSetSamples: number[] = []
	const transcriptScrollSamples: number[] = []
	async function killOwnedProcess(pid: number) {
		await stopOwnedWindowsTree(pid, workspace, environment)
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
		const startupStarted = performance.now()
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
				const response = await fetch(`http://127.0.0.1:${port}/json/version`, {
					signal: AbortSignal.timeout(1000),
				})
				lastHttpStatus = response.status
				if (response.ok) {
					browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, {
						timeout: 10_000,
					})
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
		await acceptanceAction(
			"launch-onboarding-profile",
			() =>
				page.evaluate(() =>
					localStorage.setItem("cline.code.onboarding.v1", JSON.stringify({ completedAt: new Date().toISOString() })),
				),
			30_000,
		)
		await page.reload()
		await page.getByRole("button", { name: "Settings", exact: true }).first().waitFor()
		// Visible settings are not proof that the restarted sidecar is ready.
		// Require one actual authenticated read; no command or prompt is replayed.
		await rpc(page, "get_desktop_settings")
		startupSamples.push(performance.now() - startupStarted)
		// Sample only this launched native app, never arbitrary user processes.
		// WebView/Hub/worker descendants are deliberately not called whole-app RAM.
		const powershell = join(
			process.env.SystemRoot ?? "C:\\Windows",
			"System32",
			"WindowsPowerShell",
			"v1.0",
			"powershell.exe",
		)
		const probe = startAcceptanceProcess(
			powershell,
			[
				"-NoProfile",
				"-NonInteractive",
				"-Command",
				`[Console]::Write((Get-Process -Id ${app.child.pid} -ErrorAction Stop).WorkingSet64)`,
			],
			workspace,
			environment,
		)
		const probeCode = await Promise.race([probe.exited, delay(10000, null, { ref: false })])
		if (probeCode === null && probe.child.pid) await killOwnedProcess(probe.child.pid)
		if (probeCode !== 0) throw new Error("Owned installed app memory probe failed")
		await probe.closed
		const bytes = Number(probe.diagnostics.stdoutTail.trim())
		if (!Number.isFinite(bytes) || bytes <= 0) throw new Error("Invalid owned app working-set observation")
		appWorkingSetSamples.push(bytes / 1024 / 1024)
		return page
	}

	async function rpc<T>(page: Page, command: string, args: Record<string, unknown> = {}): Promise<T> {
		const endpoint = await acceptanceAction(
			"backend-endpoint-discovery",
			() =>
				waitForInstalledBackendEndpoint(() =>
					page.evaluate(async () => {
						const native = (
							window as unknown as {
								__TAURI_INTERNALS__: { invoke: (name: string) => Promise<string> }
							}
						).__TAURI_INTERNALS__
						return await native.invoke("get_desktop_backend_endpoint")
					}),
				),
			95_000,
		)
		return (await acceptanceAction(`rpc-${command}`, () =>
			page.evaluate(installedBrowserRpc, { command, args, endpoint }),
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
		const ownedBrowser = browser
		const ownedApp = app
		try {
			await stopOwnedApplication(
				async () => {
					if (ownedApp && ownedApp.child.exitCode === null && ownedApp.child.pid) {
						await killOwnedProcess(ownedApp.child.pid)
						await withInstalledActionDeadline("owned-app-exit", () => ownedApp.exited, 10_000)
					}
				},
				async () => {
					if (ownedBrowser)
						await withInstalledActionDeadline("owned-browser-disconnect", () => ownedBrowser.close(), 10_000)
				},
			)
		} finally {
			browser = undefined
			app = undefined
		}
	}
	async function quitForRestart(page: Page) {
		const ownedBrowser = browser,
			ownedApp = app
		if (!ownedBrowser || !ownedApp || ownedApp.child.exitCode !== null)
			throw new Error("Owned live application required for normal restart")
		await quitOwnedApplicationForRestart(
			() =>
				page.evaluate(() =>
					(
						window as unknown as {
							__TAURI_INTERNALS__: { invoke: (name: string) => Promise<unknown> }
						}
					).__TAURI_INTERNALS__.invoke("quit_app"),
				),
			() => ownedApp.exited,
			async () => {
				await ownedApp.closed
				await ownedBrowser.close()
			},
		)
		browser = undefined
		app = undefined
	}

	try {
		const skillSelfcheck = startAcceptanceProcess(sidecar, ["--cline-investigation-skills-selfcheck"], workspace, environment)
		let skillSelfcheckResult: Record<string, unknown>
		try {
			const code = await withInstalledActionDeadline(
				"installed-investigation-skills-selfcheck",
				() => skillSelfcheck.exited,
				60_000,
			)
			await withInstalledActionDeadline(
				"installed-investigation-skills-selfcheck-stdio",
				() => skillSelfcheck.closed,
				10_000,
			)
			if (code !== 0) throw new Error("Installed investigation skill selfcheck failed")
			skillSelfcheckResult = JSON.parse(skillSelfcheck.diagnostics.stdoutTail.trim())
			if (
				skillSelfcheckResult.status !== "passed" ||
				skillSelfcheckResult.plugin !== INSTALLED_INVESTIGATION_PLUGIN ||
				JSON.stringify(skillSelfcheckResult.skills) !== JSON.stringify(INSTALLED_INVESTIGATION_NAMES) ||
				skillSelfcheckResult.loadedInstructions !== 6 ||
				skillSelfcheckResult.instructionOnly !== true ||
				skillSelfcheckResult.mcpServers !== 0 ||
				skillSelfcheckResult.providerCalls !== 0 ||
				skillSelfcheckResult.targetExecuted !== false
			)
				throw new Error("Installed investigation selfcheck did not confirm six instruction-only skills")
			await writeFile(join(evidence, "investigation-skills-selfcheck.json"), JSON.stringify(skillSelfcheckResult, null, 2))
		} finally {
			if (skillSelfcheck.child.pid && skillSelfcheck.child.exitCode === null) {
				await killOwnedProcess(skillSelfcheck.child.pid)
				await withInstalledActionDeadline("owned-investigation-selfcheck-exit", () => skillSelfcheck.exited, 10_000)
			}
		}
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
		// Fresh composer: choosing a mode configures only the unsent draft. No model
		// call, target execution, software install or permission expansion is needed.
		const freshAnalysis = page.getByLabel("Draft Analysis mode", { exact: true })
		await freshAnalysis.waitFor({ state: "visible", timeout: 30_000 })
		if ((await freshAnalysis.inputValue()) !== "off") throw new Error("Fresh draft Analysis must start Off")
		await freshAnalysis.selectOption("static")
		if ((await freshAnalysis.inputValue()) !== "static") throw new Error("Pre-task Analysis selection did not stick")
		const analysisToggle = page.getByRole("button", { name: "Toggle Analysis workspace", exact: true })
		await analysisToggle.click()
		await page.getByRole("region", { name: "Pre-task Analysis workspace", exact: true }).waitFor()
		const preTaskWorkspace = page.getByRole("region", { name: "Pre-task Analysis workspace", exact: true })
		await preTaskWorkspace.getByRole("button", { name: "AI commands", exact: true }).click()
		const advancedPanel = preTaskWorkspace.getByRole("region", { name: "Advanced AI commands", exact: true })
		await advancedPanel
			.getByLabel("Advanced command", { exact: true })
			.selectOption("preview_smali_patch", { timeout: 30000 })
		if (
			!(await advancedPanel.getByLabel("Exact command parameters (JSON)", { exact: true }).inputValue()).includes(
				"expected_sha256",
			)
		)
			throw new Error("Installed advanced command template missing hash guard")
		if (!(await advancedPanel.textContent())?.includes("Not available in this command pack"))
			throw new Error("Installed advanced catalog hid unavailable capabilities")
		stages.push("installed-fresh-advanced-command-catalog-visible-without-execution")
		const sharedArtifact = preTaskWorkspace.getByLabel("Shared artifact path", { exact: true })
		const sharedPath = join(workspace, "owned-selection-only.apk")
		await sharedArtifact.fill(sharedPath)
		await preTaskWorkspace.getByLabel("Remember this path on this device", { exact: true }).check()
		await preTaskWorkspace.getByRole("button", { name: "Android tools", exact: true }).click()
		const sharedAndroid = preTaskWorkspace.getByLabel("Target file or decoded project directory", { exact: true })
		if ((await sharedAndroid.inputValue()) !== sharedPath) throw new Error("Installed Android pane lost shared path metadata")
		await sharedAndroid.fill(sharedPath + ".dex")
		await preTaskWorkspace.getByRole("button", { name: "Analyze", exact: true }).click()
		if (
			(await preTaskWorkspace.getByPlaceholder("Workspace-relative or absolute path", { exact: true }).inputValue()) !==
			sharedPath + ".dex"
		)
			throw new Error("Installed Analyze pane lost shared path metadata")
		await preTaskWorkspace.getByRole("button", { name: "App analysis", exact: true }).click()
		if (
			(await preTaskWorkspace.getByLabel("JavaScript analysis target", { exact: true }).inputValue()) !==
			sharedPath + ".dex"
		)
			throw new Error("Installed source pane lost shared path metadata")
		if (!(await preTaskWorkspace.getByRole("button", { name: "Inspect static sources", exact: true }).isDisabled()))
			throw new Error("Installed draft source inspection must require an existing session")
		if (await preTaskWorkspace.getByRole("button", { name: "Review Inspector plan", exact: true }).count())
			throw new Error("Installed draft must not expose runtime authority")
		await preTaskWorkspace.getByRole("button", { name: "AI commands", exact: true }).click()
		await advancedPanel.getByLabel("Advanced command", { exact: true }).selectOption("identify_artifact")
		const sharedCommand = advancedPanel.getByLabel("Exact command parameters (JSON)", { exact: true })
		if (JSON.parse(await sharedCommand.inputValue()).target !== "")
			throw new Error("Installed shared selection silently changed AI parameters")
		await advancedPanel.getByRole("button", { name: "Use shared artifact in command JSON", exact: true }).click()
		if (JSON.parse(await sharedCommand.inputValue()).target !== sharedPath + ".dex")
			throw new Error("Installed explicit shared path transfer failed")
		await analysisToggle.click()
		await analysisToggle.click()
		if ((await sharedArtifact.inputValue()) !== sharedPath + ".dex")
			throw new Error("Installed remembered shared selection lost on workspace remount")
		await preTaskWorkspace.getByRole("button", { name: "Clear shared selection and saved path", exact: true }).click()
		if (
			(await sharedArtifact.inputValue()) !== "" ||
			(await preTaskWorkspace.getByLabel("Remember this path on this device", { exact: true }).isChecked())
		)
			throw new Error("Installed shared metadata clear failed")
		stages.push("installed-shared-artifact-cross-pane-explicit-json-remember-clear-passed")
		await analysisToggle.click()
		await freshAnalysis.selectOption("off")
		stages.push("installed-fresh-draft-analysis-visible-before-first-task")

		// Exercise the installed app's actual event receivers against our own blank
		// WebView. Never attach to user browsers or execute a supplied target.
		const captureBrowserId = randomUUID()
		const nativeCaptureInvoke = <T>(name: string, args: Record<string, unknown>) =>
			acceptanceAction(
				`native-${name}`,
				() =>
					page.evaluate(
						async ({ name, args }) => {
							const native = (
								window as unknown as {
									__TAURI_INTERNALS__: {
										invoke: (name: string, args: Record<string, unknown>) => Promise<unknown>
									}
								}
							).__TAURI_INTERNALS__
							return await native.invoke(name, args)
						},
						{ name, args },
					),
				40_000,
			) as Promise<T>
		try {
			await nativeCaptureInvoke("built_in_browser_start", { sessionId: captureBrowserId, url: "about:blank" })
			await nativeCaptureInvoke("built_in_browser_capture", { sessionId: captureBrowserId, action: "start" })
			await nativeCaptureInvoke("built_in_browser_cdp", {
				sessionId: captureBrowserId,
				method: "Runtime.enable",
				params: {},
			})
			await nativeCaptureInvoke("built_in_browser_cdp", {
				sessionId: captureBrowserId,
				method: "Runtime.evaluate",
				params: { expression: "console.log('owned-capture-secret-fixture')", returnByValue: true },
			})
			await delay(100)
			const captured = await nativeCaptureInvoke<{
				cleanupVerified: boolean
				events: Array<{ kind: string; argumentCount?: number }>
			}>("built_in_browser_capture", { sessionId: captureBrowserId, action: "stop" })
			if (!captured.cleanupVerified || !captured.events.some((e) => e.kind === "console-event" && e.argumentCount === 1))
				throw new Error("Installed native browser capture failed")
			if (JSON.stringify(captured).includes("owned-capture-secret-fixture"))
				throw new Error("Installed native capture retained console argument values")
			stages.push("installed-browser-native-metadata-capture-cleanup-verified")
		} finally {
			await nativeCaptureInvoke("built_in_browser_stop", { sessionId: captureBrowserId })
		}

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
					initialMessages: [
						...Array.from({ length: 120 }, (_, index) => ({
							id: `installer-owned-message-${index}`,
							role: "user",
							content: `Installer owned history row ${index}. ${"Owned offline transcript fixture. ".repeat(8)}`,
						})),
						// Recorded, offline tool history only. These messages never execute a
						// command and cannot supply host validation authority.
						{
							id: "installer-report-plan",
							role: "assistant",
							content: [
								{
									type: "tool_use",
									id: "installer-report-plan-call",
									name: "update_plan",
									input: {
										steps: [{ id: "owned-recorded-step", label: "Owned recorded step", status: "completed" }],
									},
								},
							],
						},
						{
							id: "installer-report-plan-result",
							role: "user",
							content: [{ type: "tool_result", tool_use_id: "installer-report-plan-call", content: '{"ok":true}' }],
						},
						{
							id: "installer-report-tool",
							role: "assistant",
							content: [
								{
									type: "tool_use",
									id: "installer-report-tool-call",
									name: "read_files",
									input: { paths: ["OWNED_SCROLL_REPORT.md"] },
								},
							],
						},
						{
							id: "installer-report-tool-result",
							role: "user",
							content: [
								{
									type: "tool_result",
									tool_use_id: "installer-report-tool-call",
									content:
										'{"status":"partial","limitations":["Owned offline recorded fixture, not executed"]}',
								},
							],
						},
						{
							id: "installer-owned-artifact",
							role: "assistant",
							content: "Owned report: `./OWNED_SCROLL_REPORT.md`",
						},
					],
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
		const installedSkillRoot = join(resolve(sidecar, ".."), "investigation-skills")
		const readSkills = () =>
			rpc<InstalledInvestigationCatalog>(page, "list_user_instruction_configs", { environmentId: "local" })
		verifyInstalledInvestigationCatalog(await readSkills(), true, installedSkillRoot)
		const setInvestigationDisabled = async (disabled: boolean) => {
			const catalog = await rpc<InstalledInvestigationCatalog>(page, "set_plugin_disabled", {
				environmentId: "local",
				path: installedSkillRoot,
				disabled,
			})
			verifyInstalledInvestigationCatalog(catalog, !disabled, installedSkillRoot)
		}
		await setInvestigationDisabled(true)
		await setInvestigationDisabled(false)
		await writeFile(
			join(evidence, "investigation-skills-evidence.json"),
			JSON.stringify(
				{
					plugin: INSTALLED_INVESTIGATION_PLUGIN,
					skills: INSTALLED_INVESTIGATION_NAMES,
					selfcheck: skillSelfcheckResult,
					namespacedCatalogVerified: true,
					disableAndReenableVerified: true,
					providerCalls: 0,
					targetExecuted: false,
					limitation: "Instruction loading only; no live model or unported engine parity claim",
				},
				null,
				2,
			),
		)
		stages.push("installed-bundled-investigation-skills-instruction-only-namespace-disable-passed")
		const verifyRecordedTaskReport = async () => {
			const destinations = page.getByRole("navigation", { name: "Task destinations", exact: true })
			await destinations.getByRole("button", { name: "Reports", exact: true }).click()
			const report = page.getByRole("region", { name: "Session reports", exact: true })
			await report.getByRole("heading", { name: "Final task report", exact: true }).waitFor({ timeout: 30000 })
			await report.getByText("Outcome: Partial / unverified", { exact: true }).waitFor({ timeout: 30000 })
			await report.getByText("Owned recorded step (plan-marked complete)", { exact: true }).waitFor({ timeout: 30000 })
			await report.getByRole("button", { name: "Export JSON", exact: true }).waitFor({ state: "visible", timeout: 30000 })
			if (await report.getByText(/host-executed declared check\(s\) passed/).count())
				throw new Error("Recorded model plan incorrectly acquired host verification authority")
			await destinations.getByRole("button", { name: "Chat", exact: true }).click()
		}
		await verifyRecordedTaskReport()
		stages.push("installed-task-report-offline-plan-partial-no-verification-no-execution-passed")
		const analysisArgs = { sessionId: session.sessionId, environmentId: "local" }
		const beforeAnalysis = await rpc<{ mode: string }>(page, "first_party_analysis_status", analysisArgs)
		if (beforeAnalysis.mode !== "off") throw new Error("New session analysis must default Off")
		await page.getByLabel("Session Analysis mode", { exact: true }).selectOption("static")
		await page.waitForFunction(() => {
			const select = document.querySelector<HTMLSelectElement>('select[aria-label="Session Analysis mode"]')
			return select?.value === "static" && !select.disabled
		})
		const parsed = await rpc<{ id: string; status: string }>(page, "first_party_analysis_run", {
			...analysisArgs,
			input: { target: "owned-analysis-current", compareTarget: "owned-analysis-previous" },
		})
		if (!["completed", "partial"].includes(parsed.status)) throw new Error("Installed static parser failed")
		const allEvidence = async (view: string, filter?: string) => {
			const items: Array<{ kind: string; value: string }> = []
			let offset = 0
			for (let count = 0; count < 20; count++) {
				const result = await rpc<{ items: Array<{ kind: string; value: string }>; nextOffset: number | null }>(
					page,
					"first_party_analysis_evidence",
					{ ...analysisArgs, query: { receiptId: parsed.id, view, filter, offset, limit: 50 } },
				)
				items.push(...result.items)
				if (result.nextOffset === null) return { items }
				if (!Number.isSafeInteger(result.nextOffset) || result.nextOffset <= offset)
					throw new Error("Installed evidence pagination stalled")
				offset = result.nextOffset
			}
			throw new Error("Installed owned evidence exceeded fixture budget")
		}
		const graph = await allEvidence("graph")
		if (!graph.items.some((e) => e.kind === "ipc-candidate")) throw new Error("Installed parser omitted owned IPC candidate")
		const values = await rpc<{ items: Array<{ kind: string; value: string }> }>(page, "first_party_analysis_evidence", {
			...analysisArgs,
			query: { receiptId: parsed.id, view: "findings", filter: "resolved-endpoint" },
		})
		if (!values.items.some((f) => f.kind === "resolved-endpoint" && f.value === "https://owned.invalid/v2"))
			throw new Error("Installed cross-module object/value/return reduction failed")
		const preloadMembers = await allEvidence("findings", "preload-member")
		if (
			!preloadMembers.items.some((f) => f.kind === "preload-member" && JSON.parse(f.value).channel === "owned:fixture") ||
			!graph.items.some((e) => e.kind === "preload-candidate") ||
			!graph.items.some((e) => e.kind === "native-boundary-candidate")
		)
			throw new Error("Installed lexical preload/native-boundary candidate inspection failed")
		const exceptionRegions = await allEvidence("findings", "managed-exception-region")
		const exceptionKinds = exceptionRegions.items
			.filter((f) => f.kind === "managed-exception-region")
			.map((f) => JSON.parse(f.value).record.kind)
		if (
			!exceptionKinds.includes("catch") ||
			!exceptionKinds.includes("finally") ||
			!graph.items.some((e) => e.kind === "managed-exception-candidate")
		)
			throw new Error("Installed managed exception region inspection failed")
		const managedDeclarations = await allEvidence("findings", "managed-method")
		const managedAdd = managedDeclarations.items
			.filter((f) => f.kind === "managed-method")
			.map((f) => JSON.parse(f.value).record)
			.find((f) => f.name === "Add")
		if (
			managedAdd?.declaringType?.name !== "Fixture" ||
			managedAdd?.declaringType?.namespace !== "ClineOwned" ||
			managedAdd?.signature?.status !== "completed" ||
			managedAdd?.signature?.display !== "int32 (int32, int32)"
		)
			throw new Error("Installed declaring-type/signature inspection failed")
		const managed = await allEvidence("findings", "managed-il-instruction")
		const managedInstructions = managed.items
			.filter((f) => f.kind === "managed-il-instruction")
			.map((f) => JSON.parse(f.value).record)
		if (
			!managedInstructions.some((f) => f.opcode === "call" && f.resolution?.name === "Add") ||
			!managedInstructions.some((f) => f.opcode === "ldstr" && f.resolution?.preview === "https://owned.invalid/managed") ||
			!managedInstructions.some((f) => f.opcode === "ldc.i8" && f.operand === "9007199254740993")
		)
			throw new Error("Installed managed IL inspection failed")
		if (!graph.items.some((f) => f.kind === "managed-flow"))
			throw new Error("Installed managed normal-flow graph unavailable")
		const mappings = await rpc<{ items: Array<{ kind: string }> }>(page, "first_party_analysis_evidence", {
			...analysisArgs,
			query: { receiptId: parsed.id, view: "findings", filter: "source-map-location" },
		})
		if (!mappings.items.some((f) => f.kind === "source-map-location"))
			throw new Error("Installed source-map inspection failed")
		const verification = await rpc<{ profile: string }>(page, "first_party_analysis_evidence", {
			...analysisArgs,
			query: { receiptId: parsed.id, view: "verification" },
		})
		verifyInstalledAnalysisProfile(verification.profile)
		const unified = await rpc<{ items: unknown[] }>(page, "first_party_analysis_cross_domain", {
			...analysisArgs,
			receiptId: parsed.id,
		})
		if (!Array.isArray(unified.items)) throw new Error("Installed unified evidence route unavailable")
		const dossiers = await rpc<{ items: unknown[] }>(page, "first_party_analysis_cross_domain", {
			...analysisArgs,
			view: "dossiers",
		})
		if (!Array.isArray(dossiers.items)) throw new Error("Installed native dossier route unavailable")

		const changes = await rpc<{ items: Array<{ kind: string; value: string; change: string }> }>(
			page,
			"first_party_analysis_evidence",
			{ ...analysisArgs, query: { receiptId: parsed.id, view: "comparison", filter: "resolved-endpoint" } },
		)
		if (
			!changes.items.some((f) => f.change === "removed" && f.value === "https://owned.invalid/v1") ||
			!changes.items.some((f) => f.change === "added" && f.value === "https://owned.invalid/v2")
		)
			throw new Error("Installed endpoint finding comparison failed")
		page.once("dialog", (dialog) => dialog.accept())
		await page.getByLabel("Session Analysis mode", { exact: true }).selectOption("hybrid")
		await page.waitForFunction(() => {
			const select = document.querySelector<HTMLSelectElement>('select[aria-label="Session Analysis mode"]')
			return select?.value === "hybrid" && !select.disabled
		})
		await page.reload()
		await page
			.getByRole("button", { name: /Installer owned session/ })
			.first()
			.click()
		const hybridStatus = await rpc<{ mode: string; receipts: Array<{ id: string }> }>(
			page,
			"first_party_analysis_status",
			analysisArgs,
		)
		if (hybridStatus.mode !== "hybrid" || !hybridStatus.receipts.some((r) => r.id === parsed.id))
			throw new Error("Installed Hybrid mode/evidence did not persist")
		const hybridBasis = await rpc<{ relation: string; evidenceHash: string }>(page, "analysis_workflow_hybrid_prepare", {
			...analysisArgs,
			input: { baselineKind: "receipt", baselineId: parsed.id, question: "Which owned browser event occurs?" },
		})
		if (hybridBasis.relation !== "investigation-context-only" || !/^[a-f0-9]{64}$/.test(hybridBasis.evidenceHash))
			throw new Error("Installed Hybrid static preflight failed")
		let missingBasisDenied = false
		try {
			await rpc(page, "analysis_workflow_hybrid_prepare", {
				...analysisArgs,
				input: {
					baselineKind: "receipt",
					baselineId: "11111111-1111-4111-8111-111111111111",
					question: "Missing basis must deny",
				},
			})
		} catch {
			missingBasisDenied = true
		}
		if (!missingBasisDenied) throw new Error("Installed Hybrid accepted missing static evidence")
		stages.push("installed-hybrid-mode-persistence-static-preflight-passed")
		let restrictedBatchDenied = false
		try {
			await rpc(page, "preview_batch", {
				...analysisArgs,
				input: {
					operation_id: randomUUID(),
					title: "Read Only batch must deny",
					stages: [{ id: "inspect", request: { operation: "inspect", target: hybridFixtureTarget } }],
				},
			})
		} catch (error) {
			if (!String(error).includes("Full Access")) throw error
			restrictedBatchDenied = true
		}
		if (!restrictedBatchDenied) throw new Error("Installed batch widened the Read Only session")
		stages.push("installed-ai-batch-read-only-profile-denied")
		const hybridExecutePlan = await rpc<{
			id: string
			requestHash: string
			requirements: string[]
			request: Record<string, unknown>
		}>(page, "first_party_analysis_execute_prepare", {
			...analysisArgs,
			hybridProposal: {
				baselineKind: "receipt",
				baselineId: parsed.id,
				question: "Does this owned isolated fixture exit 0 and emit the expected bytes?",
			},
			input: {
				operation: "js_isolated_execute",
				target: hybridFixtureTarget,
				timeoutMs: 5000,
				scenario: {
					id: "installed-hybrid-owned",
					purpose: "Owned installed Hybrid process-interface assertion only",
					exitCode: 0,
					stdoutSha256: createHash("sha256").update(hybridExpectedOutput).digest("hex"),
				},
			},
		})
		if ((hybridExecutePlan.request.hybrid as { relation?: string })?.relation !== "exact-artifact-hash")
			throw new Error("Installed Hybrid execution plan lacks exact static basis")
		const hybridApproval = await rpc<{ executionToken: string }>(page, "approve_analysis_task", {
			...analysisArgs,
			cwd: workspace,
			planId: hybridExecutePlan.id,
			requestHash: hybridExecutePlan.requestHash,
			requirements: hybridExecutePlan.requirements,
		})
		const hybridExecuted = await rpc<{
			result: {
				hybrid?: { evidenceHash: string }
				isolation: { verifiedBeforeResume: boolean }
				scenario: { outcome: string }
			}
		}>(page, "first_party_analysis_execute_run", {
			...analysisArgs,
			planId: hybridExecutePlan.id,
			executionToken: hybridApproval.executionToken,
			input: hybridExecutePlan.request,
			confirmExecution: true,
		})
		if (
			hybridExecuted.result.isolation.verifiedBeforeResume !== true ||
			hybridExecuted.result.scenario.outcome !== "supported" ||
			hybridExecuted.result.hybrid?.evidenceHash !== hybridBasis.evidenceHash
		)
			throw new Error("Installed Hybrid owned isolated execution failed scoped assertions")
		const hybridBundle = await rpc<{ payload: { records: unknown[] } }>(page, "get_evidence_bundle", {
			...analysisArgs,
			input: { receiptIds: [parsed.id], taskIds: [hybridExecutePlan.id] },
		})
		if (hybridBundle.payload.records.length !== 2)
			throw new Error("Installed Hybrid selected static/runtime export incomplete")
		stages.push("installed-hybrid-owned-isolated-execution-and-export-passed")

		await page.getByLabel("Session Analysis mode", { exact: true }).selectOption("off")
		await page.waitForFunction(() => {
			const select = document.querySelector<HTMLSelectElement>('select[aria-label="Session Analysis mode"]')
			return select?.value === "off" && !select.disabled
		})
		await page.getByRole("button", { name: "Open Analysis Workspace", exact: true }).click()
		const guide = page.getByRole("region", { name: "Guided investigation", exact: true })
		await guide.waitFor({ timeout: 30000 })
		const androidBefore = await rpc<{ state: string }>(page, "setup_center_android_status", { environmentId: "local" })
		if (androidBefore.state !== "installed-not-tested")
			throw new Error("Installed Android pack did not start honestly untested")
		await guide.getByRole("button", { name: "Analyze / rebuild an owned Android app", exact: true }).click()
		const androidPanel = page.getByRole("region", { name: "Android Analysis and Rebuild Pack", exact: true })
		await androidPanel.waitFor({ timeout: 30000 })
		page.once("dialog", async (dialog) => {
			if (dialog.message().includes("fixed owned Android")) await dialog.accept()
			else await dialog.dismiss()
		})
		await androidPanel.getByRole("button", { name: "Test owned Android fixtures", exact: true }).click()
		await page.waitForFunction(
			() => {
				const panel = document.querySelector('[aria-label="Android Analysis and Rebuild Pack"]')
				return !!panel?.querySelector('[role="alert"]') || panel?.textContent?.includes("Pack status: ready")
			},
			undefined,
			{ timeout: 600000 },
		)
		if (await androidPanel.getByRole("alert").count())
			throw new Error("Installed Android fixture acceptance failed; no readiness claimed")
		const androidAfter = await rpc<{ state: string; receipt: unknown }>(page, "setup_center_android_status", {
			environmentId: "local",
		})
		if (androidAfter.state !== "ready") throw new Error("Installed Android pack fixture did not pass")
		await writeFile(join(evidence, "android-toolchain-readiness.json"), JSON.stringify(androidAfter, null, 2))
		stages.push("installed-android-owned-resource-multidex-smali-jadx-signature-and-native-tools-passed")
		await page.getByRole("button", { name: "Start here", exact: true }).click()

		await guide.getByRole("button", { name: "Understand a JS / Electron application", exact: true }).click()
		stages.push("installed-guided-entry-navigation-passed")
		await page.getByLabel("First-party Analysis Workspace", { exact: true }).waitFor()
		await page.getByLabel("Saved analysis receipt", { exact: true }).selectOption(parsed.id)
		if (await page.getByRole("button", { name: "Inspect static sources", exact: true }).isEnabled())
			throw new Error("Off analysis must block new inspection")
		await page.getByRole("button", { name: "verification", exact: true }).click()
		await page
			.getByText("Receipt integrity and static inspection are not behavioral certification.", { exact: false })
			.waitFor()
		stages.push("installed-first-party-mode-parser-evidence-passed")
		// Receipt-bound read stays available Off; no analysis, approval or target execution is started.
		const sourceWorkspace = page.getByLabel("First-party Analysis Workspace", { exact: true })
		// Explicit UI opt-in; retained queries remain available after returning to Off.
		await page.getByLabel("Session Analysis mode", { exact: true }).selectOption("static")
		await sourceWorkspace.getByLabel("JavaScript analysis target", { exact: true }).fill("owned-application-graph")
		await sourceWorkspace.getByLabel("JavaScript comparison target", { exact: true }).fill("")
		await sourceWorkspace.getByLabel("Include application graph and Electron boundaries", { exact: true }).check()
		if (!(await sourceWorkspace.getByLabel("Include file-local semantic graph", { exact: true }).isChecked()))
			throw new Error("Application graph did not explicitly bind semantic opt-in")
		const applicationRun = sourceWorkspace.getByRole("button", { name: "Inspect static sources", exact: true })
		await applicationRun.waitFor()
		await page.waitForFunction(
			() =>
				!document.querySelector<HTMLButtonElement>('[aria-label="First-party Analysis Workspace"] button.bg-primary')
					?.disabled,
			undefined,
			{ timeout: 30000 },
		)
		await applicationRun.click()
		await page.waitForFunction(
			() => {
				const s = document.querySelector<HTMLSelectElement>('[aria-label="Saved analysis receipt"]')
				return (
					!!s?.selectedOptions[0]?.textContent?.includes("owned-application-graph") &&
					!document.querySelector<HTMLButtonElement>('[aria-label="First-party Analysis Workspace"] button.bg-primary')
						?.disabled
				)
			},
			undefined,
			{ timeout: 330000 },
		)
		const applicationReceiptId = await sourceWorkspace.getByLabel("Saved analysis receipt", { exact: true }).inputValue()
		const appSummary = await rpc<{ available: boolean; summary: { profile: string; coverage: { status: string } } }>(
			page,
			"first_party_analysis_evidence",
			{ ...analysisArgs, query: { receiptId: applicationReceiptId, view: "application-summary" } },
		)
		if (
			!appSummary.available ||
			appSummary.summary.profile !== "cline-application/1" ||
			appSummary.summary.coverage.status !== "partial"
		)
			throw new Error("Installed application graph summary missing or overstated")
		// Verification intentionally has no filter: select a filterable view first.
		await sourceWorkspace.getByRole("button", { name: "application-nodes", exact: true }).click()
		await sourceWorkspace.getByLabel("Filter analysis evidence", { exact: true }).fill("ipc-channel")
		await sourceWorkspace.getByText('"ipc-channel"', { exact: false }).first().waitFor({ timeout: 30000 })
		await page.getByLabel("Session Analysis mode", { exact: true }).selectOption("off")
		const appWorkflows = sourceWorkspace.getByLabel("Saved application workflows", { exact: true })
		await appWorkflows.locator("summary").click()
		await appWorkflows.getByLabel("Application feature seed", { exact: true }).fill("owned:application")
		await appWorkflows.getByRole("button", { name: "Run saved application query", exact: true }).click()
		const appTrace = appWorkflows.getByRole("region", { name: "Saved application workflow result", exact: true })
		await appTrace.waitFor({ timeout: 30000 })
		const displayedAppTrace = JSON.parse(await appTrace.innerText())
		if (displayedAppTrace.summary?.matched_seeds < 1 || displayedAppTrace.providerCalls !== 0)
			throw new Error("Installed application trace UI did not show saved evidence")
		const savedAppTrace = await rpc<{ providerCalls: number; verifiedBehavior: boolean; summary: { matched_seeds: number } }>(
			page,
			"first_party_analysis_evidence",
			{
				...analysisArgs,
				query: {
					receiptId: applicationReceiptId,
					view: "application-trace",
					applicationTrace: { seed: { kind: "channel", value: "owned:application" }, direction: "both" },
					limit: 2,
				},
			},
		)
		if (
			savedAppTrace.providerCalls !== 0 ||
			savedAppTrace.verifiedBehavior !== false ||
			savedAppTrace.summary.matched_seeds < 1
		)
			throw new Error("Installed saved application trace contract failed")
		if (
			await stat(applicationSentinel).then(
				() => true,
				() => false,
			)
		)
			throw new Error("Installed application graph executed target code")
		await writeFile(
			join(evidence, "application-graph-evidence.json"),
			JSON.stringify({ receiptId: applicationReceiptId, summary: appSummary, trace: savedAppTrace }, null, 2),
		)
		stages.push("installed-application-graph-electron-saved-trace-no-execution-passed")
		await sourceWorkspace.getByLabel("Include application graph and Electron boundaries", { exact: true }).uncheck()
		await sourceWorkspace.getByLabel("Include file-local semantic graph", { exact: true }).uncheck()
		// Owned structural bytes only: the fixture has no executable entrypoint or code.
		const fuseBytes = Buffer.alloc(512)
		fuseBytes.write("MZ")
		fuseBytes.writeUInt32LE(0x80, 0x3c)
		fuseBytes.writeUInt32LE(0x4550, 0x80)
		fuseBytes.writeUInt16LE(0x8664, 0x84)
		fuseBytes.write("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX", 255, "ascii")
		Buffer.from([1, 9, 49, 48, 49, 48, 49, 49, 48, 48, 49]).copy(fuseBytes, 287)
		await writeFile(join(workspace, "owned-fuses.exe"), fuseBytes)
		await page.getByLabel("Session Analysis mode", { exact: true }).selectOption("static")
		await sourceWorkspace.getByLabel("JavaScript analysis target", { exact: true }).fill("owned-fuses.exe")
		await sourceWorkspace.getByLabel("Inspect executable Electron fuses only", { exact: true }).check()
		if (
			!(await sourceWorkspace.getByLabel("JavaScript comparison target", { exact: true }).isDisabled()) ||
			!(await sourceWorkspace.getByLabel("Include file-local semantic graph", { exact: true }).isDisabled())
		)
			throw new Error("Fuse-only UI allowed mixed source options")
		const fuseRun = sourceWorkspace.getByRole("button", { name: "Inspect executable fuses", exact: true })
		await page.waitForFunction(
			() =>
				!document.querySelector<HTMLButtonElement>('[aria-label="First-party Analysis Workspace"] button.bg-primary')
					?.disabled,
			undefined,
			{ timeout: 30000 },
		)
		await fuseRun.click()
		await page.waitForFunction(
			() => {
				const s = document.querySelector<HTMLSelectElement>('[aria-label="Saved analysis receipt"]')
				return (
					!!s?.selectedOptions[0]?.textContent?.includes("owned-fuses.exe") &&
					!document.querySelector<HTMLButtonElement>('[aria-label="First-party Analysis Workspace"] button.bg-primary')
						?.disabled
				)
			},
			undefined,
			{ timeout: 75000 },
		)
		const fuseReceiptId = await sourceWorkspace.getByLabel("Saved analysis receipt", { exact: true }).inputValue()
		await page.getByLabel("Session Analysis mode", { exact: true }).selectOption("off")
		await sourceWorkspace.getByRole("button", { name: "electron-fuses", exact: true }).click()
		await sourceWorkspace.getByLabel("Filter analysis evidence", { exact: true }).fill("")
		await sourceWorkspace.getByText('"RunAsNode"', { exact: false }).first().waitFor({ timeout: 30000 })
		await sourceWorkspace.getByLabel("Fuse evidence section", { exact: true }).selectOption("runtime_implications")
		await sourceWorkspace.getByText('"not_honored"', { exact: false }).first().waitFor({ timeout: 30000 })
		const fuseEvidence = await rpc<{
			available: boolean
			artifact: { sha256: string; bytes: number }
			items: Array<{ subject: string; outcome: string }>
			providerCalls: number
			targetExecuted: boolean
			verifiedBehavior: boolean
		}>(page, "first_party_analysis_evidence", {
			...analysisArgs,
			query: { receiptId: fuseReceiptId, view: "electron-fuses", fuseSection: "runtime_implications" },
		})
		if (
			!fuseEvidence.available ||
			fuseEvidence.artifact.sha256 !== createHash("sha256").update(fuseBytes).digest("hex") ||
			fuseEvidence.artifact.bytes !== fuseBytes.length ||
			fuseEvidence.providerCalls !== 0 ||
			fuseEvidence.targetExecuted !== false ||
			fuseEvidence.verifiedBehavior !== false ||
			!fuseEvidence.items.some((i) => i.subject === "node_cli_inspect_arguments" && i.outcome === "not_honored")
		)
			throw new Error("Installed fuse evidence lost exact bytes, derivation or no-execution scope")
		if (!fuseBytes.equals(await readFile(join(workspace, "owned-fuses.exe"))))
			throw new Error("Installed fuse inspection modified the original")
		await writeFile(
			join(evidence, "electron-fuses-evidence.json"),
			JSON.stringify(
				{
					receiptId: fuseReceiptId,
					evidence: fuseEvidence,
					fixtureScope:
						"Owned structural PE bytes; no executable entrypoint, live model or arbitrary target certification",
				},
				null,
				2,
			),
		)
		stages.push("installed-electron-fuses-explicit-read-only-hash-bound-saved-off-passed")
		await sourceWorkspace.getByLabel("Inspect executable Electron fuses only", { exact: true }).uncheck()
		await sourceWorkspace.getByLabel("JavaScript analysis target", { exact: true }).fill("owned-application-graph")
		await sourceWorkspace.getByLabel("Saved analysis receipt", { exact: true }).selectOption(parsed.id)
		await sourceWorkspace.getByLabel("Filter analysis evidence", { exact: true }).fill("")
		await sourceWorkspace.getByRole("button", { name: "artifacts", exact: true }).click()
		await sourceWorkspace.getByLabel("Filter analysis evidence", { exact: true }).fill("selection-owned.ts")
		const inspectSaved = sourceWorkspace.getByRole("button", { name: "Inspect saved source identity", exact: true })
		await inspectSaved.waitFor({ timeout: 30000 })
		if ((await inspectSaved.count()) !== 1) throw new Error("Installed source identity fixture did not resolve uniquely")
		await inspectSaved.click()
		const selectedSource = page.getByRole("region", { name: "Selected source evidence", exact: true })
		await selectedSource.getByText("Source identity: matched", { exact: true }).waitFor({ timeout: 30000 })
		await selectedSource
			.getByText(`Saved SHA256: ${createHash("sha256").update(sourceSelectionText).digest("hex")}`, { exact: true })
			.waitFor()
		await selectedSource
			.getByLabel("Bounded source snapshot", { exact: true })
			.getByText("NEVER_EXECUTE_SOURCE_SELECTION", { exact: false })
			.waitFor()
		// Normal hit-tested click must remain reachable after a large selection preview.
		// Never force clicks or hide the composer to mask a real overflow regression.
		await sourceWorkspace.getByRole("button", { name: "findings", exact: true }).click()
		await inspectSaved.first().waitFor({ timeout: 30000 })
		await inspectSaved.first().click()
		await selectedSource.locator('li[aria-current="location"]').waitFor({ timeout: 30000 })
		await selectedSource.getByText("Source identity: matched", { exact: true }).waitFor()
		try {
			await writeFile(sourceSelectionTarget, 'export const changedSelection = "CURRENT_NOT_SAVED";')
			await selectedSource.getByRole("button", { name: "Recheck selected source", exact: true }).click()
			await selectedSource.getByText("Source identity: stale", { exact: true }).waitFor({ timeout: 30000 })
			if (
				(await selectedSource.getByLabel("Bounded source snapshot", { exact: true }).count()) ||
				(await selectedSource.getByRole("button", { name: "Use source path in analysis panes", exact: true }).count())
			)
				throw new Error("Installed stale source exposed a preview or reusable path")
			if ((await selectedSource.innerText()).includes("CURRENT_NOT_SAVED"))
				throw new Error("Installed stale source leaked current bytes")
		} finally {
			await writeFile(sourceSelectionTarget, sourceSelectionText)
		}
		await selectedSource.getByRole("button", { name: "Recheck selected source", exact: true }).click()
		await selectedSource.getByText("Source identity: matched", { exact: true }).waitFor({ timeout: 30000 })
		await page.getByRole("button", { name: "Start here", exact: true }).click()
		await selectedSource.getByText("Source identity: matched", { exact: true }).waitFor()
		await selectedSource.getByRole("button", { name: "Clear source evidence selection", exact: true }).click()
		await selectedSource.waitFor({ state: "detached" })
		if ((await rpc<{ mode: string }>(page, "first_party_analysis_status", analysisArgs)).mode !== "off")
			throw new Error("Installed source selection changed Analysis Off")
		stages.push("installed-source-evidence-hash-bound-selection-stale-recheck-no-execution-passed")

		await page.getByRole("button", { name: "Close diff view", exact: true }).click()

		await page.waitForFunction(() => document.querySelectorAll('[data-message-role="user"]').length >= 120)
		for (let sample = 0; sample < 3; sample++) {
			const started = performance.now()
			await page.locator('[data-message-role="user"]').first().scrollIntoViewIfNeeded()
			await page.locator('[data-message-role="user"]').last().scrollIntoViewIfNeeded()
			await acceptanceAction(
				"owned-transcript-frame",
				() =>
					page.evaluate(
						() => new Promise<void>((done) => requestAnimationFrame(() => requestAnimationFrame(() => done()))),
					),
				30_000,
			)
			transcriptScrollSamples.push(performance.now() - started)
		}
		stages.push("owned-120-row-transcript-scroll-acceptance-passed")
		await page.locator('a[data-cline-file-reference="./OWNED_SCROLL_REPORT.md"]').last().click()
		const preview = page.getByTestId("artifact-preview-scroll")
		await preview.waitFor({ state: "visible" })
		if (!(await preview.evaluate((el) => el.scrollHeight > el.clientHeight)))
			throw new Error("Owned Markdown preview is not independently scrollable")
		const box = await preview.boundingBox()
		if (
			!box ||
			box.y < 0 ||
			box.y + box.height >
				(page.viewportSize()?.height ??
					(await acceptanceAction("owned-viewport-read", () => page.evaluate(() => innerHeight), 30_000)))
		)
			throw new Error("Markdown preview exceeds viewport")
		await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2)
		await page.mouse.wheel(0, 700)
		await page.waitForFunction(() => (document.querySelector('[data-testid="artifact-preview-scroll"]')?.scrollTop ?? 0) > 0)
		await preview.focus()
		await page.keyboard.press("Control+End")
		await page.keyboard.press("End")
		await page.waitForFunction(() => {
			const el = document.querySelector('[data-testid="artifact-preview-scroll"]')
			return !!el && el.scrollTop + el.clientHeight >= el.scrollHeight - 2
		})
		await page.keyboard.press("Home")
		await page.waitForFunction(
			() => (document.querySelector('[data-testid="artifact-preview-scroll"]')?.scrollTop ?? -1) === 0,
		)
		await page.keyboard.press("Escape")
		await preview.waitFor({ state: "hidden" })
		stages.push("owned-markdown-preview-wheel-keyboard-scroll-passed")

		await settings(page, "General")
		const instructions = page.getByRole("textbox", {
			name: "Custom AI instructions",
			exact: true,
		})
		await instructions.fill("Installer acceptance: preserve this owned local setting.")
		await page.getByRole("button", { name: "Save instructions", exact: true }).click()
		await page.getByText(/Saved permanently/).waitFor()
		stages.push("local-setting-persisted-through-ui")
		await settings(page, "Analysis environment")
		await page.getByRole("button", { name: "Check analysis readiness", exact: true }).click()
		const ready = await rpc<{
			configured: boolean
			runtime: { source: string }
			readiness: { status: string }
			interpreter: { executable: string }
			setupCenter: { desktopBuild: { sourceCommit: string; capabilitySchema: string } }
		}>(page, "get_analysis_environment", { environmentId: "local" })
		await writeFile(join(evidence, "analysis-readiness.json"), JSON.stringify(ready, null, 2))
		await page.screenshot({ path: join(evidence, "readiness.png") })
		if (
			!ready.configured ||
			ready.readiness.status !== "completed" ||
			ready.runtime?.source !== "bundled" ||
			!ready.interpreter.executable.replaceAll("\\", "/").toLowerCase().includes("/resources/analysis-runtime/python.exe")
		)
			throw new Error("Installed application did not validate its bundled interpreter without CLINE_RE_PYTHON")
		await page.getByText("Fixture execution: completed.", { exact: false }).waitFor({ timeout: 90_000 })
		stages.push("installed-interpreter-owned-fixtures-passed")
		if (
			ready.setupCenter.desktopBuild.sourceCommit !== process.env.GITHUB_SHA ||
			ready.setupCenter.desktopBuild.capabilitySchema !== "setup-center/processor-acceptance-v2"
		)
			throw new Error("Installed setup UI build identity mismatch")
		await page.screenshot({ path: join(evidence, "readiness.png") })

		await page.getByRole("button", { name: "Open Setup Center", exact: true }).click()
		await page.getByLabel("IDA acceptance processor", { exact: true }).selectOption("arm64")
		// UI selection is not a commercial-license test; never launch licensed IDA in hosted CI.
		stages.push("installed-setup-navigation-and-arm64-selection-passed")
		await settings(page, "Analysis environment")
		await page.getByRole("button", { name: "Open Setup Center", exact: true }).click()
		if ((await page.getByLabel("IDA acceptance processor", { exact: true }).inputValue()) !== "arm64")
			throw new Error("Installed Setup Center forgot the selected processor after navigation")
		if (!(await page.getByRole("button", { name: "Test IDA integration (optional)", exact: true }).isVisible()))
			throw new Error("Installed IDA test is not clearly optional")
		stages.push("installed-setup-processor-remount-and-optional-test-passed")
		const triagePanel = page.getByRole("region", { name: "Binary Triage Pack readiness", exact: true })
		await triagePanel.waitFor({ timeout: 30000 })
		const triageBefore = await rpc<{ capabilities: Array<{ id: string; state: string }> }>(page, "binary_triage_status", {
			environmentId: "local",
		})
		if (triageBefore.capabilities.length !== 4 || triageBefore.capabilities.some((c) => c.state !== "installed-not-tested"))
			throw new Error("Installed triage pack must start installed but untested")
		page.once("dialog", async (dialog) => {
			if (dialog.message().includes("fixed project-owned PE fixtures")) await dialog.accept()
			else await dialog.dismiss()
		})
		await triagePanel.getByRole("button", { name: "Test triage fixtures", exact: true }).click()
		// Four sequential workers each have a 90-second budget; observe the existing
		// UI terminal result (success OR bounded error), never replay the test.
		await page.waitForFunction(
			() => {
				const panel = document.querySelector('[aria-label="Binary Triage Pack readiness"]')
				return (
					!!panel?.querySelector('[role="alert"]') ||
					(panel?.textContent?.includes(
						"Owned fixture passed for this pack/interpreter; target compatibility remains separate",
					) &&
						!panel?.textContent?.includes("Testing owned fixtures…"))
				)
			},
			undefined,
			{ timeout: 425000 },
		)
		const triageError = await triagePanel
			.getByRole("alert")
			.textContent({ timeout: 1000 })
			.catch(() => null)
		if (triageError) {
			await writeFile(
				join(evidence, "binary-triage-readiness-error.json"),
				JSON.stringify({ message: triageError.slice(0, 1000) }, null, 2),
			)
			throw new Error(`Installed triage owned acceptance: ${triageError.slice(0, 1000)}`)
		}
		const triageAfter = await rpc<{ capabilities: Array<{ id: string; state: string }> }>(page, "binary_triage_status", {
			environmentId: "local",
		})
		if (triageAfter.capabilities.length !== 4 || triageAfter.capabilities.some((c) => c.state !== "ready"))
			throw new Error("Installed triage engine fixture did not pass")
		await writeFile(join(evidence, "binary-triage-readiness.json"), JSON.stringify(triageAfter, null, 2))
		stages.push("installed-binary-triage-four-owned-engines-passed")

		const triageInput = {
			operation: "scan_yara",
			target: "owned-triage.exe",
			question: "Does the owned neutral marker match?",
		}
		let restrictedTriageDenied = false
		try {
			await rpc(page, "binary_triage_run", {
				...analysisArgs,
				confirmed: true,
				requestId: randomUUID(),
				input: triageInput,
			})
		} catch {
			restrictedTriageDenied = true
		}
		if (!restrictedTriageDenied) throw new Error("Binary triage widened the Read Only session")
		const triageSession = await rpc<{ sessionId: string }>(page, "chat_session_command", {
			request: {
				action: "start",
				config: {
					sessionId: "installer-owned-triage",
					environmentId: "local",
					cwd: workspace,
					workspaceRoot: workspace,
					provider: "openai",
					model: "gpt-4.1-mini",
					apiKey: "owned-offline-fixture",
					baseUrl: "http://127.0.0.1:1/v1",
					enableTools: false,
					permissionProfile: "full-access",
					initialMessages: [{ id: "owned-triage-start", role: "user", content: "Owned offline static triage fixture" }],
				},
			},
		})

		// Exercise exact preview -> separately approved write through the installed SDK/sidecar.
		const ownedSmaliBefore = ".method public value()I\n    .locals 1\n    const/4 v0, 0x0\n    return v0\n.end method"
		const ownedSmaliAfter = ownedSmaliBefore.replace("0x0", "0x1")
		const ownedSmaliText = `.class public Lowned/Sample;\n.super Ljava/lang/Object;\n\n${ownedSmaliBefore}\n`
		const ownedSmaliSource = join(workspace, "owned-source.smali")
		const ownedSmaliOutput = join(workspace, "owned-candidate.smali")
		await writeFile(ownedSmaliSource, ownedSmaliText)
		const ownedPatchArgs = { sessionId: triageSession.sessionId, environmentId: "local", cwd: workspace }
		const ownedPatch = {
			expected_sha256: createHash("sha256").update(ownedSmaliText).digest("hex"),
			class_descriptor: "Lowned/Sample;",
			method_signature: "value()I",
			expected_method: ownedSmaliBefore,
			replacement_method: ownedSmaliAfter,
		}
		async function runOwnedAdvanced(request: Record<string, unknown>) {
			const plan = await rpc<{ id: string; requestHash: string; requirements: string[]; request: Record<string, unknown> }>(
				page,
				"prepare_analysis_task",
				{ ...ownedPatchArgs, kind: "static", request },
			)
			const approval = await rpc<{ executionToken: string }>(page, "approve_analysis_task", {
				...ownedPatchArgs,
				planId: plan.id,
				requestHash: plan.requestHash,
				requirements: plan.requirements,
			})
			return rpc<{
				result: {
					published: boolean
					previewSha256: string
					projectSha256?: string
					sourceUnchanged?: boolean
					validation?: string
					outputSha256?: string
					batchPreviewSha256?: string
					status?: string
					mode?: string
					endpointReachableInSelectedGraph?: boolean
					edges?: unknown[]
					comparison?: { changed: string[] }
					resolvedEvidence?: { resolved: { name: string; version: string }[] }
					result?: {
						status: string
						evidence: {
							boundaryAgreement: boolean
							rangeSha256: string
							decoders: { engine: string; version: string; decodedBytes: number }[]
						}
					}
					results?: { status: string }[]
					verifiedStageIds?: string[]
					remainingStageIds?: string[]
					witnesses?: { sourceId: string; sinkId: string; route: string[] }[]
					observedExecution?: boolean
					selectedFunction?: { sha256: string; text: string }
					conclusion?: string
					executed?: boolean
					enginePreflight?: string
					batchDraft?: { stages: { request: Record<string, unknown> }[] }
					stages?: { id: string; dependsOn: string[] }[]
				}
				plan: {
					id: string
					status: string
					candidateOutcome?: {
						operation: string
						evidence: string
						outputSha256?: string
						publication?: string
						checks: { id: string; status: string }[]
					}
				}
			}>(page, "run_static_analysis", {
				...ownedPatchArgs,
				planId: plan.id,
				executionToken: approval.executionToken,
				input: plan.request,
			})
		}
		const previewRequest = {
			operation: "preview_smali_patch",
			target: ownedSmaliSource,
			output_file: ownedSmaliOutput,
			smali_patch: ownedPatch,
			timeout_ms: 120000,
		}
		const ownedPreview = await runOwnedAdvanced(previewRequest)
		if (ownedPreview.result.published || ownedPreview.plan.status !== "completed")
			throw new Error("Installed Smali preview unexpectedly published or failed")
		const ownedApplied = await runOwnedAdvanced({
			...previewRequest,
			operation: "patch_smali_method",
			smali_patch: { ...ownedPatch, preview_sha256: ownedPreview.result.previewSha256 },
		})
		if (
			!ownedApplied.result.published ||
			ownedApplied.plan.status !== "completed" ||
			(await readFile(ownedSmaliSource, "utf8")) !== ownedSmaliText ||
			(await readFile(ownedSmaliOutput, "utf8")) !== ownedSmaliText.replace(ownedSmaliBefore, ownedSmaliAfter)
		)
			throw new Error("Installed hash-bound Smali candidate patch failed")
		stages.push("installed-advanced-smali-preview-approved-candidate-original-preserved")

		const ownedProject = join(workspace, "owned-apk-project"),
			ownedProjectSmali = join(ownedProject, "smali/owned")
		await mkdir(ownedProjectSmali, { recursive: true })
		await mkdir(join(ownedProject, "smali_classes2/owned"), { recursive: true })
		await mkdir(join(ownedProject, "res/values"), { recursive: true })
		await writeFile(join(ownedProjectSmali, "Sample.smali"), ownedSmaliText)
		await writeFile(
			join(ownedProject, "smali_classes2/owned/Second.smali"),
			".class public Lowned/Second;\n.super Ljava/lang/Object;\n.method public static value()I\n .registers 1\n const/4 v0, 0x7\n return v0\n.end method\n",
		)
		await writeFile(
			join(ownedProject, "AndroidManifest.xml"),
			'<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.cline.owned" android:versionCode="1" android:versionName="1"><uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/><application android:label="@string/app_name" android:hasCode="true"/></manifest>',
		)
		await writeFile(
			join(ownedProject, "res/values/strings.xml"),
			'<resources><string name="app_name">Owned installed candidate</string></resources>',
		)
		await writeFile(
			join(ownedProject, "apktool.yml"),
			'version: 3.0.3\napkFileName: owned.apk\nusesFramework:\n  ids:\n  - 1\nsdkInfo:\n  minSdkVersion: 23\n  targetSdkVersion: 35\nversionInfo:\n  versionCode: 1\n  versionName: "1"\n',
		)
		const ownedProjectPatch = { patches: [{ path: "smali/owned/Sample.smali", patch: ownedPatch }] }
		const projectPreviewRequest = {
			operation: "preview_android_candidate",
			target: ownedProject,
			output_file: join(workspace, "owned-project-candidate.apk"),
			android_project_patch: ownedProjectPatch,
			timeout_ms: 120000,
			smali_api_level: 28,
		}
		const projectPreview = await runOwnedAdvanced(projectPreviewRequest)
		if (
			projectPreview.plan.status !== "completed" ||
			projectPreview.result.executed !== false ||
			projectPreview.result.published ||
			!projectPreview.result.projectSha256
		)
			throw new Error("Installed project preview failed or wrote output")
		const projectApplied = await runOwnedAdvanced({
			...projectPreviewRequest,
			operation: "build_android_candidate",
			android_project_patch: {
				...ownedProjectPatch,
				expected_project_sha256: projectPreview.result.projectSha256,
				preview_sha256: projectPreview.result.previewSha256,
			},
		})
		if (
			projectApplied.plan.status !== "completed" ||
			projectApplied.result.status !== "completed" ||
			!projectApplied.result.published ||
			!projectApplied.result.sourceUnchanged ||
			!projectApplied.result.outputSha256 ||
			!["assemble-smali", "assemble-smali_classes2", "rebuild-apk"].every((id) =>
				projectApplied.result.stages?.some((stage) => stage.id === id),
			) ||
			(await readFile(join(ownedProjectSmali, "Sample.smali"), "utf8")) !== ownedSmaliText
		)
			throw new Error("Installed approved Android project pipeline failed or altered its source")
		const projectOutcome = projectApplied.plan.candidateOutcome
		if (
			projectOutcome?.operation !== "build_android_candidate" ||
			projectOutcome.evidence !== "bounded-checks-passed" ||
			projectOutcome.outputSha256 !== projectApplied.result.outputSha256 ||
			projectOutcome.publication !== "new-unsigned-candidate" ||
			projectOutcome.checks.map((c) => c.id).join(",") !== "patch-0,assemble-smali,assemble-smali_classes2,rebuild-apk" ||
			projectOutcome.checks.some((c) => c.status !== "completed")
		)
			throw new Error("Installed real Android project build did not retain its bounded unsigned candidate outcome")
		// A build receipt is not authority to verify, sign or execute its output.
		const verificationDraft = await rpc<{
			id: string
			status: string
			permission: string
			kind: string
			requestHash: string
			requirements: string[]
			request: { operation: string; target: string; candidate_validation: { kind: string; expected_sha256: string } }
			candidateSource: { planId: string; outputSha256: string }
		}>(page, "prepare_candidate_verification", { ...ownedPatchArgs, planId: projectApplied.plan.id })
		if (
			verificationDraft.id === projectApplied.plan.id ||
			verificationDraft.status !== "awaiting-approval" ||
			verificationDraft.permission !== "Inspect" ||
			verificationDraft.kind !== "static" ||
			verificationDraft.request.operation !== "validate_candidate" ||
			verificationDraft.request.target !== realpathSync.native(projectPreviewRequest.output_file) ||
			verificationDraft.request.candidate_validation.kind !== "apk" ||
			verificationDraft.request.candidate_validation.expected_sha256 !== projectApplied.result.outputSha256 ||
			verificationDraft.candidateSource.planId !== projectApplied.plan.id ||
			verificationDraft.candidateSource.outputSha256 !== projectApplied.result.outputSha256
		)
			throw new Error("Installed Android candidate handoff lost independent approval or exact output identity")
		let verificationReplayDenied = false
		try {
			await rpc(page, "run_static_analysis", {
				...ownedPatchArgs,
				planId: verificationDraft.id,
				executionToken: "not-an-approval",
				input: verificationDraft.request,
			})
		} catch {
			verificationReplayDenied = true
		}
		if (!verificationReplayDenied) throw new Error("Installed candidate verification ran without its own approval")
		await rpc(page, "cancel_analysis_task", { ...ownedPatchArgs, planId: verificationDraft.id })
		const builtCandidateBytes = await readFile(projectPreviewRequest.output_file)
		try {
			await writeFile(
				projectPreviewRequest.output_file,
				Buffer.concat([builtCandidateBytes, Buffer.from("owned-stale-candidate")]),
			)
			let staleCandidateDenied = false
			try {
				await rpc(page, "prepare_candidate_verification", { ...ownedPatchArgs, planId: projectApplied.plan.id })
			} catch {
				staleCandidateDenied = true
			}
			if (!staleCandidateDenied) throw new Error("Installed build handoff accepted a changed candidate")
		} finally {
			await writeFile(projectPreviewRequest.output_file, builtCandidateBytes)
		}
		if (
			createHash("sha256")
				.update(await readFile(projectPreviewRequest.output_file))
				.digest("hex") !== projectApplied.result.outputSha256
		)
			throw new Error("Installed handoff fixture did not restore its owned APK bytes")
		stages.push("installed-approved-android-project-patch-assemble-rebuild-originals-preserved")
		// Independently approve actual read-only verification of the real unsigned APK.
		// A failed signature check must remain visible next to its successful structure check.
		const lifecycleDraft = await rpc<typeof verificationDraft>(page, "prepare_candidate_verification", {
			...ownedPatchArgs,
			planId: projectApplied.plan.id,
		})
		const lifecycleApproval = await rpc<{ executionToken: string }>(page, "approve_analysis_task", {
			...ownedPatchArgs,
			planId: lifecycleDraft.id,
			requestHash: lifecycleDraft.requestHash,
			requirements: lifecycleDraft.requirements,
		})
		const lifecycleVerification = await rpc<{ plan: { status: string }; result: { status: string } }>(
			page,
			"run_static_analysis",
			{
				...ownedPatchArgs,
				planId: lifecycleDraft.id,
				executionToken: lifecycleApproval.executionToken,
				input: lifecycleDraft.request,
			},
		)
		const lifecycleTasks = await rpc<
			Array<{
				id: string
				candidateLifecycle?: {
					version: string
					outputSha256: string
					signing: string
					device: string
					totalLinkedAttempts: number
					rejectedLinks: number
					verificationAttempts: {
						planId: string
						status: string
						evidence: string
						structure: string
						signature: string
						receiptSha256?: string
					}[]
				}
			}>
		>(page, "list_analysis_tasks", { ...ownedPatchArgs })
		const lifecycle = lifecycleTasks.find((task) => task.id === projectApplied.plan.id)?.candidateLifecycle
		const verifiedAttempt = lifecycle?.verificationAttempts.find((attempt) => attempt.planId === lifecycleDraft.id)
		const cancelledAttempt = lifecycle?.verificationAttempts.find((attempt) => attempt.planId === verificationDraft.id)
		if (
			lifecycleVerification.plan.status !== "failed" ||
			lifecycleVerification.result.status !== "failed" ||
			lifecycle?.version !== "android-candidate-lifecycle/v1" ||
			lifecycle.outputSha256 !== projectApplied.result.outputSha256 ||
			lifecycle.signing !== "not-attested" ||
			lifecycle.device !== "not-linked" ||
			lifecycle.totalLinkedAttempts !== 2 ||
			lifecycle.rejectedLinks !== 0 ||
			verifiedAttempt?.evidence !== "failed" ||
			verifiedAttempt.structure !== "completed" ||
			verifiedAttempt.signature !== "failed" ||
			!/^[a-f0-9]{64}$/.test(verifiedAttempt.receiptSha256 ?? "") ||
			cancelledAttempt?.status !== "cancelled" ||
			cancelledAttempt.signature !== "unavailable" ||
			!(await readFile(projectPreviewRequest.output_file)).equals(builtCandidateBytes)
		)
			throw new Error(
				"Installed Android lifecycle lost independent attempts, unsigned signature failure, identity or no-execution boundary",
			)
		stages.push("installed-android-lifecycle-build-verify-unsigned-signature-failure-no-execution-passed")

		const batchBinary = join(workspace, "owned-candidate-input.bin"),
			batchAst = join(workspace, "owned-candidate-input.ts"),
			batchManifest = join(workspace, "owned-candidate-batch.json")
		const batchBinaryBefore = Buffer.from([0, 1, 2, 3]),
			batchAstBefore = "export const owned = 1; export const enabled = false;\n"
		await writeFile(batchBinary, batchBinaryBefore)
		await writeFile(batchAst, batchAstBefore)
		const ownedBatch = {
			schemaVersion: 1,
			stages: [
				{
					id: "bytes",
					operation: "patch_binary",
					target: "owned-candidate-input.bin",
					output_file: "owned-candidate-output.bin",
					candidate: {
						expected_sha256: createHash("sha256").update(batchBinaryBefore).digest("hex"),
						byte_patches: [
							{ offset: 0, expected_hex: "00", replacement_hex: "aa" },
							{ offset: 1, expected_hex: "01", replacement_hex: "ff" },
						],
					},
				},
				{
					id: "literal",
					operation: "apply_ast_transform",
					target: "owned-candidate-input.ts",
					output_file: "owned-candidate-output.ts",
					candidate: {
						expected_sha256: createHash("sha256").update(batchAstBefore).digest("hex"),
						literals: [
							{ start: batchAstBefore.indexOf("1"), expected: "1", replacement: "200" },
							{ start: batchAstBefore.indexOf("false"), expected: "false", replacement: "true" },
						],
					},
				},
			],
		}
		await writeFile(batchManifest, JSON.stringify(ownedBatch))
		const batchPreview = await runOwnedAdvanced({
			operation: "preview_candidate_batch",
			target: batchManifest,
			acknowledge_external_output: true,
			timeout_ms: 120000,
		})
		if (batchPreview.plan.status !== "completed" || !batchPreview.result.batchPreviewSha256)
			throw new Error("Installed candidate batch preview failed")
		const batchApply = await runOwnedAdvanced({
			operation: "apply_candidate_batch",
			target: batchManifest,
			batch_preview_sha256: batchPreview.result.batchPreviewSha256,
			acknowledge_external_output: true,
			timeout_ms: 120000,
		})
		if (
			batchApply.plan.status !== "completed" ||
			batchApply.result.status !== "completed" ||
			batchApply.result.results?.length !== 2 ||
			!batchApply.result.results.every((s) => s.status === "completed") ||
			!(await readFile(batchBinary)).equals(batchBinaryBefore) ||
			(await readFile(batchAst, "utf8")) !== batchAstBefore ||
			!(await readFile(join(workspace, "owned-candidate-output.bin"))).equals(Buffer.from([170, 255, 2, 3])) ||
			(await readFile(join(workspace, "owned-candidate-output.ts"), "utf8")) !==
				batchAstBefore.replace("= 1", "= 200").replace("false", "true")
		)
			throw new Error("Installed approved candidate batch did not preserve inputs or publish exact candidates")
		stages.push("installed-preview-approved-binary-ast-batch-originals-preserved")
		const batchAudit = await runOwnedAdvanced({
			operation: "audit_candidate_batch",
			target: batchManifest,
			timeout_ms: 120000,
		})
		if (
			batchAudit.plan.status !== "completed" ||
			batchAudit.result.status !== "completed" ||
			batchAudit.result.published !== false ||
			batchAudit.result.verifiedStageIds?.join(",") !== "bytes,literal" ||
			batchAudit.result.remainingStageIds?.length !== 0
		)
			throw new Error("Installed read-only candidate audit failed")
		const witnessGraph = join(workspace, "owned-source-sink-graph.json")
		await writeFile(
			witnessGraph,
			JSON.stringify({
				schemaVersion: 1,
				nodes: ["a", "b"].map((id) => ({
					id,
					kind: "native-symbol",
					label: id,
					artifactSha256: "a".repeat(64),
					confidence: "candidate",
					evidenceIndex: 0,
				})),
				edges: [{ source: "a", target: "b", relation: "references-candidate", confidence: "candidate" }],
				sourceHashes: ["a".repeat(64)],
				coverage: ["owned declared candidate fixture only"],
			}),
		)
		const witness = await runOwnedAdvanced({
			operation: "trace_source_sink",
			target: witnessGraph,
			source_sink: { source_ids: ["a"], sink_ids: ["b"], relation: "declared-relationships" },
			timeout_ms: 120000,
		})
		if (
			witness.plan.status !== "completed" ||
			witness.result.status !== "completed" ||
			witness.result.observedExecution !== false ||
			witness.result.witnesses?.length !== 1 ||
			witness.result.witnesses[0].route.join(",") !== "a,b" ||
			!(await readFile(batchBinary)).equals(batchBinaryBefore) ||
			(await readFile(batchAst, "utf8")) !== batchAstBefore
		)
			throw new Error("Installed source/sink or multi-edit preservation failed")
		stages.push("installed-multiedit-audit-source-sink-originals-preserved")
		const workflowCatalog = await rpc<{ recommendations: { command: string; scope: string }[]; releaseStatus: string }>(
			page,
			"analysis_command_catalog",
			{ environmentId: "local" },
		)
		if (
			workflowCatalog.recommendations.length !== 55 ||
			new Set(workflowCatalog.recommendations.map((r) => r.command)).size !== 55 ||
			workflowCatalog.releaseStatus !== "not-certified-by-catalog"
		)
			throw new Error("Installed original recommendation ledger is incomplete or falsely certified")
		const ownedWorkflowSource = join(workspace, "owned-workflow.ts"),
			ownedWorkflowText = 'export function ownedWorkflow(){ return "owned evidence"; }\n'
		await writeFile(ownedWorkflowSource, ownedWorkflowText)
		const explanation = await runOwnedAdvanced({
			operation: "explain_behavior",
			target: ownedWorkflowSource,
			workflow_query: { symbol: "ownedWorkflow" },
			timeout_ms: 120000,
		})
		if (
			explanation.plan.status !== "completed" ||
			explanation.result.status !== "partial" ||
			explanation.result.observedExecution !== false ||
			explanation.result.selectedFunction?.sha256 !== createHash("sha256").update(ownedWorkflowText).digest("hex") ||
			!explanation.result.selectedFunction?.text.includes('return "owned evidence"') ||
			(await readFile(ownedWorkflowSource, "utf8")) !== ownedWorkflowText
		)
			throw new Error("Installed exact-function evidence failed or changed the original")
		const hypothesis = await runOwnedAdvanced({
			operation: "verify_hypothesis",
			target: witnessGraph,
			hypothesis: {
				statement: "Owned declared relationship only",
				kind: "declared-edge",
				node_id: "a",
				target_id: "b",
				relation: "references-candidate",
				expected: true,
			},
			timeout_ms: 120000,
		})
		if (
			hypothesis.plan.status !== "completed" ||
			hypothesis.result.status !== "completed" ||
			hypothesis.result.conclusion !== "supported"
		)
			throw new Error("Installed declared hypothesis verification failed")
		const ownedNotebook = join(workspace, "owned-workflow-notebook.json")
		await writeFile(
			ownedNotebook,
			JSON.stringify({
				schemaVersion: 1,
				title: "Owned preview",
				cells: [
					{ id: "triage", action: "triage", target: "owned-candidate-input.bin" },
					{ id: "inventory", action: "native_inventory", target: "owned-candidate-input.bin", dependsOn: ["triage"] },
				],
			}),
		)
		const notebookPreview = await runOwnedAdvanced({ operation: "preview_batch", target: ownedNotebook, timeout_ms: 120000 })
		if (
			notebookPreview.plan.status !== "completed" ||
			notebookPreview.result.status !== "completed" ||
			notebookPreview.result.executed !== false ||
			notebookPreview.result.stages?.length !== 2 ||
			notebookPreview.result.stages[1].dependsOn.join(",") !== "triage"
		)
			throw new Error("Installed static notebook preview failed")
		stages.push("installed-integrated-source-hypothesis-notebook-coverage-passed")
		const ownedApiAfter = join(workspace, "owned-workflow-after.ts")
		await writeFile(ownedApiAfter, 'export function ownedWorkflow(x: number): string { return "owned evidence"; }\n')
		const ownedApiComparison = await runOwnedAdvanced({
			operation: "compare_public_api",
			target: ownedWorkflowSource,
			compare_target: ownedApiAfter,
			timeout_ms: 120000,
		})
		if (
			ownedApiComparison.plan.status !== "completed" ||
			ownedApiComparison.result.comparison?.changed.join(",") !== "<entry>:ownedWorkflow"
		)
			throw new Error("Installed explicit API signature comparison failed")
		const ownedPackage = join(workspace, "owned-package.json"),
			ownedLock = join(workspace, "owned-package-lock.json"),
			ownedLockText = JSON.stringify({
				lockfileVersion: 3,
				packages: { "node_modules/owned-fixture": { version: "1.2.3" } },
			})
		await writeFile(ownedPackage, JSON.stringify({ dependencies: { "owned-fixture": "^1.0.0" } }))
		await writeFile(ownedLock, ownedLockText)
		const ownedDependencies = await runOwnedAdvanced({
			operation: "inspect_dependency_risk",
			target: ownedPackage,
			dependency_evidence: {
				lockfile: ownedLock,
				lockfile_sha256: createHash("sha256").update(ownedLockText).digest("hex"),
			},
			timeout_ms: 120000,
		})
		if (
			ownedDependencies.plan.status !== "completed" ||
			ownedDependencies.result.resolvedEvidence?.resolved[0]?.version !== "1.2.3"
		)
			throw new Error("Installed hash-bound lockfile resolution failed")
		stages.push("installed-explicit-api-signatures-lockfile-evidence-passed")
		const ownedArchiveManifest = join(workspace, "owned-evidence-manifest.json"),
			ownedArchiveOutput = join(workspace, "owned-evidence.json.gz"),
			ownedArchiveManifestText = JSON.stringify({
				schemaVersion: 1,
				title: "Owned installed evidence",
				entries: [
					{
						id: "source",
						path: "owned-workflow.ts",
						sha256: createHash("sha256").update(ownedWorkflowText).digest("hex"),
						kind: "finding",
						format: "text",
					},
				],
			})
		await writeFile(ownedArchiveManifest, ownedArchiveManifestText)
		const ownedArchive = await runOwnedAdvanced({
			operation: "export_evidence_bundle",
			target: ownedArchiveManifest,
			output_file: ownedArchiveOutput,
			evidence_archive: { manifest_sha256: createHash("sha256").update(ownedArchiveManifestText).digest("hex") },
			acknowledge_external_output: true,
			timeout_ms: 120000,
		})
		const ownedArchiveDocument = JSON.parse(gunzipSync(await readFile(ownedArchiveOutput)).toString("utf8"))
		if (
			ownedArchive.plan.status !== "completed" ||
			ownedArchive.result.published !== true ||
			ownedArchiveDocument.protocol !== "cline-evidence-archive/v1" ||
			ownedArchiveDocument.entries[0]?.sourceSha256 !== createHash("sha256").update(ownedWorkflowText).digest("hex") ||
			ownedArchiveDocument.entries[0]?.content !== ownedWorkflowText ||
			(await readFile(ownedWorkflowSource, "utf8")) !== ownedWorkflowText
		)
			throw new Error("Installed approved provenance archive failed")
		stages.push("installed-approved-provenance-archive-originals-preserved")

		const triageScope = { sessionId: triageSession.sessionId, environmentId: "local" }
		await rpc(page, "first_party_analysis_mode", { ...triageScope, mode: "static" })
		const batchRequest = {
			operation_id: randomUUID(),
			title: "Installed owned static DAG",
			parallel: 2,
			stages: [
				{ id: "inspect", request: { operation: "inspect", target: hybridFixtureTarget } },
				{
					id: "strings",
					depends_on: ["inspect"],
					request: { operation: "scan_strings", target: hybridFixtureTarget, max_results: 20 },
				},
			],
		}
		const staticBatchPreview = await rpc<{ status: string; request: { stages: Array<{ target_sha256: string }> } }>(
			page,
			"preview_batch",
			{ ...triageScope, input: batchRequest },
		)
		if (
			staticBatchPreview.status !== "previewed-not-approved" ||
			staticBatchPreview.request.stages.some((s) => !/^[a-f0-9]{64}$/.test(s.target_sha256))
		)
			throw new Error("Installed batch preview omitted input fingerprints")
		const batchPlan = await rpc<{ id: string; requirements: string[]; requestHash: string }>(page, "run_batch", {
			...triageScope,
			input: { ...batchRequest, phase: "prepare" },
		})
		const batchApproval = await rpc<{ executionToken: string }>(page, "approve_analysis_task", {
			...triageScope,
			cwd: workspace,
			planId: batchPlan.id,
			requestHash: batchPlan.requestHash,
			requirements: batchPlan.requirements,
		})
		const batchStarted = await rpc<{ id: string; accepted: boolean; completed: boolean }>(page, "run_batch", {
			...triageScope,
			input: { ...batchRequest, phase: "run", planId: batchPlan.id, executionToken: batchApproval.executionToken },
		})
		if (!batchStarted.accepted || batchStarted.completed)
			throw new Error("Installed batch start claimed completion prematurely")
		type InstalledBatchCheckpoint = {
			receipt: { status: string; revision: number; hash: string; jobs: Array<{ status: string; result?: unknown }> }
		}
		let batchCheckpoint: InstalledBatchCheckpoint | undefined
		for (let attempt = 0; attempt < 100; attempt++) {
			batchCheckpoint = await rpc<InstalledBatchCheckpoint>(page, "checkpoint_investigation", {
				...triageScope,
				input: { receiptId: batchStarted.id },
			})
			if (!["accepted", "starting", "running"].includes(batchCheckpoint.receipt.status)) break
			await delay(100)
		}
		if (
			batchCheckpoint?.receipt.status !== "completed" ||
			batchCheckpoint.receipt.jobs.some((j) => j.status !== "completed") ||
			!/^[a-f0-9]{64}$/.test(batchCheckpoint.receipt.hash) ||
			!JSON.stringify(batchCheckpoint.receipt.jobs[1].result).includes("process.stdout.write")
		)
			throw new Error("Installed durable batch DAG results failed")
		let batchReplayDenied = false
		try {
			await rpc(page, "resume_investigation", {
				...triageScope,
				input: { receiptId: batchStarted.id, revision: batchCheckpoint.receipt.revision },
			})
		} catch {
			batchReplayDenied = true
		}
		if (!batchReplayDenied) throw new Error("Installed completed batch was replayed")
		const batchCancelled = await rpc<InstalledBatchCheckpoint>(page, "cancel_batch", {
			...triageScope,
			input: { receiptId: batchStarted.id },
		})
		if (batchCancelled.receipt.revision !== batchCheckpoint.receipt.revision)
			throw new Error("Installed terminal cancellation mutated completed evidence")
		stages.push("installed-ai-batch-preview-approved-dag-checkpoint-no-replay-passed")
		const contractCatalog = await rpc<{
			contractVersion: string
			capabilities: Array<{
				command: string
				readiness: string
				implementationScope: string
				interfaces: Array<{ route: string; schemaRef: string; parameters?: unknown }>
			}>
		}>(page, "analysis_command_catalog", { environmentId: "local" })
		const batchContract = contractCatalog.capabilities.find((c) => c.command === "run_batch")
		if (
			contractCatalog.contractVersion !== "analysis-capabilities/v1" ||
			batchContract?.interfaces.map((i) => i.route).join(",") !== "static-review,ai-workflow" ||
			!JSON.stringify(batchContract.interfaces.find((i) => i.route === "ai-workflow")?.parameters).includes(
				"evidence-graph",
			) ||
			workflowCatalog.recommendations.some(
				(r) =>
					!contractCatalog.capabilities.some(
						(c) => c.command === r.command && c.implementationScope === r.scope && c.readiness === "not-probed",
					),
			)
		)
			throw new Error("Installed command contracts lost original coverage, exact AI schemas or readiness distinction")
		const chainedManifest = join(workspace, "owned-chained-graph-manifest.json")
		const chainedManifestBytes = JSON.stringify({
			schemaVersion: 1,
			results: [
				{
					protocol: "cline-advanced-analysis/v1",
					status: "completed",
					engine: "owned-installed-graph",
					engineVersion: "1",
					evidence: {},
					limitations: ["Owned report, not target compatibility"],
				},
			],
		})
		await writeFile(chainedManifest, chainedManifestBytes)
		const chainedRequest = {
			operation_id: randomUUID(),
			title: "Installed typed graph output chain",
			parallel: 1,
			stages: [
				{
					id: "build",
					request: { operation: "advanced_analysis", advanced_action: "graph_build", target: chainedManifest },
				},
				{
					id: "query",
					depends_on: ["build"],
					request: {
						operation: "advanced_analysis",
						advanced_action: "graph_query",
						target: { stage_id: "build", output: "evidence-graph" },
					},
				},
			],
		}
		const chainedPlan = await rpc<{ id: string; requirements: string[]; requestHash: string }>(page, "run_batch", {
			...triageScope,
			input: chainedRequest,
		})
		const chainedApproval = await rpc<{ executionToken: string }>(page, "approve_analysis_task", {
			...triageScope,
			cwd: workspace,
			planId: chainedPlan.id,
			requestHash: chainedPlan.requestHash,
			requirements: chainedPlan.requirements,
		})
		const chainedStarted = await rpc<{ id: string }>(page, "run_batch", {
			...triageScope,
			input: { ...chainedRequest, phase: "run", planId: chainedPlan.id, executionToken: chainedApproval.executionToken },
		})
		type ChainedCheckpoint = {
			receipt: {
				status: string
				jobs: Array<{
					status: string
					result?: unknown
					resultHash?: string
					inputReport?: {
						producerReceiptId: string
						producerStageId: string
						producerResultSha256: string
						documentSha256: string
					}
				}>
			}
		}
		let chainedCheckpoint: ChainedCheckpoint | undefined
		for (let attempt = 0; attempt < 100; attempt++) {
			chainedCheckpoint = await rpc<ChainedCheckpoint>(page, "checkpoint_investigation", {
				...triageScope,
				input: { receiptId: chainedStarted.id },
			})
			if (!["accepted", "starting", "running"].includes(chainedCheckpoint.receipt.status)) break
			await delay(100)
		}
		const chainedJobs = chainedCheckpoint?.receipt.jobs
		if (
			chainedCheckpoint?.receipt.status !== "completed" ||
			chainedJobs?.length !== 2 ||
			chainedJobs.some((j) => j.status !== "completed") ||
			chainedJobs[1].inputReport?.producerReceiptId !== chainedStarted.id ||
			chainedJobs[1].inputReport?.producerStageId !== "build" ||
			chainedJobs[1].inputReport?.producerResultSha256 !== chainedJobs[0].resultHash ||
			!/^[a-f0-9]{64}$/.test(chainedJobs[1].inputReport?.documentSha256 ?? "") ||
			!JSON.stringify(chainedJobs[1].result).includes("owned-installed-graph") ||
			(await readFile(chainedManifest, "utf8")) !== chainedManifestBytes
		)
			throw new Error("Installed typed graph chain lost provenance, result evidence or preserved input")
		stages.push("installed-shared-command-contract-typed-graph-output-chain-passed")
		const objectivePlan = await runOwnedAdvanced({
			operation: "plan_investigation",
			target: ownedWorkflowSource,
			compare_target: ownedApiAfter,
			investigation_plan: {
				workflow: "electron",
				goal: "Owned explicit source evidence",
				objectives: ["inventory", "exact-function", "compare"],
				symbol: "ownedWorkflow",
			},
			timeout_ms: 120000,
		})
		if (
			objectivePlan.result.executed !== false ||
			objectivePlan.result.batchDraft?.stages.length !== 3 ||
			objectivePlan.result.enginePreflight?.startsWith("not-run") !== true ||
			objectivePlan.result.batchDraft.stages.some((s) => s.request.script_path || s.request.output_file)
		)
			throw new Error("Installed structured batch draft fabricated execution or unsafe stages")
		const ownedBatchCfg = join(workspace, "owned-batch-cfg.json")
		await writeFile(ownedBatchCfg, JSON.stringify({ schemaVersion: 1, entry: "a", blocks: [{ id: "a", successors: [] }] }))
		const expandedBatch = {
			operation_id: randomUUID(),
			title: "Installed source partial and independent reads",
			parallel: 1,
			stages: [
				{
					id: "source",
					request: {
						operation: "explain_behavior",
						target: ownedWorkflowSource,
						workflow_query: { symbol: "ownedWorkflow" },
					},
				},
				{
					id: "blocked-dependent",
					depends_on: ["source"],
					request: { operation: "inspect", target: ownedWorkflowSource },
				},
				{
					id: "independent",
					request: { operation: "compare_public_api", target: ownedWorkflowSource, compare_target: ownedApiAfter },
				},
				{ id: "cfg", request: { operation: "advanced_analysis", advanced_action: "cfg_analyze", target: ownedBatchCfg } },
				{ id: "inventory", request: { operation: "inspect", target: ownedWorkflowSource } },
			],
		}
		const expandedPlan = await rpc<{ id: string; requirements: string[]; requestHash: string }>(page, "run_batch", {
			...triageScope,
			input: expandedBatch,
		})
		const expandedApproval = await rpc<{ executionToken: string }>(page, "approve_analysis_task", {
			...triageScope,
			cwd: workspace,
			planId: expandedPlan.id,
			requestHash: expandedPlan.requestHash,
			requirements: expandedPlan.requirements,
		})
		const expandedStarted = await rpc<{ id: string }>(page, "run_batch", {
			...triageScope,
			input: { ...expandedBatch, phase: "run", planId: expandedPlan.id, executionToken: expandedApproval.executionToken },
		})
		let expandedCheckpoint: InstalledBatchCheckpoint | undefined
		for (let attempt = 0; attempt < 100; attempt++) {
			expandedCheckpoint = await rpc<InstalledBatchCheckpoint>(page, "checkpoint_investigation", {
				...triageScope,
				input: { receiptId: expandedStarted.id },
			})
			if (!["accepted", "starting", "running"].includes(expandedCheckpoint.receipt.status)) break
			await delay(100)
		}
		if (
			expandedCheckpoint?.receipt.status !== "partial" ||
			expandedCheckpoint.receipt.jobs.map((j) => j.status).join(",") !== "partial,cancelled,partial,partial,completed" ||
			!(expandedCheckpoint.receipt.jobs[0].result as any)?.selectedFunction?.text.includes('return "owned evidence"') ||
			(await readFile(ownedWorkflowSource, "utf8")) !== ownedWorkflowText
		)
			throw new Error("Installed partial evidence unlocked dependent work, lost independent reads, or changed the input")
		let expandedResumeDenied = false
		try {
			await rpc(page, "resume_investigation", {
				...triageScope,
				input: { receiptId: expandedStarted.id, revision: expandedCheckpoint.receipt.revision },
			})
		} catch {
			expandedResumeDenied = true
		}
		if (!expandedResumeDenied) throw new Error("Installed partial dependency replayed")
		stages.push("installed-structured-batch-draft-partial-independent-reads-passed")
		const freshFlowTarget = join(workspace, "owned-fresh-source-flow.ts"),
			freshFlowSource = 'const url = "https://example.invalid/owned";\nfetch(url);\n'
		await writeFile(freshFlowTarget, freshFlowSource)
		const freshFlow = await runOwnedAdvanced({
			operation: "trace_data_flow",
			target: freshFlowTarget,
			source_flow: {
				kind: "js-ts",
				start: { path: "owned-fresh-source-flow.ts", line: 1, column: 7, kind: "configuration" },
				end: { path: "owned-fresh-source-flow.ts", line: 2, column: 1, kind: "resolved-endpoint" },
			},
			timeout_ms: 120000,
		})
		if (
			freshFlow.plan.status !== "completed" ||
			freshFlow.result.status !== "partial" ||
			freshFlow.result.mode !== "fresh-js-ts-constant-endpoint-flow" ||
			freshFlow.result.observedExecution !== false ||
			freshFlow.result.endpointReachableInSelectedGraph !== true ||
			freshFlow.result.edges?.length !== 1 ||
			(await readFile(freshFlowTarget, "utf8")) !== freshFlowSource
		)
			throw new Error("Installed fresh source flow did not preserve exact bounded static evidence")
		stages.push("installed-fresh-source-flow-exact-locations-no-execution-passed")

		// Preparation is deliberately offline: no ADB/device execution or physical-hardware claim.
		const smokeArtifact = await rpc<{ id: string }>(page, "open_binary", {
			...triageScope,
			input: { target: join(workspace, "owned-project-candidate.apk") },
		})
		const smokeInput = {
			action: "start",
			artifactId: smokeArtifact.id,
			deviceSerial: "owned-offline-no-device",
			packageName: "com.cline.owned",
			durationSeconds: 2,
			purpose: "Installed approval routing only, never execute device work",
		}
		let staticSmokeDenied = false
		try {
			await rpc(page, "run_device_smoke_test", { ...triageScope, input: smokeInput })
		} catch {
			staticSmokeDenied = true
		}
		if (!staticSmokeDenied) throw new Error("Installed Static mode allowed device launch preparation")
		await rpc(page, "first_party_analysis_mode", { ...triageScope, mode: "runtime" })
		const smokePlan = await rpc<{
			id: string
			permission: string
			requirements: string[]
			request: { target_sha256: string; owner_session_id: string }
		}>(page, "run_device_smoke_test", { ...triageScope, input: smokeInput })
		if (
			smokePlan.permission !== "Execute" ||
			!smokePlan.requirements.includes("app-may-remain-running-no-automatic-force-stop") ||
			smokePlan.request.owner_session_id !== triageSession.sessionId ||
			smokePlan.request.target_sha256 !==
				createHash("sha256")
					.update(await readFile(join(workspace, "owned-project-candidate.apk")))
					.digest("hex")
		)
			throw new Error("Installed device smoke plan lost exact identity or independent Execute requirements")
		let unapprovedSmokeDenied = false
		try {
			await rpc(page, "run_device_smoke_test", {
				...triageScope,
				input: { ...smokeInput, phase: "run", planId: smokePlan.id },
			})
		} catch {
			unapprovedSmokeDenied = true
		}
		if (!unapprovedSmokeDenied) throw new Error("Installed device smoke ran without independent approval")
		let foreignSmokeDenied = false
		try {
			await rpc(page, "run_device_smoke_test", { ...analysisArgs, input: { action: "status", taskId: smokePlan.id } })
		} catch {
			foreignSmokeDenied = true
		}
		if (!foreignSmokeDenied) throw new Error("Installed device smoke status crossed owning sessions")
		await rpc(page, "first_party_analysis_mode", { ...triageScope, mode: "off" })
		const smokeCancelled = await rpc<{ taskStatus: string; cleanupConfirmed: boolean }>(page, "run_device_smoke_test", {
			...triageScope,
			input: { action: "cancel", taskId: smokePlan.id },
		})
		const smokeStatus = await rpc<{ taskStatus: string; observationStatus: string }>(page, "run_device_smoke_test", {
			...triageScope,
			input: { action: "status", taskId: smokePlan.id },
		})
		if (
			smokeCancelled.taskStatus !== "cancelled" ||
			!smokeCancelled.cleanupConfirmed ||
			smokeStatus.taskStatus !== "cancelled" ||
			smokeStatus.observationStatus !== "not-started"
		)
			throw new Error("Installed device smoke cleanup/status replayed work or failed after Off")
		stages.push("installed-device-smoke-exact-plan-static-denial-off-cleanup-no-hardware-passed")
		await rpc(page, "first_party_analysis_mode", { ...triageScope, mode: "static" })
		// Offline approval contract only. A workflow cannot attest to its own unfinished CI.
		const releaseInput = { action: "check", pullNumber: 133, expectedHead: "a".repeat(40) }
		const releasePlan = await rpc<{
			id: string
			permission: string
			requirements: string[]
			budget: { network: string }
			request: { owner_session_id: string; expectedHead: string }
		}>(page, "check_release_gate", { ...triageScope, input: releaseInput })
		if (
			releasePlan.permission !== "Inspect" ||
			releasePlan.budget.network !== "recorded" ||
			!releasePlan.requirements.includes("public-github-exact-head-read-only-evidence") ||
			releasePlan.request.owner_session_id !== triageSession.sessionId ||
			releasePlan.request.expectedHead !== releaseInput.expectedHead
		)
			throw new Error("Installed release verification omitted exact-head independent Inspect/network scope")
		let unapprovedReleaseDenied = false
		try {
			await rpc(page, "check_release_gate", {
				...triageScope,
				input: { ...releaseInput, phase: "run", planId: releasePlan.id },
			})
		} catch {
			unapprovedReleaseDenied = true
		}
		if (!unapprovedReleaseDenied) throw new Error("Installed release verification started network work without approval")
		let foreignReleaseDenied = false
		try {
			await rpc(page, "check_release_gate", { ...analysisArgs, input: { action: "cancel", taskId: releasePlan.id } })
		} catch {
			foreignReleaseDenied = true
		}
		if (!foreignReleaseDenied) throw new Error("Installed release verification cleanup crossed owning sessions")
		let releasePolicyInjectionDenied = false
		try {
			await rpc(page, "check_release_gate", {
				...triageScope,
				input: { ...releaseInput, policy: "accept-anything", url: "https://invalid.example" },
			})
		} catch {
			releasePolicyInjectionDenied = true
		}
		if (!releasePolicyInjectionDenied)
			throw new Error("Installed release verification accepted model policy or endpoint authority")
		await rpc(page, "first_party_analysis_mode", { ...triageScope, mode: "off" })
		const releaseCancelled = await rpc<{ status: string }>(page, "check_release_gate", {
			...triageScope,
			input: { action: "cancel", taskId: releasePlan.id },
		})
		if (releaseCancelled.status !== "cancelled")
			throw new Error("Installed release verification failed owning cleanup after Off")
		let offReleaseDenied = false
		try {
			await rpc(page, "check_release_gate", { ...triageScope, input: releaseInput })
		} catch {
			offReleaseDenied = true
		}
		if (!offReleaseDenied) throw new Error("Installed Off mode allowed new release verification")
		stages.push("installed-release-gate-exact-head-inspect-off-cleanup-no-network-passed")
		await rpc(page, "first_party_analysis_mode", { ...triageScope, mode: "static" })

		const candidateValidationHandle = await rpc<{ id: string }>(page, "open_binary", {
			...triageScope,
			input: { target: ownedWorkflowSource },
		})
		const candidateReviewHandle = await rpc<{ id: string }>(page, "open_binary", {
			...triageScope,
			input: { target: batchManifest },
		})
		for (const [command, input] of [
			["validate_candidate", { artifactId: candidateValidationHandle.id, kind: "typescript" }],
			["review_candidate_changes", { artifactId: candidateReviewHandle.id }],
		] as const) {
			const plan = await rpc<{ id: string; requirements: string[]; requestHash: string }>(page, command, {
				...triageScope,
				input: { ...input, phase: "prepare" },
			})
			const approval = await rpc<{ executionToken: string }>(page, "approve_analysis_task", {
				...triageScope,
				cwd: workspace,
				planId: plan.id,
				requestHash: plan.requestHash,
				requirements: plan.requirements,
			})
			const result = await rpc<{
				plan: { status: string; candidateOutcome?: { evidence: string; receiptSha256: string } }
				result: { protocol: string; status: string; receiptSha256: string; published: boolean }
			}>(page, command, {
				...triageScope,
				input: { ...input, phase: "run", planId: plan.id, executionToken: approval.executionToken },
			})
			if (
				result.result.protocol !== "cline-candidate-verification/v1" ||
				result.result.status !== "completed" ||
				result.result.published !== false ||
				!/^[a-f0-9]{64}$/.test(result.result.receiptSha256)
			)
				throw new Error("Installed hash-bound candidate verification failed")
			if (
				result.plan.status !== "completed" ||
				result.plan.candidateOutcome?.evidence !== "bounded-checks-passed" ||
				result.plan.candidateOutcome.receiptSha256 !== result.result.receiptSha256
			)
				throw new Error("Installed candidate summary lost bounded check identity")
			let denied = false
			try {
				await rpc(page, command, { ...analysisArgs, input: { ...input, phase: "prepare" } })
			} catch {
				denied = true
			}
			if (!denied) throw new Error("Installed candidate handle crossed session boundary")
		}
		if (
			(await readFile(ownedWorkflowSource, "utf8")) !== ownedWorkflowText ||
			!(await readFile(batchBinary)).equals(batchBinaryBefore) ||
			(await readFile(batchAst, "utf8")) !== batchAstBefore
		)
			throw new Error("Installed candidate verification changed originals")
		stages.push("installed-candidate-validation-review-hash-scope-preservation-passed")
		// Syntax failure is retained evidence, never successful completion or build/device proof.
		const failedCandidatePath = join(workspace, "owned-invalid-candidate.ts"),
			failedCandidateText = "export const = ;"
		await writeFile(failedCandidatePath, failedCandidateText)
		const failedCandidateHandle = await rpc<{ id: string }>(page, "open_binary", {
			...triageScope,
			input: { target: failedCandidatePath },
		})
		const failedCandidateInput = { artifactId: failedCandidateHandle.id, kind: "typescript" }
		const failedCandidatePlan = await rpc<{ id: string; requirements: string[]; requestHash: string }>(
			page,
			"validate_candidate",
			{ ...triageScope, input: failedCandidateInput },
		)
		const failedCandidateApproval = await rpc<{ executionToken: string }>(page, "approve_analysis_task", {
			...triageScope,
			cwd: workspace,
			planId: failedCandidatePlan.id,
			requestHash: failedCandidatePlan.requestHash,
			requirements: failedCandidatePlan.requirements,
		})
		const failedCandidate = await rpc<{
			plan: {
				status: string
				candidateOutcome?: { evidence: string; inputSha256: string; receiptSha256: string }
				evidence?: { resultHash: string; outputPaths: string[] }
			}
			result: { status: string; receiptSha256: string }
		}>(page, "validate_candidate", {
			...triageScope,
			input: {
				...failedCandidateInput,
				phase: "run",
				planId: failedCandidatePlan.id,
				executionToken: failedCandidateApproval.executionToken,
			},
		})
		if (
			failedCandidate.plan.status !== "failed" ||
			failedCandidate.result.status !== "failed" ||
			failedCandidate.plan.candidateOutcome?.evidence !== "failed" ||
			failedCandidate.plan.candidateOutcome.receiptSha256 !== failedCandidate.result.receiptSha256 ||
			failedCandidate.plan.candidateOutcome.inputSha256 !==
				createHash("sha256").update(failedCandidateText).digest("hex") ||
			!/^[a-f0-9]{64}$/.test(failedCandidate.plan.evidence?.resultHash ?? "") ||
			failedCandidate.plan.evidence?.outputPaths.length !== 0
		)
			throw new Error("Installed failed candidate lost exact retained evidence or became a success")
		const retainedCandidates = await rpc<Array<{ id: string; status: string; candidateOutcome?: { evidence: string } }>>(
			page,
			"list_analysis_tasks",
			{ ...triageScope, cwd: workspace },
		)
		if (
			!retainedCandidates.some(
				(task) =>
					task.id === failedCandidatePlan.id &&
					task.status === "failed" &&
					task.candidateOutcome?.evidence === "failed",
			)
		)
			throw new Error("Installed failed candidate missing from task ledger")
		const failedCandidateExport = await rpc<{ outputPath: string }>(page, "export_analysis_evidence", {
			...triageScope,
			cwd: workspace,
			planId: failedCandidatePlan.id,
		})
		const failedCandidateBundle = JSON.parse(await readFile(failedCandidateExport.outputPath, "utf8"))
		if (
			failedCandidateBundle.payload?.task?.status !== "failed" ||
			failedCandidateBundle.payload?.task?.candidateOutcome?.evidence !== "failed" ||
			(await readFile(failedCandidatePath, "utf8")) !== failedCandidateText
		)
			throw new Error("Installed failed evidence export changed status or original")
		let failedCandidateReplayDenied = false
		try {
			await rpc(page, "validate_candidate", {
				...triageScope,
				input: {
					...failedCandidateInput,
					phase: "run",
					planId: failedCandidatePlan.id,
					executionToken: failedCandidateApproval.executionToken,
				},
			})
		} catch {
			failedCandidateReplayDenied = true
		}
		if (!failedCandidateReplayDenied) throw new Error("Installed failed candidate replayed consumed approval")
		stages.push("installed-candidate-outcomes-failed-retention-explicit-export-no-replay-passed")
		const projectBeforeFiles = { "main.ts": "export const value=1;", "removed.txt": "remove", ".owned-config": "EMPTY" },
			projectAfterFiles = { "main.ts": "export const value=2;", "added.txt": "add", ".owned-config": "EMPTY" }
		for (const [directory, files] of [
			["owned-project-before", projectBeforeFiles],
			["owned-project-after", projectAfterFiles],
		] as const) {
			await mkdir(join(workspace, directory), { recursive: true })
			for (const [name, text] of Object.entries(files)) await writeFile(join(workspace, directory, name), text)
		}
		const projectInventory = (files: Record<string, string>) =>
			createHash("sha256")
				.update(
					JSON.stringify({
						protocol: "cline-project-inventory/v1",
						files: Object.entries(files)
							.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
							.map(([path, text]) => ({
								path,
								bytes: Buffer.byteLength(text),
								sha256: createHash("sha256").update(text).digest("hex"),
							})),
					}),
				)
				.digest("hex")
		const projectHash = (text: string) => createHash("sha256").update(text).digest("hex")
		const projectManifest = {
			protocol: "cline-project-review/v1",
			baseline: { directory: "owned-project-before", inventory_sha256: projectInventory(projectBeforeFiles) },
			candidate: { directory: "owned-project-after", inventory_sha256: projectInventory(projectAfterFiles) },
			approved_changes: [
				{
					path: "main.ts",
					before_sha256: projectHash(projectBeforeFiles["main.ts"]),
					after_sha256: projectHash(projectAfterFiles["main.ts"]),
				},
				{ path: "removed.txt", before_sha256: projectHash("remove"), after_sha256: null },
				{ path: "added.txt", before_sha256: null, after_sha256: projectHash("add") },
			],
		}
		const runProjectReview = async (
			name: string,
			manifest: unknown,
			scope: "project-files" | "project-inventory" = "project-files",
		) => {
			const target = join(workspace, name)
			await writeFile(target, JSON.stringify(manifest))
			const handle = await rpc<{ id: string }>(page, "open_binary", { ...triageScope, input: { target } })
			const input = { artifactId: handle.id, scope }
			const plan = await rpc<{ id: string; requestHash: string; requirements: string[]; permission: string }>(
				page,
				"review_candidate_changes",
				{ ...triageScope, input },
			)
			if (
				plan.permission !== "Inspect" ||
				!plan.requirements.includes("all-regular-files-in-disjoint-manifest-child-roots-no-ignore-rules")
			)
				throw new Error("Installed project review hid full file-read scope")
			const approval = await rpc<{ executionToken: string }>(page, "approve_analysis_task", {
				...triageScope,
				cwd: workspace,
				planId: plan.id,
				requestHash: plan.requestHash,
				requirements: plan.requirements,
			})
			return rpc<{
				result: {
					status: string
					checks: Array<{ id: string; changedFiles: number; unexpectedChanges: number; passes: number }>
					published: boolean
				}
			}>(page, "review_candidate_changes", {
				...triageScope,
				input: { ...input, phase: "run", planId: plan.id, executionToken: approval.executionToken },
			})
		}
		const projectDraft = await runProjectReview(
			"owned-project-inventory.json",
			{
				protocol: "cline-project-inventory-request/v1",
				baseline_directory: "owned-project-before",
				candidate_directory: "owned-project-after",
			},
			"project-inventory",
		)
		if (
			projectDraft.result.status !== "partial" ||
			projectDraft.result.published ||
			projectDraft.result.checks[0]?.id !== "full-project-file-inventory-draft" ||
			projectDraft.result.checks[0].changedFiles !== 3
		)
			throw new Error("Installed inventory draft claimed approval or omitted actual changes")
		const projectReviewed = await runProjectReview("owned-project-review.json", projectManifest)
		if (
			projectReviewed.result.status !== "completed" ||
			projectReviewed.result.published ||
			projectReviewed.result.checks[0]?.id !== "full-project-file-scope" ||
			projectReviewed.result.checks[0].changedFiles !== 3 ||
			projectReviewed.result.checks[0].unexpectedChanges !== 0 ||
			projectReviewed.result.checks[0].passes !== 2
		)
			throw new Error("Installed exact full project-file review failed")
		await writeFile(join(workspace, "owned-project-after", "unexpected.ts"), "export const unexpected=true;")
		const projectRejected = await runProjectReview("owned-project-review-denied.json", {
			...projectManifest,
			candidate: {
				...projectManifest.candidate,
				inventory_sha256: projectInventory({ ...projectAfterFiles, "unexpected.ts": "export const unexpected=true;" }),
			},
		})
		if (
			projectRejected.result.status !== "failed" ||
			projectRejected.result.checks[0]?.unexpectedChanges !== 1 ||
			(await readFile(join(workspace, "owned-project-before", "main.ts"), "utf8")) !== projectBeforeFiles["main.ts"]
		)
			throw new Error("Installed undeclared project change passed or original changed")
		stages.push("installed-project-file-inventories-approved-scope-undeclared-change-denial-passed")

		// Test harness owns this paused Node child. The product planner must not connect or resume it.
		const runtimePlanSource = join(workspace, "owned-runtime-plan.js"),
			runtimePlanMarker = join(workspace, "runtime-plan-MUST-NOT-EXECUTE")
		const runtimePlanText = 'require("node:fs").writeFileSync(' + JSON.stringify(runtimePlanMarker) + ',"executed");'
		await writeFile(runtimePlanSource, runtimePlanText)
		const runtimePlanChild = startAcceptanceProcess(
			process.execPath,
			["--inspect-brk=127.0.0.1:0", runtimePlanSource],
			workspace,
			process.env,
		)
		try {
			let runtimePlanEndpoint: string | undefined
			for (let attempt = 0; attempt < 200; attempt++) {
				runtimePlanEndpoint = /ws:\/\/127\.0\.0\.1:\d+\/[a-f0-9-]+/.exec(runtimePlanChild.diagnostics.stderrTail)?.[0]
				if (runtimePlanEndpoint) break
				await delay(50)
			}
			if (!runtimePlanEndpoint || !runtimePlanChild.child.pid)
				throw new Error("Owned runtime planner fixture did not start paused")
			// Reuse the installed host's exact OS birth-identity binder, without approving/consuming its runtime plan.
			await rpc(page, "first_party_analysis_mode", { ...triageScope, mode: "runtime" })
			const identityPlan = await rpc<{ id: string; request: { processToken: string } }>(
				page,
				"first_party_analysis_inspector_prepare",
				{
					...triageScope,
					input: {
						operation: "js_inspector_observe",
						target: runtimePlanSource,
						pid: runtimePlanChild.child.pid,
						endpoint: runtimePlanEndpoint,
						durationMs: 300,
					},
				},
			)
			await rpc(page, "cancel_analysis_task", { ...triageScope, cwd: workspace, planId: identityPlan.id })
			await rpc(page, "first_party_analysis_mode", { ...triageScope, mode: "static" })
			const sourceHandle = await rpc<{ id: string }>(page, "open_binary", {
				...triageScope,
				input: { target: runtimePlanSource },
			})
			const planInput = {
				artifactId: sourceHandle.id,
				observation: {
					backend: "node-inspector",
					pid: runtimePlanChild.child.pid,
					processToken: identityPlan.request.processToken,
					endpoint: runtimePlanEndpoint,
					durationMs: 300,
					captureConsole: false,
				},
			}
			const plan = await rpc<{ id: string; requirements: string[]; requestHash: string }>(
				page,
				"plan_runtime_observation",
				{ ...triageScope, input: { ...planInput, phase: "prepare" } },
			)
			const approval = await rpc<{ executionToken: string }>(page, "approve_analysis_task", {
				...triageScope,
				cwd: workspace,
				planId: plan.id,
				requestHash: plan.requestHash,
				requirements: plan.requirements,
			})
			const planned = await rpc<{
				result: {
					protocol: string
					status: string
					attached: boolean
					observedExecution: boolean
					approval: { granted: boolean }
					receiptSha256: string
				}
			}>(page, "plan_runtime_observation", {
				...triageScope,
				input: { ...planInput, phase: "run", planId: plan.id, executionToken: approval.executionToken },
			})
			if (
				planned.result.protocol !== "cline-runtime-observation-plan/v1" ||
				planned.result.status !== "completed" ||
				planned.result.attached !== false ||
				planned.result.observedExecution !== false ||
				planned.result.approval.granted !== false ||
				!/^[a-f0-9]{64}$/.test(planned.result.receiptSha256) ||
				runtimePlanChild.diagnostics.stderrTail.includes("Debugger attached") ||
				(await readFile(runtimePlanSource, "utf8")) !== runtimePlanText
			)
				throw new Error("Installed runtime planner attached, changed source or granted consent")
			let markerCreated = true
			try {
				await readFile(runtimePlanMarker)
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
				markerCreated = false
			}
			if (markerCreated) throw new Error("Runtime planner executed owned target")
			let crossScopeDenied = false
			try {
				await rpc(page, "plan_runtime_observation", { ...analysisArgs, input: { ...planInput, phase: "prepare" } })
			} catch {
				crossScopeDenied = true
			}
			if (!crossScopeDenied) throw new Error("Runtime plan artifact handle crossed sessions")
			stages.push("installed-runtime-plan-owned-identity-no-attach-no-execute-passed")
			let staticCaptureDenied = false
			try {
				await rpc(page, "capture_process_tree", {
					...triageScope,
					input: { artifactId: sourceHandle.id, pid: runtimePlanChild.child.pid, phase: "prepare" },
				})
			} catch {
				staticCaptureDenied = true
			}
			if (!staticCaptureDenied) throw new Error("Static enabled runtime metadata capture")
			await rpc(page, "first_party_analysis_mode", { ...triageScope, mode: "runtime" })
			const captureInputs = [
				["capture_process_tree", { artifactId: sourceHandle.id, pid: runtimePlanChild.child.pid, maxProcesses: 4 }],
				["capture_file_activity", { artifactId: sourceHandle.id, durationMs: 200, maxEvents: 4 }],
			] as const
			for (const [command, input] of captureInputs) {
				const capturePlan = await rpc<{ id: string; requirements: string[]; requestHash: string }>(page, command, {
					...triageScope,
					input: { ...input, phase: "prepare" },
				})
				if (!capturePlan.requirements.includes("independent-runtime-metadata-approval"))
					throw new Error("Runtime capture missing independent approval requirement")
				const consent = await rpc<{ executionToken: string }>(page, "approve_analysis_task", {
					...triageScope,
					cwd: workspace,
					planId: capturePlan.id,
					requestHash: capturePlan.requestHash,
					requirements: capturePlan.requirements,
				})
				const captured = await rpc<{
					result: {
						status: string
						provider: string
						processes?: { pid: number }[]
						events?: unknown[]
						stopReason?: string
					}
				}>(page, command, {
					...triageScope,
					input: { ...input, phase: "run", planId: capturePlan.id, executionToken: consent.executionToken },
				})
				if (captured.result.status !== "partial") throw new Error("Metadata capture overclaimed completeness")
				if (
					command === "capture_process_tree"
						? captured.result.processes?.[0]?.pid !== runtimePlanChild.child.pid ||
							captured.result.provider !== "windows-cim-process-metadata"
						: captured.result.provider !== "node-fs-watch-exact-file" || captured.result.stopReason !== "deadline"
				)
					throw new Error("Installed runtime metadata scope mismatch")
				let reused = false
				try {
					await rpc(page, command, {
						...triageScope,
						input: { ...input, phase: "run", planId: capturePlan.id, executionToken: consent.executionToken },
					})
				} catch {
					reused = true
				}
				if (!reused) throw new Error("Runtime approval replay succeeded")
			}
			if (
				runtimePlanChild.diagnostics.stderrTail.includes("Debugger attached") ||
				(await readFile(runtimePlanSource, "utf8")) !== runtimePlanText
			)
				throw new Error("Metadata capture attached or modified target")
			let captureExecutedTarget = true
			try {
				await readFile(runtimePlanMarker)
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
				captureExecutedTarget = false
			}
			if (captureExecutedTarget) throw new Error("Runtime metadata capture executed target")
			await rpc(page, "first_party_analysis_mode", { ...triageScope, mode: "static" })
			stages.push("installed-runtime-process-file-capture-approval-no-attach-passed")
		} finally {
			if (runtimePlanChild.child.exitCode === null && runtimePlanChild.child.signalCode === null)
				runtimePlanChild.child.kill()
			await withInstalledActionDeadline("runtime-plan-fixture-cleanup", () => runtimePlanChild.closed, 10000)
		}

		// Harness launches an explicitly running trusted fixture; the product never launches/resumes it.
		const managedSource = join(workspace, "owned-managed-runtime.js"),
			managedText =
				"function neverCalled(){ return 7; }\nsetInterval(()=>{let sum=0;for(let i=0;i<100000;i++)sum+=i;},5);\n"
		await writeFile(managedSource, managedText)
		const managedChild = startAcceptanceProcess(
			process.execPath,
			["--inspect=127.0.0.1:0", managedSource],
			workspace,
			process.env,
		)
		let managedSessionId: string | undefined
		try {
			let endpoint: string | undefined
			for (let attempt = 0; attempt < 200; attempt++) {
				endpoint = /ws:\/\/127\.0\.0\.1:\d+\/[a-f0-9-]+/.exec(managedChild.diagnostics.stderrTail)?.[0]
				if (endpoint) break
				await delay(50)
			}
			if (!endpoint || !managedChild.child.pid) throw new Error("Owned managed Inspector fixture unavailable")
			const handle = await rpc<{ id: string }>(page, "open_binary", { ...triageScope, input: { target: managedSource } })
			const attachInput = { artifactId: handle.id, pid: managedChild.child.pid, endpoint, lifetimeMs: 120000 }
			let denied = false
			try {
				await rpc(page, "attach_debug_session", { ...triageScope, input: { ...attachInput, phase: "prepare" } })
			} catch {
				denied = true
			}
			if (!denied) throw new Error("Static enabled managed debugger")
			await rpc(page, "first_party_analysis_mode", { ...triageScope, mode: "runtime" })
			let sampleTaskId: string | undefined
			const approvedManaged = async (command: string, input: Record<string, unknown>) => {
				const plan = await rpc<{ id: string; permission: string; requestHash: string; requirements: string[] }>(
					page,
					command,
					{ ...triageScope, input: { ...input, phase: "prepare" } },
				)
				if (
					plan.permission !== "Execute" ||
					!plan.requirements.includes("debugger-activation-cleanup-may-pause-or-resume")
				)
					throw new Error("Managed Inspector omitted Execute/debug-control approval")
				const approval = await rpc<{ executionToken: string }>(page, "approve_analysis_task", {
					...triageScope,
					cwd: workspace,
					planId: plan.id,
					requestHash: plan.requestHash,
					requirements: plan.requirements,
				})
				const result = await rpc<{
					evidenceWarning?: string
					result: { status: string; provider: string; runtimeSessionId?: string; activeBreakpoints?: number }
				}>(page, command, {
					...triageScope,
					input: { ...input, phase: "run", planId: plan.id, executionToken: approval.executionToken },
				})
				if (result.evidenceWarning)
					throw new Error("Managed runtime evidence persistence failed; do not replay observation")
				if (result.result.status !== "partial") throw new Error("Managed Inspector overclaimed coverage")
				let replayDenied = false
				try {
					await rpc(page, command, {
						...triageScope,
						input: { ...input, phase: "run", planId: plan.id, executionToken: approval.executionToken },
					})
				} catch {
					replayDenied = true
				}
				if (!replayDenied) throw new Error("Managed runtime approval replay succeeded")
				if (command === "capture_execution_trace") sampleTaskId = plan.id
				return result.result
			}
			managedSessionId = (await approvedManaged("attach_debug_session", attachInput)).runtimeSessionId
			if (!managedSessionId) throw new Error("Installed managed attachment missing session identity")
			let crossed = false
			try {
				await rpc(page, "stop_runtime_session", { ...analysisArgs, input: { runtimeSessionId: managedSessionId } })
			} catch {
				crossed = true
			}
			if (!crossed) throw new Error("Managed stop crossed owning sessions")
			const bp = await approvedManaged("set_scoped_breakpoints", {
				runtimeSessionId: managedSessionId,
				locations: [{ line: 0, column: 24 }],
			})
			if (bp.activeBreakpoints !== 1) throw new Error("Installed scoped breakpoint not registered")
			const sampled = await approvedManaged("capture_execution_trace", {
				runtimeSessionId: managedSessionId,
				durationMs: 200,
			})
			if (sampled.provider !== "v8-cpu-sampling-selected-script")
				throw new Error("Installed runtime trace did not declare sampling limitation")
			await rpc(page, "first_party_analysis_mode", { ...triageScope, mode: "off" })
			const stopped = await rpc<{ transportClosed: boolean; protocolCleanupConfirmed: boolean }>(
				page,
				"stop_runtime_session",
				{ ...triageScope, input: { runtimeSessionId: managedSessionId } },
			)
			if (!stopped.transportClosed || !stopped.protocolCleanupConfirmed)
				throw new Error("Installed managed transport/profiler cleanup unconfirmed")
			if ((await readFile(managedSource, "utf8")) !== managedText || managedChild.child.exitCode !== null)
				throw new Error("Managed debugger changed source or killed owned process")
			stages.push("installed-managed-node-approval-breakpoint-sampling-stop-cleanup-passed")
			await rpc(page, "first_party_analysis_mode", { ...triageScope, mode: "static" })
			const staticManaged = await rpc<{ id: string }>(page, "first_party_analysis_run", {
				...triageScope,
				input: { target: managedSource },
			})
			if (!sampleTaskId) throw new Error("Managed sample task receipt missing")
			await rpc(page, "first_party_analysis_mode", { ...triageScope, mode: "off" })
			const correlated = await rpc<{
				protocol: string
				effect: string
				verifiedBehavior: boolean
				sampling: Array<{ sourceIdentity: string; verifiedExecutionPath: boolean }>
			}>(page, "correlate_static_runtime", {
				...triageScope,
				input: { receiptId: staticManaged.id, taskIds: [sampleTaskId] },
			})
			if (
				correlated.protocol !== "cline-static-runtime-correlation/v1" ||
				correlated.effect !== "saved-evidence-read" ||
				correlated.verifiedBehavior !== false ||
				correlated.sampling.length !== 1 ||
				correlated.sampling[0].sourceIdentity !== "exact-byte-match" ||
				correlated.sampling[0].verifiedExecutionPath !== false
			)
				throw new Error("Installed saved correlation identity or limitation failed")
			let correlationCrossed = false
			try {
				await rpc(page, "correlate_static_runtime", {
					...analysisArgs,
					input: { receiptId: staticManaged.id, taskIds: [sampleTaskId] },
				})
			} catch {
				correlationCrossed = true
			}
			if (!correlationCrossed) throw new Error("Saved correlation crossed owning sessions")
			if (managedChild.child.exitCode !== null || (await readFile(managedSource, "utf8")) !== managedText)
				throw new Error("Saved correlation changed or killed owned target")
			stages.push("installed-saved-static-runtime-correlation-owner-hash-no-rerun-passed")
		} finally {
			if (managedSessionId)
				await rpc(page, "stop_runtime_session", { ...triageScope, input: { runtimeSessionId: managedSessionId } }).catch(
					() => {},
				)
			if (managedChild.child.exitCode === null && managedChild.child.signalCode === null) managedChild.child.kill()
			await withInstalledActionDeadline("managed-runtime-fixture-cleanup", () => managedChild.closed, 10000)
			await rpc(page, "first_party_analysis_mode", { ...triageScope, mode: "static" })
		}

		const triageRequestId = randomUUID()
		const triageReceipt = await rpc<{ id: string; status: string; resultHash: string; evidence: { data: unknown } }>(
			page,
			"binary_triage_run",
			{ ...triageScope, confirmed: true, requestId: triageRequestId, input: triageInput },
		)
		if (
			triageReceipt.status !== "completed" ||
			!JSON.stringify(triageReceipt.evidence.data).includes("cline_owned_fixture") ||
			!/^[a-f0-9]{64}$/.test(triageReceipt.resultHash)
		)
			throw new Error("Installed owned YARA target receipt failed")
		const report = await rpc<{ observed: { targetSha256: string }; receipt: { id: string } }>(page, "binary_triage_report", {
			...triageScope,
			id: triageReceipt.id,
		})
		if (report.receipt.id !== triageReceipt.id || !/^[a-f0-9]{64}$/.test(report.observed.targetSha256))
			throw new Error("Installed scoped triage report failed")
		let crossScopeDenied = false
		try {
			await rpc(page, "binary_triage_report", { ...analysisArgs, id: triageReceipt.id })
		} catch {
			crossScopeDenied = true
		}
		if (!crossScopeDenied) throw new Error("Installed report leaked across sessions")
		let replayDenied = false
		try {
			await rpc(page, "binary_triage_run", {
				...triageScope,
				confirmed: true,
				requestId: triageRequestId,
				input: triageInput,
			})
		} catch {
			replayDenied = true
		}
		if (!replayDenied) throw new Error("Installed analysis replay was not blocked")
		await writeFile(join(evidence, "binary-triage-owned-report.json"), JSON.stringify(report, null, 2))
		stages.push("installed-binary-triage-target-report-scope-and-replay-passed")

		page.once("dialog", async (dialog) => {
			if (dialog.message().includes("reviewed and accept")) await dialog.accept()
			else await dialog.dismiss()
		})
		await page
			.getByRole("button", {
				name: "Install all supported components",
				exact: true,
			})
			.click()
		await page
			.getByLabel("Full capability pack status", { exact: true })
			.filter({ hasText: /^Ready$/ })
			.waitFor({ timeout: 240000 })
		const full = await rpc<{
			fullStatus: string
			features: Array<{ id: string; status: string }>
			runtime: { runtimeId: string; integrity: string }
		}>(page, "setup_center_status", { environmentId: "local" })
		await writeFile(join(evidence, "full-capability-readiness.json"), JSON.stringify(full, null, 2))
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
		]
		if (
			full.fullStatus !== "Ready" ||
			full.runtime.integrity !== "verified" ||
			!full.runtime.runtimeId.includes("-full-") ||
			full.features.length !== 11 ||
			!required.every((id) => full.features.filter((f) => f.id === id && f.status === "Ready").length === 1)
		)
			throw new Error("Installed full pack did not execute all eleven owned engine fixtures")
		const setupJob = await rpc<{ job: { id: string; command: string; status: string } | null }>(
			page,
			"setup_center_job_status",
		)
		if (!setupJob.job?.id || setupJob.job.command !== "setup_center_install_full" || setupJob.job.status !== "completed")
			throw new Error("Installed full pack did not retain its completed background setup job")
		if (!(await page.getByLabel("Setup operation status", { exact: true }).textContent())?.includes(setupJob.job.id))
			throw new Error("Installed Setup Center did not show its tracked job beside the actions")
		stages.push("installed-tracked-full-setup-job-passed")
		stages.push("installed-full-eleven-engine-owned-fixtures-passed")
		const ownedDualDecoder = join(workspace, "owned-dual-decoder.bin"),
			ownedDualBytes = Buffer.from([0x31, 0xc0, 0x90, 0xc3])
		await writeFile(ownedDualDecoder, ownedDualBytes)
		const ownedCrosscheck = await runOwnedAdvanced({
			operation: "crosscheck_disassembly",
			target: ownedDualDecoder,
			advanced_options: { architecture: "x86_64", offset: 0, address: 4096, bytes: 4 },
			timeout_ms: 120000,
		})
		const ownedCrosscheckResult = ownedCrosscheck.result.result
		if (
			ownedCrosscheck.plan.status !== "completed" ||
			ownedCrosscheckResult?.status !== "completed" ||
			ownedCrosscheckResult.evidence.boundaryAgreement !== true ||
			ownedCrosscheckResult.evidence.rangeSha256 !== createHash("sha256").update(ownedDualBytes).digest("hex") ||
			ownedCrosscheckResult.evidence.decoders.map((d) => d.engine).join(",") !== "capstone,miasm" ||
			!ownedCrosscheckResult.evidence.decoders.every((d) => d.version && d.decodedBytes === 4) ||
			!(await readFile(ownedDualDecoder)).equals(ownedDualBytes)
		)
			throw new Error("Installed exact-range Capstone/Miasm evidence failed")
		stages.push("installed-full-pack-exact-range-dual-decoder-passed")
		const nativeFixture = JSON.parse(
			readFileSync(new URL("../../../sdk/packages/core/scripts/owned-native-call-fixture.json", import.meta.url), "utf8"),
		) as { base64: string; sha256: string }
		const nativeBytes = Buffer.from(nativeFixture.base64, "base64"),
			nativeTarget = join(workspace, "owned-native-call-chain.so")
		if (createHash("sha256").update(nativeBytes).digest("hex") !== nativeFixture.sha256)
			throw new Error("Owned native call fixture digest mismatch")
		await writeFile(nativeTarget, nativeBytes)
		const nativeTraceRequest = {
			operation: "trace_native_calls",
			target: nativeTarget,
			function_selector: { symbol: "owned_root" },
			advanced_options: { native_calls: { max_depth: 2, max_functions: 3, max_edges: 4, max_total_bytes: 32 } },
			timeout_ms: 120000,
		}
		type OwnedNativeGraph = {
			protocol: string
			status: string
			observedExecution: boolean
			nodes: { name: string; depth: number; status: string }[]
			edges: { resolution: string }[]
			usage: { requestedBytes: number }
			coverage: { limitsReached: string[] }
		}
		const nativeGraph = (receipt: unknown) =>
			(
				receipt as {
					result: {
						status: string
						observedExecution: boolean
						stages: {
							result: {
								result: { protocol: string; input: { sha256: string }; evidence: { callGraph: OwnedNativeGraph } }
							}
						}[]
					}
				}
			).result
		const nativeResult = nativeGraph(await runOwnedAdvanced(nativeTraceRequest)),
			nativeWorker = nativeResult.stages[0]?.result.result,
			nativeCalls = nativeWorker?.evidence.callGraph
		if (
			nativeResult.status !== "partial" ||
			nativeResult.observedExecution !== false ||
			nativeWorker?.protocol !== "cline-advanced-analysis/v1" ||
			nativeWorker.input.sha256 !== nativeFixture.sha256 ||
			nativeCalls?.protocol !== "cline-native-call-graph/v1" ||
			nativeCalls.status !== "partial" ||
			nativeCalls.observedExecution !== false ||
			nativeCalls.nodes.map((n) => n.name).join(",") !== "owned_root,owned_child,owned_leaf" ||
			nativeCalls.nodes.map((n) => n.depth).join(",") !== "0,1,2" ||
			!nativeCalls.nodes.every((n) => n.status === "completed") ||
			nativeCalls.edges.length !== 3 ||
			nativeCalls.edges[2]?.resolution !== "already-scheduled-or-visited" ||
			nativeCalls.usage.requestedBytes !== 18 ||
			nativeCalls.coverage.limitsReached.length !== 0
		)
			throw new Error("Installed owned native transitive call evidence failed or claimed runtime execution")
		const nativeLimited = nativeGraph(
			await runOwnedAdvanced({
				...nativeTraceRequest,
				advanced_options: { native_calls: { max_depth: 0, max_functions: 3, max_edges: 4, max_total_bytes: 32 } },
			}),
		).stages[0]?.result.result.evidence.callGraph
		if (
			nativeLimited?.nodes.length !== 1 ||
			nativeLimited.edges[0]?.resolution !== "depth-limit" ||
			!nativeLimited.coverage.limitsReached.includes("max_depth") ||
			!(await readFile(nativeTarget)).equals(nativeBytes)
		)
			throw new Error("Installed native traversal escaped its depth budget or changed the target")
		stages.push("installed-native-direct-call-transitive-budget-cycle-no-execution-passed")
		const discoveryFixture = JSON.parse(
			readFileSync(
				new URL("../../../sdk/packages/core/scripts/owned-artifact-discovery-fixture.json", import.meta.url),
				"utf8",
			),
		) as { base64: string; sha256: string }
		const discoveryBytes = Buffer.from(discoveryFixture.base64, "base64"),
			discoveryTarget = join(workspace, "owned-misleading-artifact.exe")
		if (createHash("sha256").update(discoveryBytes).digest("hex") !== discoveryFixture.sha256)
			throw new Error("Owned discovery fixture digest mismatch")
		await writeFile(discoveryTarget, discoveryBytes)
		type OwnedDiscovery = {
			status: string
			observedExecution: boolean
			stages: {
				result: {
					result: {
						input: { sha256: string }
						evidence: {
							identification: {
								protocol: string
								unknownCount: number
								ambiguousCount: number
								observedExecution: boolean
							}
							artifacts: {
								format: string
								origin: string
								identification: { status: string; filenameTrusted: boolean }
							}[]
							coverage: { truncated: boolean }
						}
					}
				}
			}[]
		}
		const discovered = (
			await runOwnedAdvanced({
				operation: "identify_artifact",
				target: discoveryTarget,
				artifact_discovery: { max_depth: 3, max_artifacts: 8 },
				timeout_ms: 120000,
			})
		).result as unknown as OwnedDiscovery
		const discoveredWorker = discovered.stages[0]?.result.result,
			discoveredEvidence = discoveredWorker?.evidence
		if (
			discovered.status !== "partial" ||
			discovered.observedExecution !== false ||
			discoveredWorker?.input.sha256 !== discoveryFixture.sha256 ||
			discoveredEvidence?.identification.protocol !== "cline-artifact-identification/v1" ||
			discoveredEvidence.identification.unknownCount !== 1 ||
			discoveredEvidence.identification.ambiguousCount !== 1 ||
			discoveredEvidence.identification.observedExecution !== false ||
			discoveredEvidence.artifacts.map((a) => a.format).join(",") !== "zip,gzip,dex,opaque,opaque" ||
			discoveredEvidence.artifacts[2]?.origin !== "gzip-expansion" ||
			discoveredEvidence.artifacts.some((a) => a.identification.filenameTrusted !== false)
		)
			throw new Error("Installed nested content/ambiguous/unknown artifact identification failed")
		const discoveryLimited = (
			await runOwnedAdvanced({
				operation: "identify_artifact",
				target: discoveryTarget,
				artifact_discovery: { max_depth: 0, max_artifacts: 8 },
				timeout_ms: 120000,
			})
		).result as unknown as OwnedDiscovery
		if (
			discoveryLimited.status !== "partial" ||
			discoveryLimited.stages[0]?.result.result.evidence.artifacts.length !== 1 ||
			!discoveryLimited.stages[0].result.result.evidence.coverage.truncated ||
			!(await readFile(discoveryTarget)).equals(discoveryBytes)
		)
			throw new Error("Installed discovery escaped depth budget or changed input")
		stages.push("installed-content-artifact-discovery-nesting-ambiguity-budgets-no-execution-passed")
		const jniFixture = JSON.parse(
			readFileSync(
				new URL("../../../sdk/packages/core/scripts/owned-jni-cross-language-fixture.json", import.meta.url),
				"utf8",
			),
		) as { base64: string; sha256: string; nativeSha256: string }
		const jniBytes = Buffer.from(jniFixture.base64, "base64"),
			jniTarget = join(workspace, "owned-fresh-jni.apk")
		if (createHash("sha256").update(jniBytes).digest("hex") !== jniFixture.sha256)
			throw new Error("Owned fresh JNI fixture digest mismatch")
		await writeFile(jniTarget, jniBytes)
		const jniRequest = {
			operation: "trace_cross_language",
			target: jniTarget,
			cross_language: {
				kind: "android-jni",
				method: { class_descriptor: "LFixture;", name: "native_work", descriptor: "()V" },
				native_artifact: "lib/x86_64/libowned.so",
				max_candidates: 8,
				native_calls: { max_depth: 2, max_functions: 3, max_edges: 4, max_total_bytes: 32 },
			},
			timeout_ms: 120000,
		}
		type OwnedJni = {
			status: string
			observedExecution: boolean
			stages: {
				result: {
					result: {
						input: { sha256: string }
						evidence: {
							crossLanguageTrace: {
								bindingVerified: boolean
								observedExecution: boolean
								registrationStatus: string
								selectedMethodCount: number
								candidateCount: number
								nativeTraversal: { status: string; nativeArtifactSha256: string; callGraph: OwnedNativeGraph }
							}
						}
					}
				}
			}[]
		}
		const jniResult = (await runOwnedAdvanced(jniRequest)).result as unknown as OwnedJni,
			jniWorker = jniResult.stages[0]?.result.result,
			jniTrace = jniWorker?.evidence.crossLanguageTrace,
			jniGraph = jniTrace?.nativeTraversal.callGraph
		if (
			jniResult.status !== "partial" ||
			jniResult.observedExecution !== false ||
			jniWorker?.input.sha256 !== jniFixture.sha256 ||
			jniTrace?.bindingVerified !== false ||
			jniTrace.observedExecution !== false ||
			jniTrace.registrationStatus !== "unresolved-not-observed" ||
			jniTrace.selectedMethodCount !== 1 ||
			jniTrace.candidateCount !== 1 ||
			jniTrace.nativeTraversal.nativeArtifactSha256 !== jniFixture.nativeSha256 ||
			jniGraph?.observedExecution !== false ||
			jniGraph.nodes.map((n) => n.name).join(",") !== "Java_Fixture_native_1work,owned_child,owned_leaf" ||
			jniGraph.edges[2]?.resolution !== "already-scheduled-or-visited"
		)
			throw new Error("Installed fresh JNI export/native-call candidate evidence failed or claimed an observed binding")
		const missingJni = (
			await runOwnedAdvanced({
				...jniRequest,
				cross_language: { ...jniRequest.cross_language, native_artifact: "lib/missing.so" },
			})
		).result as unknown as OwnedJni
		if (
			missingJni.status !== "partial" ||
			missingJni.stages[0]?.result.result.evidence.crossLanguageTrace.candidateCount !== 0 ||
			missingJni.stages[0].result.result.evidence.crossLanguageTrace.nativeTraversal.status !== "not-started" ||
			!(await readFile(jniTarget)).equals(jniBytes)
		)
			throw new Error("Installed missing JNI library invented a binding or changed input")
		stages.push("installed-fresh-android-jni-native-candidates-no-binding-or-execution-passed")
		const electronRoot = join(workspace, "owned-fresh-electron")
		await mkdir(electronRoot)
		const electronSources = {
			"preload.ts":
				'import {contextBridge as cb,ipcRenderer as ir} from "electron";cb.exposeInMainWorld("owned",{read:(x)=>ir.invoke("owned:read",x)});',
			"renderer.js": "window.owned.read(1);globalThis.__crossLanguageShouldNotExecute=true;",
			"main.js":
				'import {ipcMain} from "electron";ipcMain.handle("owned:read",()=>42);ipcMain.handle("other:channel",()=>0);',
		}
		for (const [name, source] of Object.entries(electronSources)) await writeFile(join(electronRoot, name), source)
		type OwnedElectron = {
			status: string
			observedExecution: boolean
			mode: string
			selection: { status: string; handlerCandidates: number }
			nodes: { kind: string; value: string }[]
			edges: { kind: string }[]
			artifacts: { path: string; sha256: string }[]
			inputFingerprint: string
		}
		const electronRequest = {
			operation: "trace_cross_language",
			target: electronRoot,
			cross_language: { kind: "electron-ipc", channel: "owned:read", max_depth: 4, max_nodes: 32, max_edges: 32 },
			timeout_ms: 120000,
		}
		const electronResult = (await runOwnedAdvanced(electronRequest)).result as unknown as OwnedElectron
		if (
			electronResult.status !== "partial" ||
			electronResult.observedExecution !== false ||
			electronResult.mode !== "fresh-electron-ipc-candidates" ||
			electronResult.selection.handlerCandidates !== 1 ||
			!electronResult.nodes.some((n) => n.kind === "preload-call") ||
			!electronResult.edges.some((e) => e.kind === "preload-candidate") ||
			!electronResult.edges.some((e) => e.kind === "ipc-candidate") ||
			electronResult.nodes.some((n) => n.value === "other:channel") ||
			electronResult.artifacts.length !== 3 ||
			!/^([a-f0-9]{64})$/.test(electronResult.inputFingerprint)
		)
			throw new Error("Installed fresh Electron renderer/preload/main candidates failed")
		const missingElectron = (
			await runOwnedAdvanced({
				...electronRequest,
				cross_language: { ...electronRequest.cross_language, channel: "missing" },
			})
		).result as unknown as OwnedElectron
		if (
			missingElectron.status !== "partial" ||
			missingElectron.selection.status !== "not-found-in-covered-sources" ||
			missingElectron.nodes.length !== 0
		)
			throw new Error("Installed missing IPC channel invented a path")
		for (const [name, source] of Object.entries(electronSources))
			if (
				(await readFile(join(electronRoot, name), "utf8")) !== source ||
				!electronResult.artifacts.some(
					(a) => a.path === name && a.sha256 === createHash("sha256").update(source).digest("hex"),
				)
			)
				throw new Error("Installed fresh Electron input/provenance changed")
		stages.push("installed-fresh-electron-renderer-preload-main-channel-candidates-passed")
		const methodCallsFixture = JSON.parse(
			readFileSync(
				new URL("../../../sdk/packages/core/scripts/owned-android-method-calls-fixture.json", import.meta.url),
				"utf8",
			),
		) as { base64: string; sha256: string; ambiguousBase64: string; ambiguousSha256: string }
		const methodCallsTarget = join(workspace, "owned-method-calls.dex"),
			ambiguousMethodCallsTarget = join(workspace, "owned-method-calls-ambiguous.apk")
		for (const f of [
			{ path: methodCallsTarget, base64: methodCallsFixture.base64, sha256: methodCallsFixture.sha256 },
			{
				path: ambiguousMethodCallsTarget,
				base64: methodCallsFixture.ambiguousBase64,
				sha256: methodCallsFixture.ambiguousSha256,
			},
		]) {
			const bytes = Buffer.from(f.base64, "base64")
			if (createHash("sha256").update(bytes).digest("hex") !== f.sha256)
				throw new Error("Owned method-call fixture digest mismatch")
			await writeFile(f.path, bytes)
		}
		type OwnedMethodCalls = {
			status: string
			observedExecution: boolean
			stages: {
				result: {
					result: {
						input: { sha256: string }
						evidence: {
							methodCalls: {
								protocol: string
								status: string
								selectionStatus: string
								selectedDefinitionCount: number
								referenceCount: number
								referencesTruncated: boolean
								dispatchVerified: boolean
								observedExecution: boolean
								coverage: { methods: number; instructions: number }
								references: {
									artifactSha256: string
									relativeToSelection: string
									bytecodeOffset: number
									opcode: string
									dispatchVerified: boolean
									executionObserved: boolean
									caller: { byteFingerprint: string }
								}[]
							}
						}
					}
				}
			}[]
		}
		const methodCallsRequest = {
			operation: "trace_android_method",
			target: methodCallsTarget,
			advanced_options: { method: { class_descriptor: "LCalls;", name: "root", descriptor: "()V" } },
			timeout_ms: 120000,
		}
		const methodCallsResult = (await runOwnedAdvanced(methodCallsRequest)).result as unknown as OwnedMethodCalls,
			methodCallsWorker = methodCallsResult.stages[1]?.result.result,
			methodCalls = methodCallsWorker?.evidence.methodCalls
		if (
			methodCallsResult.status !== "partial" ||
			methodCallsResult.observedExecution !== false ||
			methodCallsWorker?.input.sha256 !== methodCallsFixture.sha256 ||
			methodCalls?.protocol !== "cline-android-method-calls/v1" ||
			methodCalls.status !== "partial" ||
			methodCalls.selectionStatus !== "defined" ||
			methodCalls.selectedDefinitionCount !== 1 ||
			methodCalls.referenceCount !== 2 ||
			methodCalls.references.length !== 2 ||
			methodCalls.references
				.map((r) => r.relativeToSelection)
				.sort()
				.join(",") !== "callee,caller" ||
			methodCalls.dispatchVerified !== false ||
			methodCalls.observedExecution !== false ||
			methodCalls.coverage.methods !== 2 ||
			methodCalls.coverage.instructions !== 4 ||
			methodCalls.references.some(
				(r) =>
					r.artifactSha256 !== methodCallsFixture.sha256 ||
					r.bytecodeOffset !== 0 ||
					r.opcode !== "invoke-static" ||
					r.dispatchVerified !== false ||
					r.executionObserved !== false ||
					!/^[a-f0-9]{64}$/.test(r.caller.byteFingerprint),
			)
		)
			throw new Error("Installed exact method-call references lost origin, limits or static-only status")
		const limitedMethodCalls = (await runOwnedAdvanced({ ...methodCallsRequest, max_results: 1 }))
			.result as unknown as OwnedMethodCalls
		const limitedMethodEvidence = limitedMethodCalls.stages[1]?.result.result.evidence.methodCalls
		if (
			limitedMethodCalls.status !== "partial" ||
			limitedMethodEvidence?.referenceCount !== 2 ||
			limitedMethodEvidence.references.length !== 1 ||
			limitedMethodEvidence.referencesTruncated !== true
		)
			throw new Error("Installed method-call detail budget lost coverage counts")
		const ambiguousMethodCalls = (await runOwnedAdvanced({ ...methodCallsRequest, target: ambiguousMethodCallsTarget }))
			.result as unknown as OwnedMethodCalls
		const ambiguousMethodEvidence = ambiguousMethodCalls.stages[1]?.result.result.evidence.methodCalls
		if (
			ambiguousMethodCalls.status !== "partial" ||
			ambiguousMethodEvidence?.selectionStatus !== "ambiguous-definition" ||
			ambiguousMethodEvidence.selectedDefinitionCount !== 2 ||
			ambiguousMethodEvidence.references.length !== 0
		)
			throw new Error("Installed method tracing selected an ambiguous DEX definition")
		if (
			!(await readFile(methodCallsTarget)).equals(Buffer.from(methodCallsFixture.base64, "base64")) ||
			!(await readFile(ambiguousMethodCallsTarget)).equals(Buffer.from(methodCallsFixture.ambiguousBase64, "base64"))
		)
			throw new Error("Installed method-call tracing modified its input")
		stages.push("installed-android-method-call-references-origin-budgets-ambiguity-no-execution-passed")
		const traversalFixture = JSON.parse(
			readFileSync(
				new URL("../../../sdk/packages/core/scripts/owned-android-call-traversal-fixture.json", import.meta.url),
				"utf8",
			),
		) as Record<"cycle" | "external", { base64: string; sha256: string }>
		const traversalTarget = join(workspace, "owned-android-call-traversal.dex"),
			externalTraversalTarget = join(workspace, "owned-android-call-external.dex")
		for (const [key, path] of [
			["cycle", traversalTarget],
			["external", externalTraversalTarget],
		] as const) {
			const f = traversalFixture[key],
				bytes = Buffer.from(f.base64, "base64")
			if (createHash("sha256").update(bytes).digest("hex") !== f.sha256)
				throw new Error("Owned Android traversal fixture digest mismatch")
			await writeFile(path, bytes)
		}
		type OwnedAndroidTraversal = {
			protocol: string
			status: string
			reason?: string
			dispatchVerified: boolean
			observedExecution: boolean
			limitsReached: string[]
			nodes: { id: string; name: string; depth: number; artifactSha256: string; byteFingerprint: string }[]
			edges: {
				id: string
				artifactSha256: string
				resolution: string
				targetMethodId: string | null
				definitionCandidateCount: number
				dispatchVerified: boolean
				executionObserved: boolean
			}[]
		}
		type OwnedTraversalResult = {
			status: string
			observedExecution: boolean
			stages: {
				result: { result: { input: { sha256: string }; evidence: { methodCalls: { traversal: OwnedAndroidTraversal } } } }
			}[]
		}
		const runTraversal = async (budget: Record<string, unknown>, target = traversalTarget) => {
			const r = (
				await runOwnedAdvanced({
					...methodCallsRequest,
					target,
					advanced_options: { ...methodCallsRequest.advanced_options, android_calls: budget },
				})
			).result as unknown as OwnedTraversalResult
			const worker = r.stages[1]?.result.result,
				g = worker?.evidence.methodCalls.traversal
			if (
				r.status !== "partial" ||
				r.observedExecution !== false ||
				!g ||
				g.protocol !== "cline-android-call-traversal/v1" ||
				g.dispatchVerified !== false ||
				g.observedExecution !== false
			)
				throw new Error("Installed Android traversal lost static-only contract")
			return { g, worker }
		}
		const { g: traversal, worker: traversalWorker } = await runTraversal({ max_depth: 4, direction: "callees" })
		if (
			traversalWorker.input.sha256 !== traversalFixture.cycle.sha256 ||
			traversal.status !== "partial" ||
			traversal.nodes.map((n) => n.name).join(",") !== "root,middle,leaf,external" ||
			traversal.nodes.map((n) => n.depth).join(",") !== "0,1,2,3" ||
			traversal.edges.length !== 4 ||
			new Set(traversal.edges.map((e) => e.id)).size !== 4 ||
			traversal.edges[2]?.resolution !== "already-scheduled-or-visited" ||
			traversal.limitsReached.length !== 0 ||
			traversal.nodes.some(
				(n) => n.artifactSha256 !== traversalFixture.cycle.sha256 || !/^[a-f0-9]{64}$/.test(n.byteFingerprint),
			) ||
			traversal.edges.some(
				(e) =>
					e.artifactSha256 !== traversalFixture.cycle.sha256 ||
					e.dispatchVerified !== false ||
					e.executionObserved !== false,
			)
		)
			throw new Error("Installed Android multihop cycle/provenance acceptance failed")
		const { g: reverseTraversal } = await runTraversal({ max_depth: 4, direction: "callers" })
		if (reverseTraversal.nodes.map((n) => n.name).join(",") !== "root,leaf,middle" || reverseTraversal.edges.length !== 3)
			throw new Error("Installed Android caller traversal direction failed")
		for (const [budget, expectedLimit, expectedNodes, expectedEdges] of [
			[{ max_depth: 0 }, "depth-budget", 1, 0],
			[{ max_nodes: 1, direction: "callees" }, "node-budget", 1, 1],
			[{ max_edges: 1, direction: "callees" }, "edge-budget", 2, 1],
		] as const) {
			const { g } = await runTraversal(budget)
			if (!g.limitsReached.includes(expectedLimit) || g.nodes.length !== expectedNodes || g.edges.length !== expectedEdges)
				throw new Error(`Installed Android traversal escaped ${expectedLimit}`)
		}
		const { g: externalTraversal, worker: externalWorker } = await runTraversal(
			{ max_depth: 4, direction: "callees" },
			externalTraversalTarget,
		)
		if (
			externalWorker.input.sha256 !== traversalFixture.external.sha256 ||
			externalTraversal.nodes.length !== 3 ||
			externalTraversal.edges.length !== 4 ||
			externalTraversal.edges[3]?.resolution !== "external-or-uncovered-definition" ||
			externalTraversal.edges[3]?.targetMethodId !== null
		)
			throw new Error("Installed Android traversal invented an external definition")
		const { g: ambiguousTraversal } = await runTraversal({ max_depth: 4 }, ambiguousMethodCallsTarget)
		if (
			ambiguousTraversal.status !== "not-started" ||
			ambiguousTraversal.reason !== "ambiguous-definition" ||
			ambiguousTraversal.nodes.length !== 0 ||
			ambiguousTraversal.edges.length !== 0
		)
			throw new Error("Installed Android traversal expanded an ambiguous root")
		for (const [key, path] of [
			["cycle", traversalTarget],
			["external", externalTraversalTarget],
		] as const)
			if (!(await readFile(path)).equals(Buffer.from(traversalFixture[key].base64, "base64")))
				throw new Error("Installed Android traversal modified an input")
		stages.push("installed-android-transitive-call-candidates-direction-cycles-budgets-no-execution-passed")
		const callbackFixture = JSON.parse(
			readFileSync(
				new URL("../../../sdk/packages/core/scripts/owned-android-entrypoints-fixture.json", import.meta.url),
				"utf8",
			),
		) as {
			base64: string
			sha256: string
			comparisonBase64: string
			comparisonSha256: string
			ambiguousBase64: string
			ambiguousSha256: string
			dexSha256: string
		}
		const callbackTarget = join(workspace, "owned-callback.apk"),
			callbackOther = join(workspace, "owned-callback-after.apk"),
			callbackAmbiguous = join(workspace, "owned-callback-ambiguous.apk")
		const callbackInputs = [
			{ path: callbackTarget, base64: callbackFixture.base64, sha256: callbackFixture.sha256 },
			{ path: callbackOther, base64: callbackFixture.comparisonBase64, sha256: callbackFixture.comparisonSha256 },
			{ path: callbackAmbiguous, base64: callbackFixture.ambiguousBase64, sha256: callbackFixture.ambiguousSha256 },
		]
		for (const f of callbackInputs) {
			const bytes = Buffer.from(f.base64, "base64")
			if (createHash("sha256").update(bytes).digest("hex") !== f.sha256)
				throw new Error("Owned callback fixture digest mismatch")
			await writeFile(f.path, bytes)
		}
		type OwnedCallbacks = {
			status: string
			observedExecution: boolean
			stages: {
				result: {
					result: {
						input: { sha256: string }
						evidence: {
							candidateCount: number
							dispatchVerified: boolean
							observedExecution: boolean
							candidates: {
								declaredClass: string
								declaringClass: string
								name: string
								descriptor: string
								artifactSha256: string
								dispatchVerified: boolean
								executionObserved: boolean
							}[]
							components: { searchStopped: string }[]
							coverage: { dexTruncated: boolean }
						}
					}
				}
			}[]
		}
		const callbackResult = (
			await runOwnedAdvanced({
				operation: "find_android_entrypoints",
				target: callbackTarget,
				advanced_options: { entrypoints: { max_depth: 8, max_components: 64, max_dex_files: 32 } },
				timeout_ms: 120000,
			})
		).result as unknown as OwnedCallbacks
		const callbackWorker = callbackResult.stages[0]?.result.result,
			callbackEvidence = callbackWorker?.evidence,
			callback = callbackEvidence?.candidates[0]
		if (
			callbackResult.status !== "partial" ||
			callbackResult.observedExecution !== false ||
			callbackWorker?.input.sha256 !== callbackFixture.sha256 ||
			callbackEvidence?.candidateCount !== 1 ||
			callbackEvidence.dispatchVerified !== false ||
			callbackEvidence.observedExecution !== false ||
			callback?.declaredClass !== "Lapp/Xxx;" ||
			callback.declaringClass !== "Lapp/Xxx;" ||
			callback.name !== "onTerminate" ||
			callback.descriptor !== "()V" ||
			callback.artifactSha256 !== callbackFixture.dexSha256 ||
			callback.dispatchVerified !== false ||
			callback.executionObserved !== false
		)
			throw new Error("Installed callback candidate origins failed or claimed dispatch/execution")
		const ambiguousCallbacks = (
			await runOwnedAdvanced({ operation: "find_android_entrypoints", target: callbackAmbiguous, timeout_ms: 120000 })
		).result as unknown as OwnedCallbacks
		if (
			ambiguousCallbacks.status !== "partial" ||
			ambiguousCallbacks.stages[0]?.result.result.evidence.candidateCount !== 0 ||
			ambiguousCallbacks.stages[0].result.result.evidence.components[0]?.searchStopped !== "ambiguous-class"
		)
			throw new Error("Installed callback analysis selected an ambiguous multidex class")
		const limitedCallbacks = (
			await runOwnedAdvanced({
				operation: "find_android_entrypoints",
				target: callbackAmbiguous,
				advanced_options: { entrypoints: { max_dex_files: 1 } },
				timeout_ms: 120000,
			})
		).result as unknown as OwnedCallbacks
		if (
			limitedCallbacks.status !== "partial" ||
			limitedCallbacks.stages[0]?.result.result.evidence.coverage.dexTruncated !== true
		)
			throw new Error("Installed callback DEX coverage cap was not explicit")
		stages.push("installed-android-manifest-dex-callback-candidates-origin-ambiguity-no-execution-passed")
		type OwnedResources = {
			status: string
			observedExecution: boolean
			stages: {
				result: {
					result: {
						input: { sha256: string }
						evidence: {
							compareInput: { sha256: string }
							changedFiles: number
							categoryCounts: Record<string, number>
							published: boolean
							observedExecution: boolean
							changesTruncated: boolean
							changes: {
								category: string
								parsedXmlStructureEqual?: boolean
								before: { sha256: string }
								after: { sha256: string }
							}[]
						}
					}
				}
			}[]
		}
		const resourceRequest = {
			operation: "diff_android_resources",
			target: callbackTarget,
			compare_target: callbackOther,
			timeout_ms: 120000,
		}
		const resourceResult = (await runOwnedAdvanced(resourceRequest)).result as unknown as OwnedResources,
			resourceWorker = resourceResult.stages[0]?.result.result,
			resourceEvidence = resourceWorker?.evidence,
			resourceXml = resourceEvidence?.changes.find((c) => c.category === "resources")
		if (
			resourceResult.status !== "partial" ||
			resourceResult.observedExecution !== false ||
			resourceWorker?.input.sha256 !== callbackFixture.sha256 ||
			resourceEvidence?.compareInput.sha256 !== callbackFixture.comparisonSha256 ||
			resourceEvidence.changedFiles !== 3 ||
			resourceEvidence.categoryCounts.manifest !== 1 ||
			resourceEvidence.categoryCounts.resources !== 1 ||
			resourceEvidence.categoryCounts.assets !== 1 ||
			resourceEvidence.published !== false ||
			resourceEvidence.observedExecution !== false ||
			resourceEvidence.changesTruncated ||
			resourceXml?.parsedXmlStructureEqual !== true ||
			resourceXml.before.sha256 === resourceXml.after.sha256
		)
			throw new Error("Installed resource byte/XML comparison failed or claimed semantic equivalence")
		const limitedResources = (await runOwnedAdvanced({ ...resourceRequest, max_results: 1 }))
				.result as unknown as OwnedResources,
			limitedResourceEvidence = limitedResources.stages[0]?.result.result.evidence
		if (
			limitedResources.status !== "partial" ||
			limitedResourceEvidence?.changedFiles !== 3 ||
			limitedResourceEvidence.changes.length !== 1 ||
			!limitedResourceEvidence.changesTruncated
		)
			throw new Error("Installed resource detail cap lost total counts")
		for (const f of callbackInputs)
			if (!(await readFile(f.path)).equals(Buffer.from(f.base64, "base64")))
				throw new Error("Installed Android static comparison modified its input")
		stages.push("installed-android-resource-member-sha256-xml-structure-budgets-no-execution-passed")
		const versionBefore = join(workspace, "owned-version-before"),
			versionAfter = join(workspace, "owned-version-after")
		const versionSources = {
			before: {
				"api.ts": "export function read(x:string):string{return x}",
				"package.json": '{"version":1}',
				"assets/a": "old",
				"lib/owned.so": "old",
				".hidden": "keep",
			},
			after: {
				"api.ts": "export function read(x:number):number{return x};globalThis.__versionMustNotRun=true;",
				"package.json": '{"version":2}',
				"assets/a": "new",
				"lib/owned.so": "new",
				".hidden": "keep",
			},
		}
		for (const [side, files] of Object.entries(versionSources)) {
			const root = side === "before" ? versionBefore : versionAfter
			await mkdir(root)
			for (const [file, value] of Object.entries(files)) {
				await mkdir(join(root, file, ".."), { recursive: true })
				await writeFile(join(root, file), value)
			}
		}
		type OwnedVersion = {
			status: string
			published: boolean
			observedExecution: boolean
			changedFiles: number
			baselineInventorySha256: string
			candidateInventorySha256: string
			categoryCounts: Record<string, number>
			changes: { path: string; before_sha256: string; after_sha256: string }[]
			changesTruncated: boolean
			publicApi: { changed: string[]; removed: string[] }
			coverage: { inventoryPasses: number }
		}
		const versionRequest = {
			operation: "compare_versions",
			target: versionBefore,
			compare_target: versionAfter,
			version_comparison: { kind: "project", max_results: 100 },
			timeout_ms: 120000,
		}
		const versionResult = (await runOwnedAdvanced(versionRequest)).result as unknown as OwnedVersion
		if (
			versionResult.status !== "partial" ||
			versionResult.published !== false ||
			versionResult.observedExecution !== false ||
			versionResult.changedFiles !== 4 ||
			versionResult.coverage.inventoryPasses !== 4 ||
			versionResult.categoryCounts.source !== 1 ||
			versionResult.categoryCounts.manifest !== 1 ||
			versionResult.categoryCounts["resources-assets"] !== 1 ||
			versionResult.categoryCounts["native-binary"] !== 1 ||
			versionResult.publicApi.changed.join(",") !== "api.ts:read" ||
			versionResult.publicApi.removed.length !== 0 ||
			versionResult.changes.length !== 4 ||
			versionResult.baselineInventorySha256 === versionResult.candidateInventorySha256
		)
			throw new Error(
				"Installed combined project version inventory/API evidence failed or claimed full semantic equivalence",
			)
		const versionLimited = (
			await runOwnedAdvanced({ ...versionRequest, version_comparison: { kind: "project", max_results: 1 } })
		).result as unknown as OwnedVersion
		if (
			versionLimited.status !== "partial" ||
			versionLimited.changedFiles !== 4 ||
			versionLimited.changes.length !== 1 ||
			!versionLimited.changesTruncated
		)
			throw new Error("Installed project comparison detail cap lost total counts")
		for (const [side, files] of Object.entries(versionSources)) {
			const root = side === "before" ? versionBefore : versionAfter
			for (const [file, value] of Object.entries(files))
				if ((await readFile(join(root, file), "utf8")) !== value)
					throw new Error("Installed version comparison modified input")
		}
		stages.push("installed-combined-project-version-hashes-api-categories-budgets-no-execution-passed")

		// Save a real receipt selector through the visible UI before a real app/sidecar restart.
		// No preview, hashes, plan or execution token may enter device selection storage.
		await openInstalledSavedSession(page, /Installer owned session/)
		await verifyRecordedTaskReport()
		stages.push("installed-task-report-restored-after-restart-no-replay-passed")
		await page.getByRole("button", { name: "Open Analysis Workspace", exact: true }).click()
		await page.getByRole("button", { name: "App analysis", exact: true }).click()
		const restartSourceWorkspace = page.getByLabel("First-party Analysis Workspace", { exact: true })
		await restartSourceWorkspace.getByLabel("Saved analysis receipt", { exact: true }).selectOption(parsed.id)
		await restartSourceWorkspace.getByRole("button", { name: "artifacts", exact: true }).click()
		await restartSourceWorkspace.getByLabel("Filter analysis evidence", { exact: true }).fill("selection-owned.ts")
		await restartSourceWorkspace.getByRole("button", { name: "Inspect saved source identity", exact: true }).click()
		const beforeRestartSource = page.getByRole("region", { name: "Selected source evidence", exact: true })
		await beforeRestartSource.getByText("Source identity: matched", { exact: true }).waitFor({ timeout: 30000 })
		await beforeRestartSource.getByLabel("Remember this evidence reference on this device", { exact: true }).check()
		await page.waitForFunction(
			(id) =>
				Object.keys(localStorage)
					.filter((k) => k.endsWith(":source-reference.v1"))
					.some((key) => JSON.parse(localStorage.getItem(key)!).selection?.receiptId === id),
			parsed.id,
			{ timeout: 30000 },
		)
		const savedSourceReference = await acceptanceAction(
			"owned-source-reference-storage",
			() =>
				page.evaluate((id) => {
					const records = Object.keys(localStorage)
						.filter((k) => k.endsWith(":source-reference.v1"))
						.map((key) => ({ key, value: JSON.parse(localStorage.getItem(key)!) }))
						.filter((r) => r.value.selection?.receiptId === id)
					return records
				}, parsed.id),
			30000,
		)
		if (
			savedSourceReference.length !== 1 ||
			JSON.stringify(Object.keys(savedSourceReference[0].value).sort()) !== JSON.stringify(["selection", "version"]) ||
			savedSourceReference[0].value.version !== 1 ||
			Object.keys(savedSourceReference[0].value.selection).sort().join(",") !== "receiptId,selector" ||
			savedSourceReference[0].value.selection.selector.kind !== "artifact" ||
			Object.keys(savedSourceReference[0].value.selection.selector).sort().join(",") !== "kind,path"
		)
			throw new Error("Installed remembered source reference retained extra data or wrong selector")
		await page.screenshot({ path: join(evidence, "full-capabilities.png") })
		await setInvestigationDisabled(true)
		await acceptanceAction("owned-normal-native-quit-for-restart", () => quitForRestart(page), 95_000)
		page = await launch()
		verifyInstalledInvestigationCatalog(await readSkills(), false, installedSkillRoot)
		await setInvestigationDisabled(false)
		await writeFile(
			join(evidence, "investigation-skills-restart.json"),
			JSON.stringify(
				{
					plugin: INSTALLED_INVESTIGATION_PLUGIN,
					disabledPersisted: true,
					reenabled: true,
					providerCalls: 0,
					targetExecuted: false,
				},
				null,
				2,
			),
		)
		stages.push("installed-bundled-investigation-skills-disable-persisted-restart-passed")
		const restartedSourceReference = await acceptanceAction(
			"owned-source-reference-after-restart",
			() => page.evaluate((key) => localStorage.getItem(key), savedSourceReference[0].key),
			30000,
		)
		verifyInstalledSourceReferenceStorage(savedSourceReference[0].value, restartedSourceReference)
		await settings(page, "General")
		const persisted = await rpc<{ customAiInstructions?: string }>(page, "get_desktop_settings")
		if (persisted.customAiInstructions !== "Installer acceptance: preserve this owned local setting.")
			throw new Error("Installed backend setting did not survive restart")
		await verifyRestartInstructions(
			page.getByRole("textbox", {
				name: "Custom AI instructions",
				exact: true,
			}),
			"Installer acceptance: preserve this owned local setting.",
		)

		const resumedFull = await rpc<{
			fullStatus: string
			runtime: { runtimeId: string }
		}>(page, "setup_center_status", { environmentId: "local" })
		if (resumedFull.fullStatus !== "Ready" || !resumedFull.runtime.runtimeId.includes("-full-"))
			throw new Error("Full private interpreter selection or actual fixture receipt did not survive restart")
		stages.push("full-pack-selection-and-receipts-survived-restart")
		const sessions = await rpc<Array<{ sessionId: string }>>(page, "list_chat_sessions")
		if (!sessions.some((item) => item.sessionId === session.sessionId))
			throw new Error("Owned session did not survive installed-app restart")
		await rpc(page, "chat_session_command", {
			request: {
				action: "attach",
				sessionId: session.sessionId,
				config: { environmentId: "local" },
			},
		})
		stages.push("restart-setting-and-session-persistence-passed")
		await openInstalledSavedSession(page, /Installer owned session/)
		await page.getByRole("button", { name: "Open Analysis Workspace", exact: true }).click()
		const restoredSource = page.getByRole("region", { name: "Selected source evidence", exact: true })
		await restoredSource
			.getByText("Restored evidence reference — recheck required. No source has been read.", { exact: true })
			.waitFor({ timeout: 30000 })
		if (
			(await restoredSource.getByLabel("Bounded source snapshot", { exact: true }).count()) ||
			(await restoredSource.getByText("Source identity: matched", { exact: true }).count())
		)
			throw new Error("Installed restart restored a live source preview or trusted identity")
		try {
			await writeFile(sourceSelectionTarget, 'export const restartChanged = "CURRENT_RESTART_NOT_SAVED";')
			await restoredSource.getByRole("button", { name: "Recheck selected source", exact: true }).click()
			await restoredSource.getByText("Source identity: stale", { exact: true }).waitFor({ timeout: 30000 })
			if (
				(await restoredSource.getByLabel("Bounded source snapshot", { exact: true }).count()) ||
				(await restoredSource.innerText()).includes("CURRENT_RESTART_NOT_SAVED")
			)
				throw new Error("Installed restored stale source exposed current bytes")
		} finally {
			await writeFile(sourceSelectionTarget, sourceSelectionText)
		}
		await restoredSource.getByRole("button", { name: "Recheck selected source", exact: true }).click()
		await restoredSource.getByText("Source identity: matched", { exact: true }).waitFor({ timeout: 30000 })
		await restoredSource.getByRole("button", { name: "Clear source evidence selection", exact: true }).click()
		await restoredSource.waitFor({ state: "detached" })
		await page.waitForFunction((key) => localStorage.getItem(key) === null, savedSourceReference[0].key, { timeout: 30000 })
		if (
			(await acceptanceAction(
				"owned-source-reference-clear",
				() => page.evaluate((key) => localStorage.getItem(key), savedSourceReference[0].key),
				30000,
			)) !== null
		)
			throw new Error("Installed explicit clear did not remove saved source reference")
		if ((await rpc<{ mode: string }>(page, "first_party_analysis_status", analysisArgs)).mode !== "off")
			throw new Error("Installed source restart changed Analysis Off")
		await page.getByRole("button", { name: "Close diff view", exact: true }).click()
		stages.push("installed-source-reference-restart-inert-explicit-recheck-clear-passed")
		const beforeHub = JSON.parse(await readFile(discoveryPath, "utf8"))
		if (!Number.isInteger(beforeHub.pid) || beforeHub.pid < 1) throw new Error("Owned isolated Hub PID unavailable")
		// This discovery belongs only to this fixture. No user Hub is killed.
		await killOwnedProcess(beforeHub.pid)
		// list_chat_sessions is local SQLite discovery, not a Hub readiness probe.
		// First exercise the real registration/reattachment recovery contract.
		await verifyRecoveredHubSession(
			() =>
				rpc(page, "chat_session_command", {
					request: {
						action: "attach",
						sessionId: session.sessionId,
						config: { environmentId: "local" },
					},
				}),
			() => rpc<Array<{ sessionId: string }>>(page, "list_chat_sessions"),
			session.sessionId,
		)
		const afterHub = JSON.parse(await readFile(discoveryPath, "utf8"))
		if (afterHub.pid === beforeHub.pid && afterHub.authToken === beforeHub.authToken)
			throw new Error("Hub restart did not refresh discovery identity")
		stages.push("hub-restart-saved-session-reattached-without-prompt-replay")

		await settings(page, "Setup Center")
		page.once("dialog", async (dialog) => await dialog.accept())
		await page.getByRole("button", { name: "Roll back to core", exact: true }).click()
		await page
			.getByLabel("Full capability pack status", { exact: true })
			.filter({ hasText: /^Setup needed$/ })
			.waitFor({ timeout: 90000 })
		const rollback = await rpc<{
			runtime: { runtimeId: string; integrity: string }
		}>(page, "setup_center_status", { environmentId: "local" })
		if (rollback.runtime.integrity !== "verified" || rollback.runtime.runtimeId.includes("-full-"))
			throw new Error("Core rollback failed to select its verified interpreter")
		stages.push("full-to-core-rollback-preserved-owned-session")
		await stop()
		page = await launch()
		await rpc(page, "chat_session_command", {
			request: {
				action: "attach",
				sessionId: session.sessionId,
				config: { environmentId: "local" },
			},
		})
		await writeFile(
			join(evidence, "performance.json"),
			JSON.stringify(
				{
					schemaVersion: 1,
					sourceCommit: process.env.GITHUB_SHA,
					environmentId: `${process.platform}-${process.arch}-${process.env.RUNNER_OS ?? "local"}`,
					workloadVersion: "installed-owned-ui/processor-setup-core-full-core-120-row-v12",
					runtimeProfiles: ["core", "full", "core-after-rollback"],
					metrics: {
						installedReadyMs: startupSamples,
						nativeAppWorkingSetMB: appWorkingSetSamples,
						ownedTranscriptScrollRoundTripMs: transcriptScrollSamples,
					},
					units: {
						installedReadyMs: "milliseconds",
						nativeAppWorkingSetMB: "MiB",
						ownedTranscriptScrollRoundTripMs: "milliseconds",
					},
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
		)
		await stop()
		stages.push("installed-owned-app-cleanup-confirmed")
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
		// Fixed fixture-owned page only. Capture the actual failed UI before native teardown.
		try {
			const failedPage = browser
				?.contexts()
				.flatMap((context) => context.pages())
				.find((candidate) => /tauri\.localhost|tauri:\/\/localhost/.test(candidate.url()))
			if (failedPage && !failedPage.isClosed())
				await failedPage.screenshot({ path: join(evidence, "failure.png"), timeout: 5000 })
		} catch {
			/* A closed renderer must not replace the original acceptance failure. */
		}
		// Read only two fixed fixture-owned logs, each at most 64 KiB, redacted.
		let hubStartupDiagnostic = ""
		for (const [leaf, evidenceLeaf] of [
			["code.log", "owned-backend-tail.log"],
			["hub-daemon.log", "owned-hub-daemon-tail.log"],
		] as const) {
			try {
				const log = await open(join(root, "data", "logs", leaf), "r")
				try {
					const info = await log.stat()
					if (info.isFile() && info.size <= 50 * 1024 * 1024) {
						const buffer = Buffer.alloc(Math.min(info.size, 64 * 1024))
						const { bytesRead } = await log.read(buffer, 0, buffer.length, Math.max(0, info.size - buffer.length))
						const tail = redactedLaunchText(buffer.subarray(0, bytesRead).toString("utf8"))
						await writeFile(join(evidence, evidenceLeaf), tail)
						if (leaf === "hub-daemon.log") hubStartupDiagnostic = tail.slice(-1600)
					}
				} finally {
					await log.close()
				}
			} catch {
				/* Diagnostics do not substitute for the strict acceptance result. */
			}
		}
		await writeFile(
			join(evidence, "summary.json"),
			JSON.stringify({ status: "failed", stages, lastAction, reason, hubStartupDiagnostic }, null, 2),
		)
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
