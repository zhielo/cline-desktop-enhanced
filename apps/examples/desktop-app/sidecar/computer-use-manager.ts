import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rm } from "node:fs/promises";
import { basename, join, normalize } from "node:path";
import type {
	AgentToolContext,
	ComputerUseExecutor,
	ComputerUseInput,
} from "@cline/core";
import { resolveClineDataDir } from "@cline/shared/storage";
import type { DesktopSettings } from "./desktop-settings";

const MAX_ACTIONS = 200;
const MAX_SESSION_AGE_MS = 15 * 60_000;
const MAX_SCREENSHOTS = 10;
const POWERSHELL_TIMEOUT_MS = 20_000;

export type ComputerUseStateItem = {
	computerSessionId: string;
	ownerSessionId: string;
	executable: string;
	processId: number;
	status: "active" | "stopped";
	createdAt: string;
	actionCount: number;
};

type SessionRecord = ComputerUseStateItem & {
	createdAtMs: number;
	screenshotPaths: string[];
};

type PowerShellRunner = (
	payload: Record<string, unknown>,
	signal?: AbortSignal,
) => Promise<Record<string, unknown>>;

type ComputerUseManagerOptions = {
	readSettings: () => DesktopSettings;
	onStateChanged?: (items: ComputerUseStateItem[]) => void;
	platform?: NodeJS.Platform;
	runPowerShell?: PowerShellRunner;
	now?: () => number;
};

function canonicalExecutable(value: string): string {
	return normalize(value.trim()).replaceAll("/", "\\").toLowerCase();
}

function jsonResult(value: unknown): string {
	return JSON.stringify(value, null, 2);
}

function requireOwner(context: AgentToolContext): string {
	if (!context.sessionId) {
		throw new Error("computer_use requires a host-provided sessionId");
	}
	return context.sessionId;
}

const POWERSHELL_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class ClineComputerUseNative {
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extraInfo);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extraInfo);
  public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
}
"@
$payloadText = [Console]::In.ReadToEnd()
$payload = $payloadText | ConvertFrom-Json
function ProcessPath([int]$pidValue) {
  try { return (Get-Process -Id $pidValue -ErrorAction Stop).Path } catch { return $null }
}
function ForegroundInfo {
  $hwnd = [ClineComputerUseNative]::GetForegroundWindow()
  [uint32]$pidValue = 0
  [void][ClineComputerUseNative]::GetWindowThreadProcessId($hwnd, [ref]$pidValue)
  $process = Get-Process -Id $pidValue -ErrorAction Stop
  $path = ProcessPath $pidValue
  return @{ hwnd = $hwnd; pid = [int]$pidValue; path = $path; title = $process.MainWindowTitle }
}
function AssertAllowedForeground {
  $foreground = ForegroundInfo
  if (-not $foreground.path -or $foreground.path.ToLowerInvariant() -ne ([string]$payload.expectedPath).ToLowerInvariant()) {
    throw "Foreground application left the allowlisted executable; computer control paused"
  }
  if (@('consent.exe','credentialuibroker.exe','lockapp.exe','logonui.exe') -contains ([IO.Path]::GetFileName($foreground.path).ToLowerInvariant())) {
    throw "Protected Windows security surfaces cannot be controlled"
  }
  return $foreground
}
function SelectorCondition {
  $conditions = New-Object System.Collections.Generic.List[System.Windows.Automation.Condition]
  if ($payload.selector.automation_id) {
    $conditions.Add((New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty, [string]$payload.selector.automation_id)))
  }
  if ($payload.selector.name) {
    $conditions.Add((New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, [string]$payload.selector.name)))
  }
  if ($payload.selector.control_type) {
    $wanted = [string]$payload.selector.control_type
    $property = [System.Windows.Automation.AutomationElement]::ControlTypeProperty
    $known = [System.Windows.Automation.ControlType]::$wanted
    if ($known) { $conditions.Add((New-Object System.Windows.Automation.PropertyCondition($property, $known))) }
  }
  if ($conditions.Count -eq 0) { return [System.Windows.Automation.Condition]::TrueCondition }
  if ($conditions.Count -eq 1) { return $conditions[0] }
  return New-Object System.Windows.Automation.AndCondition($conditions.ToArray())
}
function FindTarget($root) {
  if (-not $payload.selector) { return [System.Windows.Automation.AutomationElement]::FocusedElement }
  return $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, (SelectorCondition))
}
function ClickAt([int]$x, [int]$y, [string]$button) {
  [void][ClineComputerUseNative]::SetCursorPos($x, $y)
  if ($button -eq 'right') { $down = 0x0008; $up = 0x0010 } else { $down = 0x0002; $up = 0x0004 }
  [ClineComputerUseNative]::mouse_event($down,0,0,0,[UIntPtr]::Zero)
  [ClineComputerUseNative]::mouse_event($up,0,0,0,[UIntPtr]::Zero)
}
function KeyPress([string]$key) {
  $map = @{ ENTER=0x0D; TAB=0x09; ESCAPE=0x1B; SPACE=0x20; BACKSPACE=0x08; DELETE=0x2E; UP=0x26; DOWN=0x28; LEFT=0x25; RIGHT=0x27; HOME=0x24; END=0x23; PAGEUP=0x21; PAGEDOWN=0x22 }
  $vk = [byte]$map[$key]
  if (-not $vk) { throw "Unsupported key" }
  [ClineComputerUseNative]::keybd_event($vk,0,0,[UIntPtr]::Zero)
  [ClineComputerUseNative]::keybd_event($vk,0,2,[UIntPtr]::Zero)
}
if ($payload.action -eq 'inspect_process') {
  $expected = ([string]$payload.expectedPath).ToLowerInvariant()
  $foreground = ForegroundInfo
  $match = Get-Process | Where-Object { (ProcessPath $_.Id) -and (ProcessPath $_.Id).ToLowerInvariant() -eq $expected } | Select-Object -First 1
  if ($foreground.path -and $foreground.path.ToLowerInvariant() -eq $expected) { $match = Get-Process -Id $foreground.pid }
  if (-not $match) { throw "The allowlisted application is not running" }
  @{ pid = [int]$match.Id; path = (ProcessPath $match.Id); title = $match.MainWindowTitle; foreground = ($foreground.pid -eq $match.Id) } | ConvertTo-Json -Compress
  exit 0
}
$foreground = AssertAllowedForeground
$root = [System.Windows.Automation.AutomationElement]::FromHandle($foreground.hwnd)
if (-not $root) { throw "Unable to inspect the foreground window" }
switch ([string]$payload.action) {
  'observe' {
    $elements = New-Object System.Collections.Generic.List[object]
    $all = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
    $limit = [Math]::Min($all.Count, 200)
    for ($i = 0; $i -lt $limit; $i++) {
      $el = $all.Item($i)
      if ($el.Current.IsPassword) { continue }
      $r = $el.Current.BoundingRectangle
      $elements.Add(@{ automationId=$el.Current.AutomationId; name=$el.Current.Name; controlType=$el.Current.ControlType.ProgrammaticName.Replace('ControlType.',''); enabled=$el.Current.IsEnabled; offscreen=$el.Current.IsOffscreen; x=[int]$r.X; y=[int]$r.Y; width=[int]$r.Width; height=[int]$r.Height })
    }
    $screenshot = $null
    if ($payload.screenshotPath) {
      $rect = New-Object ClineComputerUseNative+RECT
      if ([ClineComputerUseNative]::GetWindowRect($foreground.hwnd, [ref]$rect)) {
        $width = [Math]::Max(1, $rect.Right - $rect.Left); $height = [Math]::Max(1, $rect.Bottom - $rect.Top)
        $bitmap = New-Object System.Drawing.Bitmap($width, $height)
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        try { $graphics.CopyFromScreen($rect.Left, $rect.Top, 0, 0, $bitmap.Size); $bitmap.Save([string]$payload.screenshotPath, [System.Drawing.Imaging.ImageFormat]::Png); $screenshot = [string]$payload.screenshotPath } finally { $graphics.Dispose(); $bitmap.Dispose() }
      }
    }
    @{ pid=$foreground.pid; executable=$foreground.path; title=$foreground.title; screenshotPath=$screenshot; elements=$elements } | ConvertTo-Json -Depth 6 -Compress
  }
  'click' {
    if ($payload.selector) {
      $target = FindTarget $root
      if (-not $target) { throw "No matching accessibility element found" }
      if ($target.Current.IsPassword) { throw "Password controls cannot be targeted" }
      $pattern = $null
      if ($target.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$pattern)) { $pattern.Invoke() }
      else { $r=$target.Current.BoundingRectangle; ClickAt ([int]($r.X+$r.Width/2)) ([int]($r.Y+$r.Height/2)) ([string]$payload.button) }
    } else {
      ClickAt ([int]$payload.x) ([int]$payload.y) ([string]$payload.button)
    }
    @{ ok=$true; action='click'; pid=$foreground.pid } | ConvertTo-Json -Compress
  }
  'type' {
    $target = FindTarget $root
    if (-not $target) { throw "No focused or matching accessibility element found" }
    if ($target.Current.IsPassword) { throw "Typing into password controls is not supported" }
    $pattern = $null
    if (-not $target.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$pattern)) { throw "Target does not expose a safe ValuePattern" }
    if ($pattern.Current.IsReadOnly) { throw "Target is read-only" }
    $pattern.SetValue([string]$payload.text)
    @{ ok=$true; action='type'; characters=([string]$payload.text).Length; pid=$foreground.pid } | ConvertTo-Json -Compress
  }
  'key' { KeyPress ([string]$payload.key); @{ ok=$true; action='key'; key=$payload.key; pid=$foreground.pid } | ConvertTo-Json -Compress }
  'scroll' {
    if ($null -ne $payload.x -and $null -ne $payload.y) { [void][ClineComputerUseNative]::SetCursorPos([int]$payload.x,[int]$payload.y) }
    [ClineComputerUseNative]::mouse_event(0x0800,0,0,[uint32]([int]$payload.delta),[UIntPtr]::Zero)
    @{ ok=$true; action='scroll'; delta=[int]$payload.delta; pid=$foreground.pid } | ConvertTo-Json -Compress
  }
  'wait' {
    $deadline = [DateTime]::UtcNow.AddMilliseconds([int]$payload.timeoutMs)
    do { $target = FindTarget $root; if ($target) { break }; Start-Sleep -Milliseconds 100 } while ([DateTime]::UtcNow -lt $deadline)
    @{ ok=($null -ne $target); action='wait'; pid=$foreground.pid } | ConvertTo-Json -Compress
  }
  default { throw "Unsupported computer-use action" }
}
`;

async function runPowerShell(
	payload: Record<string, unknown>,
	signal?: AbortSignal,
): Promise<Record<string, unknown>> {
	const encoded = Buffer.from(POWERSHELL_SCRIPT, "utf16le").toString("base64");
	return await new Promise((resolve, reject) => {
		const child = spawn(
			"powershell.exe",
			["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
			{ stdio: ["pipe", "pipe", "pipe"], windowsHide: true },
		);
		let stdout = "";
		let stderr = "";
		const timeout = setTimeout(() => child.kill(), POWERSHELL_TIMEOUT_MS);
		const abort = () => child.kill();
		signal?.addEventListener("abort", abort, { once: true });
		child.stdout.setEncoding("utf8").on("data", (chunk) => {
			if (stdout.length < 2_000_000) stdout += chunk;
		});
		child.stderr.setEncoding("utf8").on("data", (chunk) => {
			if (stderr.length < 32_000) stderr += chunk;
		});
		child.on("error", (error) => {
			clearTimeout(timeout);
			signal?.removeEventListener("abort", abort);
			reject(error);
		});
		child.on("close", (code) => {
			clearTimeout(timeout);
			signal?.removeEventListener("abort", abort);
			if (signal?.aborted)
				return reject(new Error("Computer action cancelled"));
			if (code !== 0)
				return reject(
					new Error(stderr.trim() || `PowerShell exited with ${code}`),
				);
			try {
				resolve(JSON.parse(stdout.trim()) as Record<string, unknown>);
			} catch {
				reject(new Error("Computer-control helper returned invalid JSON"));
			}
		});
		child.stdin.end(JSON.stringify(payload));
	});
}

export class DesktopComputerUseManager {
	private readonly sessions = new Map<string, SessionRecord>();
	private readonly platform: NodeJS.Platform;
	private readonly runner: PowerShellRunner;
	private readonly now: () => number;

	constructor(private readonly options: ComputerUseManagerOptions) {
		this.platform = options.platform ?? process.platform;
		this.runner = options.runPowerShell ?? runPowerShell;
		this.now = options.now ?? Date.now;
	}

	readonly executor: ComputerUseExecutor = async (input, context) =>
		this.execute(input, context);

	list(ownerSessionId?: string): ComputerUseStateItem[] {
		this.expire();
		return [...this.sessions.values()]
			.filter(
				(item) => !ownerSessionId || item.ownerSessionId === ownerSessionId,
			)
			.map(
				({ createdAtMs: _createdAtMs, screenshotPaths: _paths, ...item }) =>
					item,
			);
	}

	async takeOver(ownerSessionId?: string): Promise<number> {
		const matches = [...this.sessions.values()].filter(
			(item) => !ownerSessionId || item.ownerSessionId === ownerSessionId,
		);
		for (const item of matches) await this.stop(item);
		return matches.length;
	}

	private emit(): void {
		this.options.onStateChanged?.(this.list());
	}

	private expire(): void {
		for (const session of this.sessions.values()) {
			if (this.now() - session.createdAtMs > MAX_SESSION_AGE_MS)
				void this.stop(session);
		}
	}

	private requireSession(id: string, owner: string): SessionRecord {
		this.expire();
		const session = this.sessions.get(id);
		if (!session || session.ownerSessionId !== owner) {
			throw new Error("Unknown or unowned computer-control session");
		}
		if (session.actionCount >= MAX_ACTIONS) {
			throw new Error(
				"Computer-control action limit reached; start a new session",
			);
		}
		return session;
	}

	private async stop(session: SessionRecord): Promise<void> {
		this.sessions.delete(session.computerSessionId);
		session.status = "stopped";
		await rm(
			join(resolveClineDataDir(), "computer-use", session.computerSessionId),
			{
				recursive: true,
				force: true,
			},
		).catch(() => {});
		this.emit();
	}

	private async execute(
		input: ComputerUseInput,
		context: AgentToolContext,
	): Promise<string> {
		const owner = requireOwner(context);
		if (input.action === "list")
			return jsonResult({ sessions: this.list(owner) });
		if (input.action === "start") {
			if (this.platform !== "win32")
				throw new Error("computer_use currently supports Windows only");
			const settings = this.options.readSettings();
			if (!settings.computerUseEnabled)
				throw new Error("Computer use is disabled in Desktop settings");
			const requested = canonicalExecutable(input.executable);
			const allowed = settings.computerUseAllowedApplications.find(
				(candidate) => canonicalExecutable(candidate) === requested,
			);
			if (!allowed)
				throw new Error("Executable is not in the computer-use allowlist");
			const inspected = await this.runner(
				{ action: "inspect_process", expectedPath: allowed },
				context.signal,
			);
			const processId = Number(inspected.pid);
			if (!Number.isInteger(processId) || processId <= 0)
				throw new Error("Unable to identify the allowlisted process");
			const computerSessionId = randomUUID();
			const createdAtMs = this.now();
			const record: SessionRecord = {
				computerSessionId,
				ownerSessionId: owner,
				executable: allowed,
				processId,
				status: "active",
				createdAt: new Date(createdAtMs).toISOString(),
				createdAtMs,
				actionCount: 0,
				screenshotPaths: [],
			};
			this.sessions.set(computerSessionId, record);
			this.emit();
			return jsonResult({
				...record,
				createdAtMs: undefined,
				screenshotPaths: undefined,
				foreground: inspected.foreground === true,
			});
		}
		const session = this.requireSession(input.computer_session_id, owner);
		if (input.action === "stop") {
			await this.stop(session);
			return jsonResult({
				computerSessionId: session.computerSessionId,
				stopped: true,
			});
		}
		const currentSettings = this.options.readSettings();
		if (
			!currentSettings.computerUseEnabled ||
			!currentSettings.computerUseAllowedApplications.some(
				(candidate) =>
					canonicalExecutable(candidate) ===
					canonicalExecutable(session.executable),
			)
		) {
			await this.stop(session);
			throw new Error(
				"Computer use was disabled or the application was removed from the allowlist",
			);
		}
		session.actionCount += 1;
		const payload: Record<string, unknown> = {
			...input,
			expectedPath: session.executable,
			expectedPid: session.processId,
		};
		if (input.action === "observe" && input.include_screenshot !== false) {
			const directory = join(
				resolveClineDataDir(),
				"computer-use",
				session.computerSessionId,
			);
			await mkdir(directory, { recursive: true, mode: 0o700 });
			payload.screenshotPath = join(
				directory,
				`${String(session.actionCount).padStart(4, "0")}.png`,
			);
		}
		if (input.action === "wait") payload.timeoutMs = input.timeout_ms ?? 5_000;
		const result = await this.runner(payload, context.signal);
		if (typeof result.screenshotPath === "string") {
			const screenshotPath = result.screenshotPath;
			const bytes = await readFile(screenshotPath);
			result.screenshot = {
				path: screenshotPath,
				bytes: bytes.length,
				sha256: createHash("sha256").update(bytes).digest("hex"),
			};
			session.screenshotPaths.push(screenshotPath);
			while (session.screenshotPaths.length > MAX_SCREENSHOTS) {
				const expired = session.screenshotPaths.shift();
				if (expired) await rm(expired, { force: true }).catch(() => {});
			}
		}
		this.emit();
		return jsonResult({
			computerSessionId: session.computerSessionId,
			application: basename(session.executable),
			actionCount: session.actionCount,
			...result,
		});
	}
}
