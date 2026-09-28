import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DesktopComputerUseManager } from "../sidecar/computer-use-manager";
import type { DesktopSettings } from "../sidecar/desktop-settings";

const windows = process.platform === "win32" && process.arch === "x64";
const powershell =
  process.env.SystemRoot &&
  path.join(
    process.env.SystemRoot,
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe",
  );
let root = "";
let marker = "";
let fixture: ChildProcess | undefined;
let fixtureStderr = "";
let manager: DesktopComputerUseManager | undefined;
let computerSessionId = "";

const context = {
  sessionId: "windows-computer-use-fixture",
  agentId: "fixture-agent",
  iteration: 1,
};

function terminateFixture(): void {
  if (!fixture?.pid || fixture.exitCode !== null || fixture.signalCode !== null)
    return;
  spawnSync("taskkill.exe", ["/PID", String(fixture.pid), "/T", "/F"], {
    stdio: "ignore",
    windowsHide: true,
    timeout: 10_000,
  });
}

async function waitFor(check: () => boolean, label: string): Promise<void> {
  for (let attempt = 0; attempt < 300; attempt += 1) {
    if (check()) return;
    await Bun.sleep(100);
  }
  throw new Error(`Timed out waiting for ${label}`);
}

describe.skipIf(!windows)("deterministic Windows computer-use fixture", () => {
  beforeAll(async () => {
    if (!powershell || !existsSync(powershell))
      throw new Error("Windows PowerShell fixture host was not found");
    root = mkdtempSync(path.join(tmpdir(), "cline-computer-use-fixture-"));
    marker = path.join(root, "committed.txt");
    const ready = path.join(root, "ready.txt");
    const script = path.join(root, "fixture.ps1");
    writeFileSync(
      script,
      `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Cline deterministic computer-use fixture'
$form.Name = 'fixtureWindow'
$form.Size = New-Object System.Drawing.Size(560,360)
$form.StartPosition = 'CenterScreen'
$form.TopMost = $true
$inputBox = New-Object System.Windows.Forms.TextBox
$inputBox.Name = 'inputBox'
$inputBox.AccessibleName = 'Fixture input'
$inputBox.Location = New-Object System.Drawing.Point(30,35)
$inputBox.Size = New-Object System.Drawing.Size(450,30)
$passwordBox = New-Object System.Windows.Forms.TextBox
$passwordBox.Name = 'passwordBox'
$passwordBox.AccessibleName = 'Fixture password'
$passwordBox.Location = New-Object System.Drawing.Point(30,90)
$passwordBox.Size = New-Object System.Drawing.Size(450,30)
$passwordBox.UseSystemPasswordChar = $true
$commit = New-Object System.Windows.Forms.Button
$commit.Name = 'commitButton'
$commit.AccessibleName = 'Fixture commit'
$commit.Text = 'Commit deterministic value'
$commit.Location = New-Object System.Drawing.Point(30,145)
$commit.Size = New-Object System.Drawing.Size(220,36)
$commit.Add_Click({ [IO.File]::WriteAllText('${marker.replaceAll("'", "''")}', $inputBox.Text) })
$form.Controls.AddRange(@($inputBox,$passwordBox,$commit))
$form.Add_Shown({
  [IO.File]::WriteAllText('${ready.replaceAll("'", "''")}', 'ready')
  $form.Activate()
})
[void]$form.ShowDialog()
`,
    );
    fixture = spawn(
      powershell,
      [
        "-NoLogo",
        "-NoProfile",
        "-WindowStyle",
        "Hidden",
        "-ExecutionPolicy",
        "Bypass",
        "-STA",
        "-File",
        script,
      ],
      { stdio: ["ignore", "ignore", "pipe"], windowsHide: true },
    );
    fixture.stderr?.setEncoding("utf8").on("data", (chunk) => {
      if (fixtureStderr.length < 16_000) fixtureStderr += chunk;
    });
    try {
      await waitFor(
        () =>
          existsSync(ready) ||
          fixture?.exitCode !== null ||
          fixture?.signalCode !== null,
        "fixture window",
      );
    } catch (error) {
      throw new Error(
        `${error instanceof Error ? error.message : String(error)}${fixtureStderr.trim() ? `: ${fixtureStderr.trim()}` : ""}`,
      );
    }
    if (!existsSync(ready)) {
      throw new Error(
        `Fixture exited before opening${fixtureStderr.trim() ? `: ${fixtureStderr.trim()}` : ""}`,
      );
    }
    await Bun.sleep(500);

    const settings: DesktopSettings = {
      cloudSessionsEnabled: false,
      customAiInstructions: "",
      computerUseEnabled: true,
      computerUseAllowedApplications: [powershell],
    };
    manager = new DesktopComputerUseManager({
      platform: "win32",
      readSettings: () => settings,
    });
    const started = JSON.parse(
      await manager.executor(
        { action: "start", executable: powershell, acknowledge_risk: true },
        context,
      ),
    ) as { computerSessionId: string; foreground: boolean };
    expect(started.foreground).toBe(true);
    computerSessionId = started.computerSessionId;
  }, 45_000);

  afterAll(async () => {
    if (manager && computerSessionId) {
      await manager
        .executor(
          { action: "stop", computer_session_id: computerSessionId },
          context,
        )
        .catch(() => {});
    }
    terminateFixture();
    if (root) rmSync(root, { recursive: true, force: true });
  });

  test("observes, types, invokes, and blocks password controls", async () => {
    if (!manager) throw new Error("fixture manager was not initialized");
    const observed = JSON.parse(
      await manager.executor(
        {
          action: "observe",
          computer_session_id: computerSessionId,
          include_screenshot: false,
        },
        context,
      ),
    ) as { elements: unknown[] };
    if (observed.elements.length === 0) {
      console.warn(
        "Windows runner exposes no interactive UI Automation tree; foreground scoping passed and interactive fixture actions were skipped",
      );
      return;
    }
    const waited = JSON.parse(
      await manager.executor(
        {
          action: "wait",
          computer_session_id: computerSessionId,
          selector: { control_type: "Edit" },
          timeout_ms: 5_000,
        },
        context,
      ),
    ) as { ok: boolean };
    expect(waited.ok).toBe(true);

    await manager.executor(
      {
        action: "type",
        computer_session_id: computerSessionId,
        selector: { control_type: "Edit" },
        text: "deterministic-value",
        verify: {
          selector: { control_type: "Button" },
          state: "exists",
          timeout_ms: 5_000,
        },
      },
      context,
    );
    await manager.executor(
      {
        action: "key",
        computer_session_id: computerSessionId,
        key: "TAB",
      },
      context,
    );
    await expect(
      manager.executor(
        {
          action: "type",
          computer_session_id: computerSessionId,
          text: "must-not-be-stored",
        },
        context,
      ),
    ).rejects.toThrow("password");
    await manager.executor(
      {
        action: "key",
        computer_session_id: computerSessionId,
        key: "TAB",
      },
      context,
    );
    await manager.executor(
      {
        action: "key",
        computer_session_id: computerSessionId,
        key: "ENTER",
      },
      context,
    );
    await waitFor(() => existsSync(marker), "committed fixture value");
    expect(readFileSync(marker, "utf8")).toBe("deterministic-value");
  }, 30_000);
});
