# Desktop execution and analysis workbench

The desktop workspace combines source review, searchable project files, resumable terminals, static reverse engineering, supervised debugging, tool health, and evidence output in one Codex-style surface.

## Opening the workspace

Open any local chat and select **Workspace** in the header. The workspace has four top-level tabs:

- **Changes** — review, stage, unstage, or confirmation-gated revert.
- **Files** — search project paths and open, preview, reveal, or copy an exact path.
- **Terminal** — manage resumable interactive host terminals.
- **Analysis** — static analysis, debugger actions, tool discovery, and evidence.

Remote SSH chats retain their existing agent tools, but the direct desktop Terminal and Analysis tabs are intentionally local-only.

## Integrated terminal

The Terminal tab reuses the host-scoped `ProcessSessionManager` and Bun's native PTY/ConPTY boundary. A terminal has a stable process ID, bounded and secret-redacted output, stdin, resize metadata, interrupt/terminate controls, and conservative restart recovery.

Starting a terminal requires a confirmation explaining that it runs on the host and is not an operating-system sandbox. The UI starts only a known shell profile; subsequent commands are typed explicitly by the user. Windows profiles are PowerShell, Command Prompt, and WSL. Unix hosts use the configured shell, bash, or zsh.

## Static reverse engineering

The Analyze view exposes a strict subset of `reverse_engineer` operations:

- inspect
- scan strings
- forensic report
- APK security report and signature verification
- headless analysis and decompilation
- Smali disassembly

Relative paths resolve from the current workspace. Existing executor controls still enforce absolute targets, bounded output, managed output roots, hashing, cancellation, cache reuse, and safe regular expressions. Arbitrary analysis scripts, APK rebuilding, and extraction are not accepted by this direct UI.

**Open GUI** uses the executor's existing verified IDA/Ghidra/JADX launcher. It requires an explicit click and never launches the analyzed target itself.

## Supervised debugging

The Debug view exposes the existing one-shot GDB, LLDB, and CDB executor. Every operation requires the user to confirm that the target is owned or authorized. Continue and step require a second execution-control confirmation.

The workbench does not maintain a hidden persistent debugger, accept arbitrary debugger command strings, elevate privileges, or enable remote debugging. Crash-dump inspection remains non-executing.

## Tool health and evidence

Tool Health reports detected engines, debuggers, executable paths, versions, capabilities, and setup recommendations. Results are generated from live discovery rather than assumed from configuration.

The evidence pane preserves structured results such as artifact hashes, architecture, entry points, findings, generated report paths, debugger state, and missing-tool warnings. It does not invent unavailable results.

## Security boundary

Permission profiles are capability guards, not native containment. Integrated terminals and approved debugger launches execute with the current desktop user's operating-system permissions. Unknown or hostile executables must not be launched on the host.

For malware detonation, use a separately provisioned disposable Windows Sandbox or Hyper-V virtual machine with networking disabled and no personal credentials. This repository does not silently enable Windows optional features, create virtual machines, install IDA/Ghidra plugins, or bypass application licensing. Those boundaries require explicit machine administration and independently reviewed companion packages.

## Primary implementation files

- `apps/examples/desktop-app/webview/components/views/chat/diff-view.tsx`
- `apps/examples/desktop-app/webview/components/views/chat/workspace-terminal.tsx`
- `apps/examples/desktop-app/webview/components/views/chat/analysis-workbench.tsx`
- `apps/examples/desktop-app/sidecar/commands.ts`
- `sdk/packages/core/src/extensions/tools/executors/process-session-manager.ts`
- `sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts`
- `sdk/packages/core/src/extensions/tools/executors/live-debugger.ts`

## Required validation

1. Build the SDK.
2. Type-check the desktop app.
3. Run the desktop sidecar and chat UI suites.
4. Run `commands-workbench.test.ts`.
5. Run the custom-fork preservation verifier.
6. Run the Windows ConPTY smoke test and installer workflow before distributing an `.exe`.
