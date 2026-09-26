# Cline Enhanced custom fork

This file is the durable customization ledger for this repository. The source on `main` is the source of truth: every installer must be built from a committed revision, and custom behavior must never exist only as an uncommitted patch or generated build output.

## Build policy

- Produce an **unsigned Windows x64 NSIS `setup.exe`** for private use and testing.
- Do not publish a GitHub Release from the custom installer workflow.
- Record the exact Git commit in `BUILD-INFO.txt` and retain the installer as a workflow artifact.
- Include this ledger in every installer artifact.
- Run `scripts/verify-custom-fork.ts` before every custom Windows build. If a customization is intentionally renamed or replaced, update both the implementation and the verifier in the same commit.

## Preserved customizations

### AI task execution UI

- Polished sticky AI task report with progress, repair, verification, and execution states.
- Typed task lifecycle events persisted in chat metadata.
- Stable step IDs map tool evidence and durations to their exact plan steps.
- Structured step kinds take priority; text-label heuristics remain only as compatibility fallback behavior.
- One active step is enforced, failed or malformed plan updates are ignored, and an older turn's plan is not reused for a new request.
- Copyable task reports for issue reports and debugging.

Primary files:

- `apps/examples/desktop-app/sidecar/context.ts`
- `apps/examples/desktop-app/sidecar/chat-session.ts`
- `apps/examples/desktop-app/webview/lib/chat-schema.ts`
- `apps/examples/desktop-app/webview/lib/task-report.ts`
- `apps/examples/desktop-app/webview/components/views/chat/task-report-panel.tsx`

### Permanent Custom AI Instructions

- Visible editor under **Settings → General → Custom AI instructions**.
- Stored in the desktop settings file and retained across app restarts.
- Added to every new local AI session before project and session rules.
- Maximum length: 50,000 characters.

Primary files:

- `apps/examples/desktop-app/sidecar/desktop-settings.ts`
- `apps/examples/desktop-app/sidecar/commands.ts`
- `apps/examples/desktop-app/sidecar/chat-session.ts`
- `apps/examples/desktop-app/webview/components/views/settings/settings-view.tsx`

### Windows reliability

- Canonical Windows paths are used for temporary Git worktrees; short-path aliases, slash direction, and case differences do not break cleanup or tests.
- Worktree deletion resolves the repository root, removes the worktree, removes a canonical-path fallback when Git alias matching fails, prunes stale metadata, and independently deletes `refs/heads/cline/<id>`.
- Sidecar stores are closed during tests and logging fixtures work across platforms.
- Desktop, example VS Code, and repository-root Vitest configurations are native ESM in `vitest.config.mts`; the legacy CommonJS-loaded `.ts` configs must not be restored.
- React image-attachment tests explicitly enable the React `act(...)` environment.
- The custom installer validates type safety, sidecar behavior, task reports, focused customization tests, installer configuration, installation, startup, and unsigned binaries.

Primary files:

- `apps/examples/desktop-app/sidecar/commands.ts`
- `apps/examples/desktop-app/sidecar/commands-git-worktree.test.ts`
- `vitest.config.mts`
- `sdk/tsconfig.json`
- `apps/examples/desktop-app/vitest.config.mts`
- `apps/examples/desktop-app/package.json`
- `apps/examples/vscode/vitest.config.mts`
- `apps/examples/vscode/package.json`
- `apps/examples/desktop-app/webview/lib/image-attachments.test.ts`
- `.github/workflows/build-custom-windows-installer.yml`

### Command execution performance

- Command execution favors structured direct argv calls when shell syntax is unnecessary, immediately emits the first output chunk, records duration, time-to-first-output, and output-volume telemetry without command text, and sends the command preview only once instead of repeating it on every progress event. The full implementation contract and phased roadmap are recorded in `docs/CODEX_LIKE_COMMAND_EXECUTION.md`.

Primary files:

- `sdk/packages/core/src/extensions/tools/schemas.ts`
- `sdk/packages/core/src/extensions/tools/definitions.ts`
- `sdk/packages/core/src/extensions/tools/executors/bash.ts`
- `docs/CODEX_LIKE_COMMAND_EXECUTION.md`

### Specialized tools

- Android automation includes device selection, screen metadata, UI hierarchy, validated touch/swipe/key/text actions, foreground-package guards, and before/after screenshot evidence.
- Unrestricted `adb shell` is intentionally available for already-authorized devices and requires `acknowledge_risk: true`; see `docs/ANDROID_DEVICE_AUTOMATION.md`.
- Reverse-engineering and Smali workflows, with cross-platform IDA/Ghidra discovery, executable/version/capability reporting, version-and-option-aware cache reuse, complete output draining, process-tree cancellation, and verified GUI startup.
- A separate opt-in `live_debugger` tool provides explicitly acknowledged, bounded, one-shot GDB/LLDB launch and attach workflows with command-safe breakpoint and address validation; see `docs/LIVE_DEBUGGING.md`.
- APK comparison improvements.
- Codex-compatible tool calls and binary attachment handling.

Primary files:

- `sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts`
- `sdk/packages/core/src/extensions/tools/executors/supervised-process.ts`
- `sdk/packages/core/src/extensions/tools/executors/live-debugger.ts`
- `docs/LIVE_DEBUGGING.md`

## Required validation

Before an installer build, preserve and run the checks encoded by `.github/workflows/build-custom-windows-installer.yml`:

1. `bun scripts/verify-custom-fork.ts`
2. SDK build and desktop type-check
3. Desktop sidecar regression suite
4. Windows installer configuration test
5. AI task-report tests
6. Focused customization tests
7. Unsigned NSIS packaging and artifact upload

Do not hide a new regression by weakening assertions or making a required customization check non-blocking. Fix the implementation or update the expected contract only when behavior changes intentionally.

## Rules for future AI assistants

1. Read this file, `/AGENTS.md`, and `/.github/copilot-instructions.md` before changing desktop, sidecar, task-report, tool, or installer behavior.
2. Preserve these features unless the user explicitly asks to replace or remove one.
3. Commit every durable source change to the repository before triggering a build.
4. Never rely on local-only files, an uncommitted diff, generated `dist/` output, or a workflow workspace as the only copy of a customization.
5. Update this ledger and `scripts/verify-custom-fork.ts` in the same commit when adding, replacing, renaming, or intentionally removing custom behavior.
6. Run the relevant focused tests, desktop type-check, repository lint, and custom-fork verifier.
7. Keep the personal installer unsigned and artifact-only; do not create a release unless the user explicitly changes that policy.
