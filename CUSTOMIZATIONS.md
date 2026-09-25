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
- Transcript parsing remains only as compatibility fallback behavior.
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

- Canonical Windows paths are used for temporary Git worktrees.
- Short-path aliases, slash direction, and case differences do not break cleanup or tests.
- The custom installer validates type safety, task reports, customization tests, installer configuration, installation, startup, and unsigned binaries.

### Specialized tools

- Supervised Android device debugging.
- Reverse-engineering and Smali workflows.
- APK comparison improvements.
- Codex-compatible tool calls and binary attachment handling.

## Rules for future AI assistants

1. Read this file before changing desktop, sidecar, task-report, tool, or installer behavior.
2. Preserve these features unless the user explicitly asks to replace or remove one.
3. Commit every durable source change to the repository before triggering a build.
4. Never rely on local-only files, an uncommitted diff, or generated `dist/` output as the only copy of a customization.
5. Update this ledger when adding, replacing, or intentionally removing custom behavior.
6. Run the relevant focused tests, desktop type-check, repository lint, and custom-fork verifier.
