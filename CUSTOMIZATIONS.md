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

- Cline account sign-in follows the current official desktop WorkOS device-code flow: obtain device authorization, publish the confirmation code and exact verification URL to the webview before browser handoff, open the default browser, poll for completion, and register the resulting tokens with the Cline API. No local callback server is required. Windows URL launching uses `rundll32 url.dll,FileProtocolHandler`, and every sign-in surface retains selectable Open and Copy fallbacks if the OS handoff fails.
- Canonical Windows paths are used for temporary Git worktrees; short-path aliases, slash direction, and case differences do not break cleanup or tests.
- Worktree deletion resolves the repository root, removes the worktree, removes a canonical-path fallback when Git alias matching fails, prunes stale metadata, and independently deletes `refs/heads/cline/<id>`.
- Managed task worktrees persist their identity, source revision/repository, base branch, generated branch, and retention decision. The chat exposes Apply to Local, Create Branch, Open PR, Keep, and explicitly confirmed Discard actions after checking both checkouts for dirty or conflicting state.
- Parallel writing teammates can request an `isolated-writer` workspace. Core creates a handoff-compatible managed Git worktree, routes that teammate's built-in tools and workspace prompt to it, persists ownership across restart recovery, records changed files on async runs, and flags cross-agent path overlaps before handoff. Settled overlap evidence is persisted on the writer child session; the desktop roster blocks handoff visibly, lists conflicting paths, and opens that writer's worktree/session for review and resolution.
- Apply to Local accepts committed work only and aborts a conflicting cherry-pick; Keep prevents session deletion from cleaning the worktree; cleanup remains idempotent and never deletes renamed/user-created branches.
- Sidecar stores are closed during tests and logging fixtures work across platforms.
- Desktop, example VS Code, and repository-root Vitest configurations are native ESM in `vitest.config.mts`; the legacy CommonJS-loaded `.ts` configs must not be restored.
- React image-attachment tests explicitly enable the React `act(...)` environment.
- The custom installer validates type safety, sidecar behavior, task reports, focused customization tests, installer configuration, installation, startup, and unsigned binaries.
- Installed-sidecar smoke validation executes the installed `code-sidecar.exe` against an isolated Hub, waits for its ready contract, and checks `/health`; it does not depend on a racy one-time Windows process-name/path snapshot while the sidecar transitions into its detached daemon.
- The sidecar readiness gate uses the same 30-second cold-start window as the desktop host. Once an installer has been collected successfully, the workflow records the smoke outcome and uploads the private test artifact even when a later smoke assertion fails, while retaining the failed job conclusion.

Primary files:

- `apps/examples/desktop-app/sidecar/commands.ts`
- `apps/examples/desktop-app/sidecar/commands-git-worktree.test.ts`
- `apps/examples/desktop-app/webview/components/views/chat/worktree-handoff-bar.tsx`
- `docs/WORKTREE_HANDOFF.md`
- `vitest.config.mts`
- `sdk/tsconfig.json`
- `apps/examples/desktop-app/vitest.config.mts`
- `apps/examples/desktop-app/package.json`
- `apps/examples/vscode/vitest.config.mts`
- `apps/examples/vscode/package.json`
- `apps/examples/desktop-app/webview/lib/image-attachments.test.ts`
- `apps/examples/desktop-app/sidecar/oauth-login.ts`
- `apps/examples/desktop-app/sidecar/oauth-login.test.ts`
- `apps/examples/desktop-app/webview/hooks/use-oauth-user-code.ts`
- `apps/examples/desktop-app/webview/components/oauth-authorization-prompt.tsx`
- `apps/examples/desktop-app/webview/components/views/onboarding/onboarding-view.test.tsx`
- `.github/workflows/build-custom-windows-installer.yml`

### Command execution performance

- Command execution favors structured direct argv calls when shell syntax is unnecessary, immediately emits the first output chunk, records duration, time-to-first-output, and output-volume telemetry without command text, and sends the command preview only once instead of repeating it on every progress event. The implemented behavior contract is recorded in `docs/CODEX_LIKE_COMMAND_EXECUTION.md`.
- The SDK exposes a host-scoped `process_session` tool backed by `ProcessSessionManager`, with direct argv start, stable process IDs, owner isolation, cursor-based reads, writable stdin, terminal resize, portable process-tree signals, explicit close, bounded head/tail output, global/per-owner limits, and completed-session expiry. Pipe execution remains the default; `interactive: true` attaches Bun's native Unix PTY or Windows ConPTY boundary and records terminal dimensions. Act and Full Access modes enable it; Plan mode disables it so it cannot bypass the read-only command guard. Existing `run_commands` behavior remains unchanged.
- Active process sessions persist only owner, PID, kernel start token, working directory, and terminal metadata. After an unexpected host restart, exact start-token revalidation restores conservative status/signal control without fabricating lost stdin, terminal, or output handles. PID-only recovery and identity mismatches fail closed.
- The unsigned Windows installer uses Bun 1.3.14 for native ConPTY while the repository's default Bun 1.3.13 remains sufficient for Unix PTY support. The installer workflow compiles and executes a real ConPTY input/resize smoke test before packaging, covering the embedded runtime used by the installed sidecar.
- Agent-started SDK processes withhold credential-bearing inherited and override environment variables unless the host explicitly grants an exact name. Known and pattern-detected secrets are redacted before streamed output, final results, errors, detached logs, or process-session buffers retain them. The policy and its remaining security boundary are documented in `docs/PROCESS_ENVIRONMENT_SECURITY.md`.
- Codex-grade process sessions, durable task state, worktree handoff, additive permission profiles, parallel orchestration, telemetry-gated PowerShell optimization, and optional scoped computer use must follow the phased contract in `docs/CODEX_PARITY_ROADMAP.md` and GitHub issue #20.
- Windows `run_commands` records a local, privacy-safe rolling baseline containing only execution mode, duration, time-to-first-output, output volume, success, and timestamp. It stores no command, arguments, cwd, environment, output, or identity. The prewarmed PowerShell worker remains disabled until at least 20 direct and 50 shell samples show both a 150 ms startup disadvantage and a 60% shell-startup share; a diagnostic command reports `collecting`, `not_recommended`, or `eligible` without enabling optimization.

Primary files:

- `sdk/packages/core/src/extensions/tools/schemas.ts`
- `sdk/packages/core/src/extensions/tools/definitions.ts`
- `sdk/packages/core/src/extensions/tools/executors/bash.ts`
- `sdk/packages/core/src/extensions/tools/executors/process-session-manager.ts`
- `sdk/packages/core/scripts/process-session-terminal-smoke.ts`
- `sdk/packages/core/src/extensions/tools/runtime.ts`
- `sdk/packages/core/src/extensions/tools/executors/process-environment-policy.ts`
- `docs/CODEX_LIKE_COMMAND_EXECUTION.md`
- `docs/PROCESS_ENVIRONMENT_SECURITY.md`
- `docs/CODEX_PARITY_ROADMAP.md`

### Additive permission profiles

- General settings expose host-enforced `read-only`, `workspace`,
  `workspace-network`, and `full-access` profiles for new local sessions.
  `full-access` is the desktop default when no preference has been stored,
  keeping the enforced boundary aligned with the existing Full Access/Yolo
  composer contract; restricted profiles remain explicit choices, and callers
  may still supply custom capability profiles through the SDK.
- Enforcement runs before approval and tool execution and is inherited by
  delegated agents.
- Restricted profiles fail closed for unclassified plugin/MCP tools and keep
  network, external-device/debugger, process-session, command, and file-write
  capabilities independently controllable.
- The preference is persisted in global settings and resolved by the sidecar,
  so a webview client cannot silently weaken it while starting a session.
- Capability profiles are not described as an operating-system sandbox; native
  filesystem and network containment remains separate follow-up work.

Primary files:

- `sdk/packages/core/src/extensions/tools/permission-profile.ts`
- `sdk/packages/core/src/extensions/tools/permission-profile.test.ts`
- `sdk/packages/core/src/runtime/orchestration/runtime-builder.ts`
- `sdk/packages/core/src/services/global-settings.ts`
- `apps/examples/desktop-app/sidecar/chat-session.ts`
- `apps/examples/desktop-app/webview/components/views/settings/settings-view.tsx`
- `docs/PERMISSION_PROFILES.md`

### Durable task execution

- Plan-tool updates are normalized by a host-side durable task state machine rather than trusted as presentation-only data. It enforces stable step identity, one active step, valid task transitions, terminal-state protection, and a repair/verification gate before work can advance past a failed or blocked step.
- Each session stores an atomic, versioned `task-state.json` artifact alongside its session data. Starting or re-attaching a session restores the canonical plan and active step so subsequent tool evidence remains associated after a desktop restart.
- Typed `plan.updated` events expose the canonical task state and transition history plus optional acceptance criteria, validation commands and results, owning agent, worktree, checkpoint run, artifacts, timestamps, repair attempt limits, skip reasons, and rollback metadata.
- In Full Access or explicitly auto-approved sessions, newly completed local steps execute their declared validation commands sequentially with bounded runtime and no retained command output. A failure marks the step failed, records only a sanitized status, and skips later commands until repair.
- Every skipped step requires a non-empty reason. Restoring a workspace checkpoint rewinds task steps associated with that checkpoint or a later run, and records the rollback in the task transition history.
- Sessions without `task-state.json` migrate the newest compatible projected `plan.updated` report once, then use the canonical artifact. Existing projection-only reports remain readable.
- See `docs/DURABLE_TASK_EXECUTION.md`. The unsigned installer workflow and private artifact-only release policy are unchanged.

Primary files:

- `apps/examples/desktop-app/sidecar/task-state-machine.ts`
- `apps/examples/desktop-app/sidecar/task-validation.ts`
- `apps/examples/desktop-app/sidecar/context.ts`
- `apps/examples/desktop-app/sidecar/chat-session.ts`
- `apps/examples/desktop-app/webview/lib/chat-schema.ts`
- `apps/examples/desktop-app/webview/lib/task-report.ts`
- `docs/DURABLE_TASK_EXECUTION.md`
- `docs/CODEX_PARITY_ROADMAP.md`

### Parallel-agent desktop controls

- Persisted subagent and team-task children appear in the parent session's agent
  roster with status, assigned task, latest activity, model, and transcript.
- Team-task rows expose host-controlled Stop, Guide, and Retry actions. These
  target one teammate without aborting the lead session.
- Guide uses the existing team mailbox and live steering boundary; Retry queues
  the latest failed, cancelled, or interrupted task with conversation
  continuity.
- Control requests are validated at the sidecar, Hub, root-session, and
  child-agent boundaries. Running synchronous `spawn_agent` and configured-agent
  children register host-owned control handles, expose Stop and Guide without
  aborting the lead, consume one-shot steering messages inside their own loop,
  and remove the handle atomically when the child settles. Retry remains limited
  to durable team runs; completed synchronous tool calls must be spawned again by
  the lead rather than replayed outside the parent tool contract.

Primary files:

- `sdk/packages/core/src/extensions/tools/team/multi-agent.ts`
- `sdk/packages/core/src/runtime/host/local-runtime-host.ts`
- `sdk/packages/core/src/hub/server/hub-server-transport.ts`
- `apps/examples/desktop-app/sidecar/commands.ts`
- `apps/examples/desktop-app/webview/hooks/use-session-agents.ts`
- `apps/examples/desktop-app/webview/components/agent-header.tsx`

### Specialized tools

- Android automation includes device selection, screen metadata, UI hierarchy, validated touch/swipe/key/text actions, foreground-package guards, and before/after screenshot evidence.
- Unrestricted `adb shell` is intentionally available for already-authorized devices and requires `acknowledge_risk: true`; see `docs/ANDROID_DEVICE_AUTOMATION.md`.
- Reverse-engineering and Smali workflows, with cross-platform IDA/Ghidra discovery, executable/version/capability reporting, version-and-option-aware cache reuse, complete output draining, process-tree cancellation, and verified GUI startup.
- Windows reverse-engineering discovery refreshes persisted tool environment variables and performs a bounded two-level search under `Documents`, `Program Files`, and `%LOCALAPPDATA%\Programs`; it does not scan arbitrary drive roots.
- IDA Hex-Rays batch decompilation uses a generated bounded IDAPython script, verifies a non-empty pseudocode artifact, and never passes output paths through the incompatible `-Ohexrays:<path>:ALL` form.
- A separate opt-in `live_debugger` tool provides explicitly acknowledged, bounded, one-shot GDB/LLDB launch and attach workflows with command-safe breakpoint and address validation; see `docs/LIVE_DEBUGGING.md`.
- APK comparison improvements.
- Codex-compatible tool calls and binary attachment handling.

Primary files:

- `sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts`
- `sdk/packages/core/src/extensions/tools/executors/supervised-process.ts`
- `sdk/packages/core/src/extensions/tools/executors/live-debugger.ts`
- `docs/LIVE_DEBUGGING.md`

### Scoped Windows computer use

- Desktop settings provide an explicit opt-in and exact absolute `.exe` allowlist. The host refuses every control-session start until enabled, and restricted permission profiles block the tool.
- `computer_use` supports owner-agent-scoped start/list/observe/click/type/key/scroll/wait/stop operations for one foreground allowlisted Windows application. Child agents cannot start control; owners may issue and revoke leases bounded by exact agent ID, expiry, and action count.
- Windows UI Automation selectors are preferred over coordinate fallback. Every action revalidates the foreground executable; password controls, protected Windows security processes, arbitrary key combinations, and clipboard typing are denied.
- Sessions are bounded to 200 actions and 15 minutes. Screenshot evidence is stored under the private Cline data directory, capped at 10 images per session, and deleted on stop or takeover.
- Local computer-use diagnostics persist aggregate counts and durations only; they exclude executable paths, titles, selectors, typed text, screenshots, and identities.
- Windows installer testing force-terminates timed-out process trees instead of waiting forever, then runs a deterministic WinForms fixture through real UI Automation when the Windows host exposes an interactive accessibility tree. Noninteractive hosted runners retain the foreground-scope assertion and report the action portion as a capability skip, without changing the workflow or publishing a release.
- The desktop displays a persistent Computer control active banner with a host-owned Stop and take over action.
- Structured tools, MCP, browser protocols, and the specialized Android/reverse-engineering tools remain preferred.

Primary files:

- `sdk/packages/core/src/extensions/tools/schemas.ts`
- `sdk/packages/core/src/extensions/tools/definitions.ts`
- `sdk/packages/core/src/extensions/tools/permission-profile.ts`
- `apps/examples/desktop-app/sidecar/computer-use-manager.ts`
- `apps/examples/desktop-app/sidecar/computer-use-metrics.ts`
- `apps/examples/desktop-app/scripts/computer-use-windows.test.ts`
- `apps/examples/desktop-app/sidecar/desktop-settings.ts`
- `apps/examples/desktop-app/webview/app/page.tsx`
- `apps/examples/desktop-app/webview/components/views/settings/settings-view.tsx`
- `docs/SCOPED_COMPUTER_USE.md`

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
