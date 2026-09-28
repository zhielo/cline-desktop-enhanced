# Codex-grade execution and task orchestration roadmap

This document is the durable architecture and delivery contract for GitHub issue #20. It applies Codex-inspired execution patterns without removing Cline Enhanced's multi-model support, specialized Android/reverse-engineering tools, or private unsigned Windows installer workflow.

## Invariants

- Preserve `.github/workflows/build-custom-windows-installer.yml` as an unsigned, artifact-only Windows x64 build for private use and testing.
- Do not publish a GitHub Release unless the user explicitly changes that policy.
- Preserve Full Access and every customization recorded in `CUSTOMIZATIONS.md`.
- Add safer permission profiles without silently weakening Full Access.
- Prefer structured tools and MCP integrations over visual computer control.
- Ship each phase independently with focused tests, compatibility notes, failure recovery, and customization-ledger updates.
- Do not claim prompt instructions are an operating-system sandbox.

## Phase 1 — Resumable process sessions

Parent issue: #21

Evolve command execution from spawn-and-collect into a host-scoped process service while retaining one-shot `run_commands` compatibility.

Implementation status: complete. `ProcessSessionManager` is exposed through the additive `process_session` tool in Act and Full Access modes. It provides direct argv start, stable IDs, owner-scoped lifecycle access, cursor reads, stdin, signals, terminal resize, explicit close, bounded head/tail output, resource limits, and expiry while preserving one-shot `run_commands`. Pipe execution remains the default; explicit interactive sessions use Bun's maintained Unix PTY/Windows ConPTY boundary and report their terminal dimensions. Plan mode deliberately disables the tool so it cannot bypass the read-only command guard. Active process identity is durably recorded without command arguments, environment, or output. After a host restart, recovery requires an exact kernel start-token match rather than PID identity alone; restored sessions expose status and signals while explicitly refusing unavailable stdin/resize operations and continuously revalidate identity until exit.

Required operations:

- start a one-shot or interactive process;
- return a stable execution ID;
- poll bounded output without replaying previously acknowledged chunks;
- write stdin;
- send supported signals or Windows control actions;
- close or terminate the process tree;
- list only processes owned by the requesting session;
- expire abandoned processes and logs within documented limits.

Safety and correctness requirements:

- validate process identity with a kernel start token rather than PID alone;
- cap concurrent sessions globally and per chat;
- retain bounded head/tail output and explicit omission counts;
- keep stdout and stderr stream identity;
- preserve timeout, cancellation, detachment, process-tree cleanup, and immediate first output;
- use Unix PTY and Windows ConPTY through a maintainable native boundary before advertising TTY semantics;
- keep direct argv execution outside shell or worker paths.

## Phase 2 — Durable task state machine

Parent issue: #22

Promote the current task-report projection into authoritative persisted task state.

Implementation status: complete. The desktop sidecar normalizes plan-tool updates through a transition-validating state machine and atomically persists a versioned task-state artifact per session. The artifact restores the current plan and active step after desktop restart or session re-attachment. Typed plan events carry canonical status, stable plan/step IDs, acceptance criteria, validation commands and results, owner, worktree, checkpoint run, artifacts, timestamps, skip reasons, repair limits, rollback metadata, and transition history. Invalid plans, duplicate/parallel active steps, unjustified skips, terminal-state regressions, and advancement past unrepaired failures are rejected. Full Access and explicitly auto-approved local sessions automatically execute newly declared validation commands with bounded runtime. Checkpoint restore rewinds associated task progress, and older projection-only sessions migrate once into canonical task state. See `docs/DURABLE_TASK_EXECUTION.md`.

Canonical states:

`planned → running → verifying → repairing → completed`

Exceptional states:

`waiting_for_user`, `blocked`, `failed`, `cancelled`, and justified `skipped`.

Every task step must support stable identity, acceptance criteria, validation commands, owning agent, worktree, artifacts, timestamps, repair attempt limits, and transition history. A failed validation cannot advance to later work until repaired, explicitly blocked, or skipped with a recorded reason.

## Phase 3 — Worktree-first isolation and handoff

Parent issue: #23

Implementation status: complete. New local tasks can run from an exact selected revision in a managed worktree with a durable identity and source metadata. The desktop detects dirty/conflicting state and exposes Apply to Local, Create Branch, Open PR, Keep, and explicitly confirmed Discard actions. Apply aborts cleanly on conflict, Keep survives session deletion, and idempotent cleanup independently removes stale generated branches while preserving user branches. See `docs/WORKTREE_HANDOFF.md`.

Required lifecycle:

- create from the selected local revision without polluting branches;
- associate one durable worktree identity with the task/thread;
- detect dirty or conflicting local state before handoff;
- offer Apply to Local, Create Branch, Open PR, Keep, and Discard;
- make cleanup idempotent and independently remove stale task branches;
- never discard uncommitted work without an explicit user action.

## Phase 4 — Additive permission profiles

Parent issue: #24

Implementation status: capability enforcement and desktop controls implemented. SDK command and process-session execution has a host-enforced environment-secret foundation. Sensitive inherited and override variables are withheld unless the host grants an exact name, and retained output is sanitized before entering UI, result, detached-log, or session buffers. Optional `read-only`, `workspace`, `workspace-network`, `full-access`, and custom capability profiles run at the shared `beforeTool` boundary and propagate to delegated agents. Restricted profiles fail closed for unclassified plugin/MCP tools, separate built-in network and external-device capabilities, and reuse the command guard for read-only shell calls. General settings now persist a profile for new local sessions, defaulting to `full-access` when no preference exists so the host-enforced boundary matches the desktop composer's existing Full Access/Yolo label; the sidecar resolves the stored boundary rather than trusting the webview to provide it. These profiles are not claimed as an OS sandbox; native filesystem and network containment remains follow-up work under #24.

Add read-only, workspace, workspace plus network policy, Full Access, and custom named profiles. Keep approval UX separate from technical enforcement.

Enforcement should cover filesystem roots, command execution, network enablement/destination policy, MCP/plugin side effects, and background tasks. Full Access remains available and still cannot bypass operating-system permissions, remote authentication, licensing, or parser/resource limits.

## Phase 5 — Parallel agent orchestration

Parent issue: #25

Implementation status: desktop control surface implemented for team-task agents. The existing team runtime provides bounded parallel runs, persisted parent/child sessions, status/activity tracking, result aggregation, cancellation, mailbox steering, retries, and concurrency caps. The desktop agent roster exposes Open, Stop, Guide, and Retry actions without aborting the lead session. Host and Hub commands validate the owning root session and teammate identity before acting. Team leads can now spawn an `isolated-writer`: Core creates a managed Git worktree, routes that teammate's tools and workspace prompt to it, persists the assignment, inventories changed files for async runs, and records cross-agent path overlaps before handoff. Generic `spawn_agent` and configured-agent children now register independent host-owned handles for their synchronous lifetime, so the desktop roster can Stop or Guide one running child without aborting the lead; handles are ownership-scoped and removed when the child settles. Retry remains intentionally limited to durable team runs because replaying a completed synchronous tool call outside its parent would violate the parent tool contract. The desktop roster also persists and consolidates overlap evidence, marks the writer handoff blocked, lists conflicting paths, and routes directly to the writer worktree/session for resolution.

Expose parent/child task threads, active operation, status, worktree owner, model, stop/steer/retry controls, concurrency caps, and consolidated results. Default parallel delegation to read-heavy work. Give every parallel writer an isolated worktree and detect overlapping edits before handoff.

## Phase 6 — Windows command-latency optimization

Parent issue: #26

Use the existing duration, time-to-first-output, output-chunk, output-volume, and direct-versus-shell telemetry to establish a baseline. Add a feature-flagged, serialized, restartable prewarmed PowerShell worker only if measurements show shell startup dominates. On failure, fall back to the existing executor. Never route direct argv commands through the worker.

Implementation status: Windows now persists a bounded local baseline of numeric timing/output measurements only and exposes a deterministic decision report. The gate requires at least 20 successful direct and 50 successful shell samples with output, a median shell first-output delay at least 150 ms above direct execution, and shell startup consuming at least 60% of median shell duration. Until the report is `eligible`, the worker is not implemented or enabled and existing execution remains unchanged.

## Phase 7 — Scoped computer use

Parent issue: #27

Implementation status: Windows-only scoped computer use is implemented as an explicit opt-in for new Full Access sessions. The host enforces exact executable allowlists, foreground executable and process-instance revalidation, session-and-agent ownership, owner-issued child-agent leases with expiry/action budgets and revocation, bounded accessibility/screenshot observations, protected/password-surface denial, action/runtime/evidence limits, in-window coordinate bounds, optional appear/disappear post-action verification, and a visible Stop and Take Over control. Local diagnostics persist aggregate counts and durations only. The unchanged installer workflow now runs a deterministic WinForms/UI Automation fixture after the native installer cleanup suite. Accessibility selectors are preferred over coordinates, and structured tools/MCP remain the required first choice. See `docs/SCOPED_COMPUTER_USE.md`. Native OS sandboxing, macOS/Linux adapters, and DPI/multi-monitor/modal fixture coverage remain follow-up work.

## Delivery order

1. Documentation consistency and baseline tests.
2. Process service foundation and one-shot compatibility.
3. Interactive process tools and native PTY/ConPTY boundary.
4. Durable task state and migration from projected reports.
5. Worktree lifecycle and handoff.
6. Permission profiles.
7. Parallel agent UI and coordination.
8. Telemetry-driven PowerShell optimization.
9. Optional scoped computer use.

Each phase lands through a focused pull request. Merge only after its stated checks pass or remaining failures are proven unchanged from the current `main` baseline.
