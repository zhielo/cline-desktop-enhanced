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

Implementation status: the first foundation is present in `ProcessSessionManager`. It provides stable IDs, owner-scoped lifecycle access, cursor reads, piped stdin, signals, bounded head/tail output, resource limits, and expiry. It is intentionally not wired into the public tool surface or existing `run_commands` yet, and it reports `interactive: false`; those compatibility and real PTY/ConPTY steps remain follow-up work under #21.

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

Canonical states:

`planned → running → verifying → repairing → completed`

Exceptional states:

`waiting_for_user`, `blocked`, `failed`, `cancelled`, and justified `skipped`.

Every task step must support stable identity, acceptance criteria, validation commands, owning agent, worktree, artifacts, timestamps, repair attempt limits, and transition history. A failed validation cannot advance to later work until repaired, explicitly blocked, or skipped with a recorded reason.

## Phase 3 — Worktree-first isolation and handoff

Parent issue: #23

Substantial tasks and parallel writers should run in managed worktrees. Preserve the existing Windows canonical-path and cleanup hardening.

Required lifecycle:

- create from the selected local revision without polluting branches;
- associate one durable worktree identity with the task/thread;
- detect dirty or conflicting local state before handoff;
- offer Apply to Local, Create Branch, Open PR, Keep, and Discard;
- make cleanup idempotent and independently remove stale task branches;
- never discard uncommitted work without an explicit user action.

## Phase 4 — Additive permission profiles

Parent issue: #24

Add read-only, workspace, workspace plus network policy, Full Access, and custom named profiles. Keep approval UX separate from technical enforcement.

Enforcement should cover filesystem roots, command execution, network enablement/destination policy, MCP/plugin side effects, and background tasks. Full Access remains available and still cannot bypass operating-system permissions, remote authentication, licensing, or parser/resource limits.

## Phase 5 — Parallel agent orchestration

Parent issue: #25

Expose parent/child task threads, active operation, status, worktree owner, model, stop/steer/retry controls, concurrency caps, and consolidated results. Default parallel delegation to read-heavy work. Give every parallel writer an isolated worktree and detect overlapping edits before handoff.

## Phase 6 — Windows command-latency optimization

Parent issue: #26

Use the existing duration, time-to-first-output, output-chunk, output-volume, and direct-versus-shell telemetry to establish a baseline. Add a feature-flagged, serialized, restartable prewarmed PowerShell worker only if measurements show shell startup dominates. On failure, fall back to the existing executor. Never route direct argv commands through the worker.

## Phase 7 — Scoped computer use

Parent issue: #27

Evaluate generic computer use only after process sessions, task state, worktrees, permissions, and parallel orchestration are stable. Require explicit app allowlists, visible stop/takeover controls, screenshot/context boundaries, and denial of administrator/security-prompt approval. Prefer MCP/plugins and structured tools whenever available.

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
