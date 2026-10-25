# Deep-audit remediation — 2026-10-25

Baseline: `c4e37fb1075280874e78aab9107848868ac76506`.

This change set addresses all eleven findings from the desktop lifecycle audit. It is source remediation, not a claim that every application defect is known or that installed Windows/live-provider acceptance has already completed.

## Applied changes

| Finding | Implementation | Regression evidence |
|---|---|---|
| F01 unsafe session cleanup | Opaque local cleanup IDs; known-session requirement; canonical owned directory/log cleanup; no stored-path parent deletion. Shared core derives message/compaction paths and refuses outside-root or junction aliases too. | `session-cleanup.test.ts`, `commands-git-worktree.test.ts`, core `session-artifacts.test.ts` and `persistence-service.test.ts` |
| F02 destructive discovery | Discovery is read-only; reserved staging and unindexed directories remain untouched. | `session-data/discovery-lifecycle.test.ts` |
| F03 JSON secret redaction | Recursive structured JSON sensitive-key redaction and quoted assignment fallback. Existing preview, exclusions and best-effort limitations remain. | `notion-agent-bridge.test.ts` |
| F04 state replacement loss | Never unlink the previous valid state as a replacement-rename workaround. Failed replacement fails visibly and preserves the previous state. | `task-state-machine.test.ts` |
| F05 attachment steering loss | Attachment-bearing submissions stay queued for the normal multimodal turn. Text-only steering remains supported. Returned queue snapshots expose actual delivery. | `pending-prompt-service.test.ts` |
| F06 text-only queue dedup | Distinct submissions retain separate entries, including identical text with different images. Only explicit submission identity can deduplicate at the queue-service boundary; queue promotion/editing uses prompt IDs. | `pending-prompt-service.test.ts`, `local-runtime-host.test.ts` |
| F07 partial attachment writes | Provisional copies, rollback on failure and retained original upload IDs for retry; consume staging only after the batch succeeds. | `attachments.test.ts` |
| F08 unknown model capabilities | Unknown capability provenance is explicit and propagated through builtin, compatible and configured-model gateway producers. Only exact known non-unknown bundled facts can fill gaps. Unresolved image support produces a visible failed completion, not silent media stripping. | `catalog-live.test.ts`, provider `compat.test.ts`, existing capability/handler/default tests |
| F09 old media displaces current | Reserve the current user's media budget first without changing stored history or removing resource limits. Older media receives the existing omission marker when necessary. | `ai-sdk-format.test.ts` |
| F10 stale-base release evidence | Policy v2 binds current base, head and live synthetic merge SHA, verifies both ordered merge parents and rechecks base/merge identity during final collection. Report the tested integration tree, which may differ from the head tree. | `release-gate-verifier.test.ts`, `release-gate-collector.test.ts` |
| F11 incomplete Git review | NUL-delimited tracked/untracked inventory, ignored-file exclusion, rename parsing, bounded new-text line counts, confined source reads and explicit unknown check status that does not allow merge. | `engineering-git-review.test.ts`, existing control-plane tests |

## Compatibility decisions

- No automatic merge, release publication, updater activation or permission broadening is added.
- Media steering deliberately falls back to a regular queued turn. It does not claim that the existing text-only steering callback became multimodal.
- Unknown capability facts do not mean “vision enabled.” A user gets an actionable error until metadata is resolved or a verified image model is selected.
- An arbitrary legacy external artifact path is not considered owned solely because it appears in persisted state. Such artifacts may remain on disk rather than risk deleting user data.
- No garbage collector is run as a side effect of listing sessions.
- A failed state save is not reported as successful merely because an older snapshot survives.
- Secret detection remains best effort. Review the outbound evidence preview; no scanner can guarantee every secret is found.
- The release gate remains read-only and cannot guarantee that a base will not change after verification. Required up-to-date checks or a correctly configured merge queue remain important.

## Validation scope

The focused regression matrix contains 510 tests across shared media/schema (71), model catalog/provider/capability (129), core queue/runtime/default/handler (150), core persistence/ownership (22), and desktop lifecycle/security/review/release (138). These are targeted unit and controlled integration checks, not the full monorepo suite or installed Windows acceptance.

Validation commands include:

```bash
# Repository root
bun run build:sdk
bun scripts/verify-custom-fork.ts

# Affected SDK package directories
bun run typecheck

# Desktop directory
bun run typecheck
```

Vitest is run through Node, its configured test runtime. Running Vitest directly under Bun 1.3.14 in this review environment produced a dependency-loading incompatibility; no production code was changed to hide that runner failure. Heavy declaration checks must run without competing build/test processes on small machines; memory-killed runs are not passing results.

The new ownership/discovery suites are included by the existing desktop sidecar and core unit-suite directory coverage. No workflow checks, assertions, safety gates or timeouts are disabled to make the patch pass. The customization ledger and preservation verifier are updated together.

## Required acceptance before merging/releasing

1. Let the PR's required GitHub workflows run against its current integration candidate. A source-only build is not an installed-app acceptance result.
2. Inspect the Windows installer and installed-WebView evidence tied to the exact commit, run attempt and artifact digest.
3. Test idle, queued and attempted-steer image submissions in both fresh and restored sessions. Confirm attachment-bearing steering appears queued and eventually reaches a normal turn.
4. Inject Windows sharing/rename failure and confirm the previous task snapshot survives and the UI reports the save failure.
5. Test malformed cleanup IDs, external stored paths, directory junctions and active uploads during sidebar refresh.
6. Confirm review includes new untracked files and labels CI knowledge unknown instead of passing.
7. Advance the PR base without changing the head; old release evidence must fail until the current merge candidate is rebuilt and verified.

The exact cause of the historical image screenshot still needs installed-build identity and sanitized attachment/provider diagnostics. Source fixes prevent the audited mechanisms; they do not retroactively prove which mechanism occurred in that session.

## CI follow-up: remote deletion routing

The full desktop suite exposed a regression in the F01 command guard: SSH sessions without a local session record were rejected before the remote manager could delete them. The local known-session prerequisite now applies only to local cleanup; SSH deletion stays delegated to the selected remote manager and returns before local artifact cleanup. Existing unknown-local-session protections remain enabled. The remote-routing regression test explicitly asserts there is no local live-session entry.

Follow-up local validation: the full desktop sidecar/WebView suite passed 1,931 tests (five existing skips), the compiled desktop startup test passed, desktop typechecks passed, and all 353 preservation contracts passed. GitHub CI and the Windows installer gate must still succeed for this exact follow-up commit before merge.
