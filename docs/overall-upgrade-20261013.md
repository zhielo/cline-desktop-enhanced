# Integrated reliability and investigation upgrade

## Scope

This upgrade extends the existing first-party analysis workspace; it does not integrate REA, replace the existing runtime, disable approvals, or claim whole-product superiority. No repository changes are automatically merged.

### Delivered interfaces

| Interface | Actual behavior | Important limit |
| --- | --- | --- |
| `open_binary` | Workspace-confined regular-file identity handle with SHA-256, size and mutation checks | A handle is not decompilation or execution; maximum 512 MiB |
| `analyze_function` | Prepare and run an exact Ghidra/IDA function selector through existing one-use approval plans | Installed licensed/native providers still need their existing readiness tests |
| `trace_application_feature` | Combine selected static label-match candidates with selected scenario records | Partial/unresolved only; no causal handler→IPC→native proof |
| `capture_browser_scenario` | Explicit recording of already-open owned built-in browser actions and native WebView2 network-origin/console-count metadata | Windows only; 120 seconds, 256 events, 100 action acknowledgements; no bodies, paths, queries, cookies, screenshots or console arguments |
| `get_evidence_bundle` | Explicit selection of owning-session receipts/tasks/scenarios, bounded JSON and integrity hash | Best-effort redaction, review before sharing; not a full database/settings backup |

These are desktop RPC commands, not newly registered model tools. They use the saved local session/workspace and trusted UI connection, not caller-supplied ownership. New work requires an idle enabled Analysis session. Recording start additionally requires Runtime and explicit recording consent. Recording stop remains available after switching Off or becoming busy, and returns unpersisted stopped evidence with a warning if receipt storage fails. Completed/partial metadata statuses do not certify target behavior.

The folded **Guided investigation** panel connects these commands without launching targets or replaying commands. Function approval remains an independent review action; changing the selected artifact, function, engine, session, or mode invalidates a displayed plan. Approval does not authorize an altered request. Existing JavaScript Execute and debugger approval requirements remain unchanged. The legacy approval RPC now rejects originless/non-approving connections; authenticated integration access is not approval authority.

### Reliability and installation

- One installer candidate build per PR rather than duplicate feature/fix branch-push and PR builds; main/tag builds remain.
- Exact requirements/script-keyed Windows wheel cache, streaming SHA-256 inventory verification before reuse, no loose restore prefixes. This detects mutation; it is not producer attestation.
- Bounded noninteractive wheel build (20 minutes), offline wheel installation (5 minutes), progress heartbeat and owned process-tree termination on deadline. A timeout fails the build; fixtures are not skipped. Cold/warm build-time improvement must be measured in CI, not assumed.
- Optional private packs and licensed engines remain optional/on-demand. Setup Center adds filter/needs-attention views and explains installed versus tested/stale readiness.
- Backend connectivity indicators report the transport state and never replay accepted actions. Existing Hub/task/session recovery is retained.

### Draft and data recovery

- Opt-in, device-local plaintext unsent-text recovery: maximum 32,000 characters, seven-day recovery eligibility (expired text is removed on next access, not by a background secure eraser), environment/workspace/session keys, manual restore and explicit discard. Never automatically sent. Attachments and credentials are not backed up. Do not enable for sensitive prompts.
- Accepted sends clear only a matching saved draft, not a newer edit. Failed sends preserve the existing prompt recovery path. Scope changes cancel pending draft saves.
- New workflow records use a separate versioned SQLite store; future versions are refused rather than overwritten. Existing session/task stores and NSIS upgrade/rollback behavior are not replaced.
- Selected evidence export is not backup/restore of the entire app. No whole-database backup, remote recording, browser/Electron active sandbox, or full cross-process semantic proof is claimed.

## Validation and release gate

- New regressions exercise real SQLite scope/mutation/version checks, the real approval orchestrator's exact request hash and single-use token, stopped-evidence persistence failures, owner-scoped browser metadata, manual draft recovery and scope switching, and guided UI plan invalidation.
- Existing consolidated parser/runtime/security/chat/settings/installer/recovery suites remain mandatory. New UI tests are included in the required chat gate; sidecar tests are included by its existing directory suite.
- New native metadata processor tests run on Windows, and the installed acceptance journey invokes actual WebView2 capture against its own blank fixture window, checking an observed console event, omitted argument values and cleanup. This is not a full web-application behavior benchmark.
- Merge only after exact-head Windows installer, installed WebView, upgrade/rollback and required checks pass. Local Linux tests and Windows-target COM type checks are not installed-Windows acceptance evidence.
