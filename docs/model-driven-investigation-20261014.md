# Model-driven investigation upgrade

## Scope

Builds on merged PR #112. The desktop now supplies five named model tools: `open_binary`, `analyze_function`, `trace_application_feature`, `capture_browser_scenario`, and `get_evidence_bundle`. They are unavailable in CLI/VS Code, absent without a host executor, sequential and non-retrying. Their catalog toggle follows reverse engineering; external-tool permission profiles still apply.

## Authority and approval

- The model cannot supply a session/workspace, mode, trust flag, approval token, phase or recording-consent boolean. Strict schemas reject these fields.
- The host obtains the owning local session and workspace from the runtime context and saved session. A module-private identity distinguishes a model transaction from desktop RPC input; no fake WebSocket approval connection is constructed.
- A model transaction may run while its own turn is busy. Desktop-initiated new work still requires an idle trusted session. Both paths require Analysis enabled for new work; recording starts require Runtime mode. Existing recording may be stopped after mode changes.
- `analyze_function` prepares the existing immutable, target-identity/request-hash-bound plan. A **fresh desktop human review** is required independently of ordinary tool auto-approval. The one-use execution token stays inside the host and is never part of the model schema or returned result. The existing orchestrator consumes it and rechecks the target identity.
- Recording start independently asks the connected desktop human for bounded metadata-recording consent. Model text is not consent. Listing browsers and stopping an existing recording do not grant start consent.
- No trusted approval surface, rejection, disconnect, cancellation or a 120-second review deadline denies the operation. Pending native plans are cancelled on denial/failure; cancellation errors are surfaced rather than represented as confirmed cleanup. There is no automatic execution retry.
- A mode/workspace change invalidates the pending transaction. UI mode controls and independent Execute/debugger approvals remain unchanged. Analysis and recording do not grant JavaScript Execute permission.

## Native evidence

Existing selected-function Ghidra output remains available. IDA's fixed selected-function adapter additionally exports schema-checked pseudocode/signature, processor name, image base/address space and at most 128 ctree call candidates. Its traversal stops at 100,000 expressions. Unknown expressions remain unresolved; unavailable callsite addresses explicitly identify a function-entry fallback. Direct object references are **decompiler candidates**, not observed calls. The loader checks the expected provider's schema and rejects missing, oversized, symlinked or invalid evidence. IDA cache identity changes with the adapter version.

This is not unrestricted indirect-call recovery, runtime relocation proof, a new decompiler, or a substitute for an installed matching licensed IDA/Hex-Rays processor. Python fixtures execute the generated adapter against API doubles; those fixtures do not validate a live license or real-world decompiler accuracy.

## Trace and report interpretation

Feature tracing preserves fact IDs, source locations, source confidence and selected receipt/scenario references. Matching facts are grouped into renderer, preload, IPC, native and managed candidate stages. It reports explicit unresolved boundaries and evidence needed next. Shared labels, timing, provider assertions and byte equality are **not promoted to causal edges**. Matching output is bounded to 100 facts and reports truncation. Optional selected task IDs expose owned native candidate summaries without inventing runtime relocation.

Evidence exports now include the selected task's owning-session hash-checked provider snapshot, not only the task completion receipt. A JSON-pointer index links each report entry to its selected record and distinguishes static facts, browser observations and task receipts. Both records and derived report fields receive best-effort credential redaction. The existing 4 MiB export limit remains; exports are not full backups and require review before sharing.

## Validation and release gates

Required validation includes the new SDK tool-schema/profile tests and desktop model transaction, host review transport, report and workflow tests. Generated IDA adapter execution uses controlled fake APIs; provider routing tests use mock engines. Existing installer, real Windows AppContainer, native browser and installed-WebView acceptance gates are retained.

Do not infer Windows installer acceptance from a local Linux test result. Do not infer a live model turn or licensed IDA acceptance from host/executor fixtures. Merge only after the new PR's own required CI and Windows installer checks succeed.

## Still not established

- Recovered end-to-end renderer → preload → IPC → native causality.
- General runtime relocation or arbitrary indirect-call resolution.
- Complete Electron/preload or .NET semantics.
- Superiority over REA. A comparative run still needs pinned REA and app versions, identical authorized fixtures/models/budgets, ground-truth scoring, false-positive accounting, timings and reproducible raw evidence. No benchmark result is asserted by this patch.

## Windows discovery-publication CI follow-up

The Windows SDK rerun exposed `EPERM` while replacing `hub-discovery.json` during real-process crash recovery. Discovery publication now retries only Windows `EPERM`, `EACCES` and `EBUSY` from the same atomic rename: at most six attempts with 25/50/100/200/400 ms backoff (775 ms total delay, excluding filesystem operation time). The existing mutation lock remains held, and the unique temporary file has already been closed and synced.

No incumbent record is unlinked or rewritten in place. Permanent errors still fail and clean only the writer's own temporary file; unrelated files and the previous complete record remain. Other platforms and unrelated error codes do not retry. Tests cover bounded retry behavior, complete-file preservation, caller cleanup, lock release and real-process crash recovery. This is not a daemon-launch, analysis, execution or approval retry. Fresh Windows CI is required to validate the new head; the earlier installer pass does not certify this follow-up. The earlier console-fixture failure passed on rerun but its root cause has not been established.

The extension E2E job's Bun cache now uses a separate restore action and a success-only, cache-miss save step with a one-minute budget. Only this optional cache save tolerates failure; dependency installation, SDK build and both platform E2E test steps remain blocking. Exact keys are retained without broad restore fallbacks. This addresses observed post-test cache stalls without extending the job deadline or weakening test assertions.
