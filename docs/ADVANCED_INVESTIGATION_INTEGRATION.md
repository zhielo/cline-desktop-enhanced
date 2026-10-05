# Advanced investigation integration

One integrated workbench extends the existing Android static tools, targeted native/decompiler adapters, expression/IR/CFG analysis, signed runtime transport and long-chat recovery. It does not replace the existing permission profiles or bypass provider authentication.

## Durable workspace

Select **Investigation** to create a device-local case, reopen its checkpoint, record unresolved questions and choose active/paused/authentication-required/worker-disconnected/closed. Cases use a workspace-scoped SQLite store outside chat; compare-and-swap revisions reject stale edits. Task request/artifact hashes, bounded evidence summaries, output references and an integrity chain are recorded separately from transcripts. Hashes detect corruption, not a local privileged actor rewriting the database. Cases retain up to 256 evidence entries/100 jobs/1024 audit events and 1 MiB metadata; fork before limits. Metadata summaries retain at most 64 rows per category and report available/retained counts. Full signed results are referenced, not falsely presented as complete summaries.

Select a case before preparing analysis. Its bound task retains exact approval requirements. Fork inherits evidence/checkpoints but not executable jobs; reopening never replays tools. Reopen the existing case to continue after chat edits or auth renewal. Authentication-required is an explicit investigation state, not a token-refresh implementation. Previous Hub/desktop long-chat lifecycle protections remain mandatory.

## Cross-language evidence and transformations

Static DEX method/class/prototype evidence, derived JNI names/export candidates, native function summaries and signed runtime registrations are shown together. Descriptor-matched registrations are labeled correlation; duplicate matches remain ambiguous. Absolute addresses are not stable identities. Missing native module SHA256 remains unresolved; a disk hash alone would not attest loaded memory. Existing `native_function`, `android_method`, IDA/Ghidra targeted adapters and their configured/licensed prerequisites remain unchanged. Installing an engine is not proof it ran on the approved input.

Existing expression comparison, bounded IR deobfuscation and CFG analysis link transformation records to the case. Z3 `unsat` is labeled equivalent only when the completed result binds the approved input hash, and only under the expression model. Other outcomes remain heuristic/inconclusive. Model assumptions live in approved inputs/exported evidence; no claim of whole-method/binary equivalence is made. No original binary is rewritten, so rollback is retaining/reselecting the original. Universal VM devirtualization, arbitrary key recovery, full native recovery and automated semantic binary rewriting are not implemented.

## Isolated Android runtime

See `workers/android-capture/README.md`. Capture is opt-in, separately approved, authenticated over HTTPS and bound to a pinned Ed25519 worker identity. This is an operator-provisioned Linux controller plus disposable Android target, NOT on-host target execution. Private content-addressed DEX and exact signed receipt publication reject symlink ancestors and mismatched existing files. Host ACLs, reparse-race protection against other actors, disk encryption and secure deletion remain operator responsibilities. Retrieval never resubmits the target and does not conceal the original failed/interrupted task status.

## Required gates and honest release status

Consolidated source validation includes new investigation/capture/UI regressions while preserving every earlier gate. Windows workflow additionally executes owned Python protocol fixtures and builds the pinned instrumentation bundle; then retains process-session, installer and installed-sidecar tests. Exact-head Windows packaging/installed smoke remains necessary, and no auto-merge/release is enabled. Protocol fixtures and compilation do not establish working live Android capture, licensed engines, hardware isolation or general hidden/encrypted-code recovery.

## Physical-device extension

The current runtime adapter targets a dedicated physical Android device through an operator-provisioned isolated Linux controller. It adds separately consented package-scoped native disk capture, nonce/PID/loader-hash correlation, periodic worker retention and authenticated explicit logical removal. See the worker README for exact scope. No physical-device wipe or automatic rooting is performed; existing packages are not replaced. Outer VM provisioning, Frida/Gadget deployment and real hardware validation remain prerequisites, not claimed delivered features.
