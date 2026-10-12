# First-party Analysis Workspace

A Windows-first static-analysis foundation extending Cline Enhanced without REA. This is **not full REA parity or a superiority claim**.

## Usage

1. Setup Center → **Test first-party static analysis** runs fixed owned fixtures. Read bundled parser license/notices here. Presence and readiness are distinct; the fixture receipt is scoped to the current backend lifetime.
2. Open an existing local session. While idle, select **Analysis: Static** in its header, then **Open**.
3. Inspect a workspace-relative JS/TS source, directory, package metadata or bounded ASAR. Optionally compare another confined artifact/directory.
4. Explore paginated Artifacts, Findings, candidate Graph edges, receipt Timeline and Verification. Graph links navigate to the supporting source/target evidence.
5. Off blocks new first-party inspections, not unrelated existing tools. Evidence remains readable after Off/restart. Runtime selection grants no permissions or target-action approvals and adds no JS Inspector implementation.

The agent uses `reverse_engineer.javascript_analysis`, then `analysis_evidence` with the returned receipt ID. Existing permission profiles remain authoritative; restrictive profiles may deny the agent tool even when explicit user-requested UI inspection is available through a trusted desktop command.

## Implementation

Shared Core owns contracts, private SQLite evidence, atomic cross-process admission, worker supervision and bounded evidence queries. The compiled sidecar provides a fixed `--cline-analysis-worker` branch before Hub/setup/server startup. TypeScript 5.9.3 parses syntax only; no target import/evaluation/transpilation/execution, target write or network operation is requested. No REA, separate Node/npm installation or Python pack is required for the packaged parser.

The existing shared Hub remains the agent authority. No second Hub or automatic busy-Hub restart is introduced. An older attached Hub must follow the existing build-mismatch/idle restart flow; UI parsing does not prove that an old Hub has upgraded.

## Supported evidence

- Source-byte hashes, paths, line/column locations, parser/profile identity and observed/derived distinctions.
- Literal modules/native-addon references, conservative relative import candidates, function/call syntax, declared package entrypoints and literal global-fetch candidates.
- ES named imports and unshadowed top-level CommonJS Electron destructuring for IPC/preload candidates. Shadowing conservatively suppresses candidate bindings.
- Computed values stay unknown. Equal IPC channel names are candidate relationships, not proof of delivery, execution, unique routing or feature behavior.
- Byte comparison uses relative paths; it does not infer rename identity, recovered original symbols or semantic equivalence.
- Links/unpacked ASAR, malformed/oversized files, source maps and excluded dependency/build directories are not fully analyzed. Exclusions, recovery and reached budgets produce explicit partial coverage.
- Immutable terminal receipts retain process PID/exit/signal, request/result hashes, errors and cancellation. Hashes establish content integrity, not producer trust, attestation or correctness. `verifiedBehavior` remains false.

**Not implemented:** comprehensive lexical/semantic/data-flow recovery, universal deobfuscation, new .NET readers, new native function dossiers/cross-engine reconciliation, JS Inspector capture, active browser-scenario capture or reconstruction certification. Existing native/Android/project-edit/runtime workflows and approvals are preserved, not relabeled as new capabilities.

## Limits and recovery

Two shared worker reservations; 250 retained receipts with no silent pruning. Ceilings: 128 source files, 4096 inventory entries, depth 8, 1 MiB/source, 8 MiB total source bytes, 32 MiB ASAR, 200000 traversal visits, 8000 findings/relationships, 4 MiB output and a 60-second worker deadline.

These are bounded workload/admission limits, **not an OS sandbox or total-RSS quota**. AST construction precedes traversal accounting. Filesystem sharing/races, malformed source or resource exhaustion may fail rather than yield evidence.

Child credentials are stripped; target .env/bunfig are not used as host configuration. Cancel/timeout kills only the owned parser process; no replay occurs. Unconfirmed termination retains its reservation. Abrupt host loss leaves running reservations for operator investigation: no PID-only recovery, unsafe automatic reservation clearing or automatic retry exists. This recovery limitation must be addressed before broader release.

Evidence can include private strings and stays in private application data. It is not automatically publicly uploaded. Agent model calls still follow the user's configured provider/data policy.

## Acceptance and release

Owned fixtures cover syntax/IPC/preload/modules, shadowing/unknowns, malformed source, non-execution, confinement/budgets, ASAR and comparison. Store/worker tests cover default Off, exact session scope, active-job mode rejection, restart retention, admission, integrity, credential stripping and real child cancellation. UI tests cover explicit/idle-only modes, runtime confirmation, remote exclusion and retained Off evidence.

Consolidated CI includes these tests. Windows installer smoke additionally runs the installed executable's parser selfcheck. Installed WebView acceptance tests default Off, Static/Off transitions, owned IPC relationships, evidence navigation and disabled new inspections in Off, without replacing existing acceptance assertions.

**The current-revision Windows installed gates must pass before release.** Local Linux tests cannot substitute. No REA comparison or superiority/performance benchmark has run.

TypeScript 5.9.3 is Apache-2.0; complete upstream license and notices ship in `sidecar/analysis-parser-notices.ts`, readable in Setup Center. No REA-authored code is copied.
