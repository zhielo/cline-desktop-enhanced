# Integrated install-and-use, optimization and recovery delivery

This integrated PR preserves the complete custom-fork feature set, Full Access,
exact ownership checks, and private unsigned artifact-only Windows distribution.
It does not publish a release, enable an upstream update endpoint, or invent a
Codex-relative or before/after performance score.

## Shipped source changes

- **Installed analysis runtime:** the Windows build packages the official
  SHA-256-pinned CPython 3.13.12 embeddable x64 runtime and the existing tested
  six-engine environment (LIEF, Capstone, Androguard, Z3, Miasm, cryptography).
  The installer carries dependency metadata, retained license files and a file
  integrity manifest. Transitive dependency versions are recorded in that
  manifest; this is not a claim that every PyPI dependency is hash-locked.
- **Interpreter ownership:** the installed backend and its Hub helper/daemon
  entry points select the private runtime before creating child processes.
  Isolated `-I -B` workers do not use user site-packages or create bytecode files
  in installed resources. Explicit developer interpreter overrides remain
  supported. IDA, Hex-Rays licenses, physical devices and sandbox provisioning
  are separate and never claimed as bundled.
- **Readiness and repair:** Settings → Analysis environment tests owned fixtures
  and offers explicitly confirmed, offline repair from validated installed
  resources. An existing repaired runtime is verified rather than overwritten
  while an engine might own it. Restart is required for an existing Hub to pick
  up a repaired interpreter. Corrupt installed resources require reinstalling
  the trusted installer; no arbitrary pip install is performed. Analysis failure
  does not prevent ordinary coding startup.
- **Readiness cache:** concurrent checks coalesce. Only completed owned fixtures
  can be reused for five minutes when the interpreter and packaged runtime
  identity match. Explicit checks force a new execution. This cache is not
  licensing or live-device acceptance.
- **Hub recovery:** metadata/session preflight can recover a managed local Hub
  transport before registration, not only after a task command fails. Recovery
  retries registration once and refreshes discovery through the existing
  managed-Hub ownership path. Health probes cannot recursively start recovery;
  header-auth remote connections do not use local discovery. Existing no-replay
  contracts for consequential task sends remain unchanged. The exact reported
  1006 error gets preserved-history/reconnection guidance, not API-key guesses.
- **Resource admission:** a fair, bounded queue coordinates Python work and
  persistent native worker capacity within each owning process. It estimates
  memory reservations, rejects admission under low free memory, supports queued
  cancellation, and retains reservations until an owned native worker actually
  exits. Economy/Balanced/Deep controls are available in the GUI; Deep never
  raises the existing two-worker hard pool cap. Profiles persist and are
  inherited by newly started backend processes.
- **Long transcripts:** browser-native variable-height render containment is
  applied only to older rows of long transcripts. The live tail stays rendered;
  the DOM, copy, browser find, artifact actions and accessibility remain intact.
  Small transcript DOM structure is unchanged.
- **Session search:** ended sessions update their own derived index without a
  full history scan when the host supports exact session reads. Full recovery
  reconciliation remains available and yields between batches. Deletion
  tombstones, SQLite serialization and disposal ownership are preserved.
- **Model eligibility:** required capabilities, minimum context and an optional
  per-million-token cost ceiling are hard filters before selecting a ranked
  model. No eligible model means no selected model. Defaults/low samples are
  labelled as estimates; supplied sample counts are not independently audited.
- **Evidence efficiency:** static notebook fingerprints exclude diagnostic job
  IDs/receipt paths/timing but include packaged-runtime identity. Artifact,
  engine/configuration and dependency changes still invalidate cells. Graph
  queries enforce output budgets and preserve source hashes and partial
  coverage. No cached approval becomes permission for a new execution.
- **Review impact:** bounded relative JS/TS import analysis reports affected-file
  candidates and suggested adjacent test files. It reads at most 250 source
  files/8 MiB after a 2,000-entry bounded walk, skips dependency/build trees and
  linked entries, and never executes tests automatically. Results are shown in
  Engineering. This is not a complete AST, alias, dynamic-import or security audit.
- **Performance policy:** a blocking test suite verifies comparable-environment,
  minimum-sample and p95 regression policy. Installed acceptance records three
  candidate startup samples. A missing controlled baseline is explicitly
  `baseline-required`, never `passed` or a fabricated improvement.
- **Trusted updates foundation:** owner Ed25519-signed metadata is checked for
  tampering, expiration, app-owned HTTPS source, downgrade, runtime compatibility
  and data-schema compatibility. Downloads and activation remain disabled.

## Important remaining acceptance boundaries

This PR does not claim all recommendations are fully realized:

1. Machine-wide resource coordination across multiple SDK/Hub processes and
   OS-enforced CPU/RAM limits are not supplied by in-process admission.
2. Full React transcript virtualization is deliberately not enabled before
   scroll-anchor, find/copy, accessibility and interaction measurements. Native
   render containment is the conservative first optimization.
3. Controlled before/after cold/warm/idle/peak-memory/task-cost benchmarks are
   still needed before claiming an improvement or setting observed budgets.
4. Model confidence calibration and mission-wide token/dollar accounting need
   measured task outcomes; a supplied cost ceiling is not a mission ledger.
5. Full semantic AST review is not claimed by bounded import candidates.
6. Live signed updates, staged installer/data rollback and migration acceptance
   remain disabled until owner keys and an explicitly approved distribution
   channel exist. No release/signing secret is requested or embedded in a PR.
7. Licensed IDA/Hex-Rays and physical-device acceptance remain separate.

These are explicit boundaries, not silently passed checkboxes. The single PR
contains all source changes above, but should not be described as complete
implementation of every future capability in the original roadmap.

## Blocking acceptance

`bun run validate:advanced` includes focused resource, runtime integrity,
update-signature, performance-policy, routing, cache, graph, search, Hub and
existing preservation/safety regressions. The Windows installer uses an additive
Tauri resources configuration. Its installed WebView acceptance runs without
`CLINE_RE_PYTHON`, verifies the private interpreter through actual owned fixtures,
reopens a saved session after a real isolated Hub restart, checks settings/session
persistence, and records startup measurements. No paid model turn or old prompt
is replayed by acceptance.
