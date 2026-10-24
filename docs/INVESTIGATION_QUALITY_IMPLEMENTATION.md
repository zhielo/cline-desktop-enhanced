# Investigation quality implementation

Base: `8318e4ad12467bf2ce82eeb7cc426fbff7bb3809`.
Reviewed REA reference: `f9fabdfcb2c241b18fec0acb5c3b4a14f76f4805`.

This is a completion ledger, not a claim that this branch implements every item.
No REA runtime, CLI, MCP registration or installation is a production dependency.
No new IDA license-file, plugin-name or license-discovery gate is permitted.
An optional provider's actual invocation failure must not disable another provider.
Vendor runtime errors remain errors; this project does not bypass vendor licensing.

| Workstream | Existing foundation | Required completion evidence | State |
| --- | --- | --- | --- |
| Evidence and unknowns | UnifiedEvidenceStore, correlation, InvestigationStore | Scoped immutable references; durable revisioned questions; contradiction retention; restart and legacy reads | Implemented; full release gates pending |
| Native dossiers/value flow | Exact Ghidra/IDA selectors and bounded call-target evidence | Real Ghidra argument/return def-use fixtures, bounded frontiers, IDA-specific availability | Implemented bounded saved three-function dependencies; Windows exact-head and release gates pending |
| JS static/runtime reconciliation | Saved static receipts and approved runtime snapshots | Content/location/ambiguity/mismatch fixtures; no I/O during reconciliation | Implemented for saved passive Inspector reports; broader coverage remains |
| Bundle recovery | Source acquisition and application graphs | Reviewed engine identity; Windows process/resource boundary; staged no-overwrite publication; real bundle fixtures | Partial: fixed AST factory recovery and staged provenance export implemented; general Wakaru-equivalent recovery remains |
| Model evaluations/skills | Six guides and installed acceptance | Known-answer model journeys with fixed scoring; real routes, not only mocks or file presence | Guides updated and integrity checked; new live-model evaluations not completed |
| Artifact readers | Existing format discovery and worker | Go build info, Rust auditable metadata, PyInstaller inventory, supported IL2CPP versions; malformed/bounded fixtures | Implemented bounded readers and real parser-child smoke; exact-head Windows/release gates pending |

## Release conditions

One implementation PR, with reviewable commits. Do not merge as “all complete”
while a required row is incomplete or only mocked. Run all existing required
core/engine/installed gates against the exact final source and build the Windows
installer from that source. Missing licensed providers remain optional and
explicitly unverified, not a failure of an unrelated supported provider.
No startup, shell, terminal or global timeout upgrade is included.

## Evidence authority

Hashes establish content consistency, not producer authentication or correctness.
Question status is workflow metadata, not a verified conclusion. Only refer to
evidence already retained in the owning case. Keep unsupported or absent
historical fields unknown. Reopening a case never reruns analysis.

## Implemented in this branch

- `manage_investigation_unknowns`: local authenticated owning-workspace metadata
  route. Exact case and question revisions prevent stale updates. Supporting and
  contradicting links require existing same-case evidence IDs and result hashes.
  Links accumulate, role reversal is rejected, and historical cases preserve their
  old audit hashes without synthesizing missing fields. Workspace cases are not
  claimed to be private to a single chat session.
- Investigation UI: record questions, review statuses and notes, add retained
  evidence links, and display contradictions. Reading and reviewing metadata
  never starts an analysis provider. Restricted tool profiles stay restricted.
- Saved Inspector reconciliation: recognize the retained passive Inspector
  protocol, bind source identity to the task target, distinguish exact bytes plus
  location, location-only, contradictory bytes and duplicate-byte ambiguity.
  Do not export network source labels, fetch source maps, attach or read files.
- Ghidra: additive optional argument and return def-use records. Fixed budgets:
  16 arguments per call, 32 dependency sources, 16 frontier records, 256 visits,
  depth 8, 64 returns. Parameters, constants and local call-return sites remain
  dependency candidates; memory, phi/cycles and unsupported operations remain
  frontiers. This is not interprocedural value equivalence or target execution.
- IDA adapter licensing behavior is unchanged: no license-file/plugin-name gate
  was added. Actual Hex-Rays initialization remains an actual runtime operation,
  and its errors do not authorize a fallback or disable Ghidra. IDA has not been
  executed in this environment and is not certified by the Ghidra tests.

## Validation so far (not a release certificate)

- Expanded local core run: 601 passed, 4 skipped.
- Final focused core/native/Inspector run: 43 passed, 1 skipped, including
  reconciliation of a real running owned Node Inspector report.
- Desktop/store/model-bridge/UI/skill-integrity run: 94 passed.
- SDK build and desktop plus WebView type checks passed.
- Actual Ghidra 12.1.4 on compiled owned ELF fixtures passed parameter-to-call,
  call-return, parameter-plus-constant and memory-load-frontier assertions.
  See `validation/investigation-quality-owned-ghidra.json`. The fixture process
  was analyzed, not executed. Exact-name ambiguity was observed and correctly
  rejected during development; no nearby-function fallback was added.
- Windows installer build, installed acceptance, the consolidated release
  validator and the remaining three workstreams are not yet complete.

Do not mark this branch ready for merge or describe all six workstreams as
complete from these local checks. Missing parity fixtures are not successful
checks; no "same or higher than REA" certification is claimed.

## Additional implementation on this branch

- `trace_native_value_flow`: list then trace 1–10 exact owning saved static tasks.
  Cross-function edges require exact artifact, Ghidra version, architecture,
  address space/base and one retained callee. Argument binding is explicit;
  missing/duplicate observations, recursion, memory and budgets remain frontiers.
  No provider/file access, target execution or whole-program value equivalence.
  Actual production Ghidra three-function fixture passed; see
  `validation/investigation-quality-native-flow.json`.
- `inspect_artifact_metadata`: immutable handle + explicit Go/Rust/PyInstaller/
  IL2CPP reader. Runs through the fixed, supervised first-party parser child,
  uses stable confined 32 MiB acquisition, rechecks the selected SHA256 and
  exposes bounded paginated `artifact-metadata` evidence readable while Off.
  Go/Rust readers cover supported PE/ELF/Mach-O containers; IL2CPP versions
  24/27/29/31/39 decode bounded inventories, not native-address linking.
  PyInstaller covers CArchive cookie/TOC only, not nested PYZ/decompilation.
  Reader source pin, local integration patches, fixture hashes and MIT notices
  are preserved under `analysis/artifact-readers/upstream`.
- `recover_bundle_sources`: exact inert AST-literal Webpack/Rspack/esbuild
  factory recovery in the existing parser child. UTF-8 byte ranges, original
  source and fragment hashes, engine revision and omissions remain retained.
  Source fragments are inert base64; they are not executed or runnable originals.
- `publish_bundle_recovery`: separate reviewed Modify plan, owning Full Access
  session, exact saved report hash and original source recheck. Stages one new
  no-overwrite JSON provenance package; no automatic execution or promotion.
  Only this exact operation can use its genuine host model-investigation grant
  during that owning model session. Other writes retain existing desktop/idle
  requirements; JSON-shaped grants cannot authorize export.
- The bundled guides now describe these exact routes and their limits. Skill
  file hashes were regenerated. This does not substitute for live-model testing.

## Current validation scope and remaining blockers

- Full local analysis directory run: 554 passed, 4 skipped. Three skipped files
  require the separately checked-out historical reference; CI runs those parity
  comparisons. A skip is not parity evidence.
- Desktop investigation/store/guidance/UI run: 100 passed.
- Focused recovery/readers/native/profile/catalog run: 105 passed before the
  subsequent additional host/guard tests; do not add overlapping test counts.
- Real supervised parser-child smoke passed Go, Rust, IL2CPP and bundle recovery,
  including saved evidence reads while Off. No target code was executed.
- SDK build passed. Lint/type checks and exact-head CI must be rerun after the
  final changes. A prior green or still-running installer build does not cover
  this new source.
- General Wakaru-equivalent source recovery and the required live-model
  known-answer evaluations are still incomplete. No model-provider credentials
  are configured in this worker environment. Scripted host tests are not a
  live-model evaluation, and this ledger does not claim otherwise.
- Keep PR #155 draft/unmerged until these gaps and final Windows installer plus
  installed acceptance are completed. Do not waive a required gate to merge.

## Host integration corrections

- Preparation and execution now carry the same explicit per-operation timeout
  for metadata inspection, bundle recovery and publication. This fixes exact
  approval-envelope matching; no global timeout policy was changed.
- Recovery publication preserves the owning chat session for its saved receipt
  lookup instead of using the workspace process-owner identifier.
- Actual public supervised parser API -> saved receipt -> human-reviewed busy
  model host -> no-overwrite export regression passed. The three related host
  suites passed 99 tests; the strengthened real-worker host suite passed 32.
  These are overlapping checks, not 131 distinct tests or a live-model score.
- Repeated full analysis directory check: 554 passed, 4 skipped; permission
  profile regression: 46 passed; model routing: 5 passed. SDK build and
  desktop/WebView types passed. Final error-level lint, quick verification and desktop/WebView types passed.
  Exact published-head CI remains required.

## Full host journey follow-up

- Added fixed parser dispatch for metadata/recovery options and validated exact
  owning-session workspace before consuming the one-use plan. Evidence creation
  and export now use that same chat session, not the workspace process owner.
- Actual model-host transaction sequence (scripted decisions, not an LLM):
  immutable artifact open -> separately reviewed recovery -> supervised parser ->
  owning saved receipt -> metadata inspection of an owned PyInstaller CArchive ->
  separate Modify review -> no-overwrite recovery export. All 99 tests in the
  three host suites passed with this strengthened regression.
- The three formerly skipped semantic/application/fuse parity tests were run
  against separately fetched reference d0067ba34a39ea47dd7e11bb2e6169bc0938cc3f
  and passed. This does not certify full parity with current REA.
- A concurrent local consolidated run suffered an OS-killed TypeScript process
  (137); this is a failed gate, not a typecheck pass. Rerun serially on the final
  published source. No release gate was removed or downgraded.

- Release recipe fingerprints were updated for the added Ghidra CI step and
  expanded parser test list. Required check names, core gates and installed
  acceptance labels were not removed or relaxed. Old recipe hashes correctly
  blocked the first customization gate; the new recipes must pass full CI.
## Exact-head Windows failure follow-up

- Installer run 40069541880 at 5d82271 failed both customization and sidecar
  regression gates at the same owning-model recovery export. No installer was
  produced; installed acceptance did not run. These are failures, not passes.
- Canonicalize workspace and artifact identities with the native filesystem
  resolver before confinement comparisons. This avoids comparing Windows 8.3
  TEMP aliases against expanded paths while retaining relative traversal,
  outside-root and linked-escape rejection. Recovery export uses the same
  canonical identity for saved target and relative artifact labels.
- Local checks for this fix: 32 owning-host tests and 18 analysis/recovery tests
  passed, including canonical root aliases and linked escapes. The SDK build
  passed. A Windows rerun is required; Linux tests do not prove the Windows fix.
- Extension E2E run 40069541925 retained blank Cline view snapshots followed by
  waitUntil timeouts. This is a separate unresolved initialization failure, not
  evidence that recovery export failed in that extension route. Extension unit
  job failures also still need their underlying diagnostics.

## Pinned general-recovery foundation (not public-route completion)

- Added an internal Wakaru 1.14.0 adapter for official Linux/Windows x64 binaries.
  Build-only preparation validates exact release-archive and executed-file hashes,
  retains the upstream Apache-2.0 license, and refuses an existing destination.
  It does not install REA, download at app startup, or expose executable paths to
  the model. A dedicated cross-platform CI job runs the real owned fixture.
- The real Linux owned fixture recovered two webpack modules and their source
  maps. Transformed-module hashes and original input-range hashes are separate;
  no runtime-equivalence, original-name or general parity claim is made.
- The adapter rejects changed input bytes, invalid UTF-8, missing/unpinned engines,
  unsafe/duplicate output names, symlinks, unreported files and out-of-input ranges.
  It retains inert module/map bytes under explicit file/entry/depth/time budgets.
  Output polling is not a hard disk quota, and process separation is not a hard
  memory limit or OS sandbox. Unconfirmed drainage does not authorize cleanup.
- Public model routing, installed resource packaging, parent/descendant lifecycle,
  and saved/export receipt integration remain incomplete. In particular, the
  existing parser host strips resource environment configuration and kills its
  immediate worker; adding a nested native engine there without lifecycle work
  would risk an orphan. The new adapter is deliberately not wired into that route.
- Local real-engine adapter tests: 4 passed. The build-only downloader passed its
  Linux archive/executable/license checks. Windows execution is pending CI.

## Extension failure diagnosis

- Current local extension build passed; 1,246 adapter tests and all 81 isolated
  unit files (1,121 passing tests reported by the runner) passed.
  This does not negate the hosted extension integration/E2E failures.
- Added bounded per-test VS Code activation log retention before E2E cleanup,
  with credential-pattern redaction and a passing owned retention test. Hosted
  extension/platform test steps now tee output with pipefail and retain failure
  logs. Existing test commands, nonzero exits and aggregate gates remain required.
  No activation fix or timeout increase is claimed; the next diagnostics are
  needed to identify the real failure.

## Reproduced extension activation regression and correction

- The platform failure was reproduced with server diagnostics: bundled
  jsonc-parser 3.3.1 loaded its UMD factory, whose forwarded relative require
  attempted to resolve `./impl/format` beside cline-core.js. The process exited
  before readiness. This is a concrete packaging regression, not a slow-model
  or timeout diagnosis.
- A narrow production esbuild plugin resolves only jsonc-parser to its upstream
  ESM entry for extension/standalone/E2E builds. Other package entry conditions,
  parser behavior, metadata-reader sources and vendor license handling are
  unchanged. A real Node CJS bundle regression passes with the production plugin.
- Rebuilt standalone, restored the local SQLite native dependency skipped by
  the initial ignore-scripts install, then reran the real owned platform spec:
  1 passed. The missing local SQLite binding was a separate local prerequisite,
  not evidence of a hosted SQLite failure. Hosted extension/E2E must rerun.
- Kept the diagnostics helper's bun:test regression in its isolated unit runner,
  explicitly excluding that one non-Playwright helper from Playwright collection.
  Listing still finds all 14 original setup/E2E tests in 9 files. No actual E2E
  scenario or assertion was removed. Credential redaction now includes named
  token/secret/password fields and URL credentials, with bounded regex scans.
- General-recovery owned engine CI at ef0696e passed on Windows and Linux
  (run 40079069164). This does not complete its public/installed lifecycle.

## Windows Inspector clock-domain correction

- Exact head `8c3162e` passed extension activation/platform checks, all three
  desktop extension E2E platforms, SDK Windows/Linux, Windows regression gates,
  and the pinned general-recovery fixtures. The installer did not build: the
  Windows semantic-source gate failed the real running-console fixture with 22
  reports rejected as future timestamps, despite exact loaded-source identity.
- Node 24 Inspector uses V8 `CurrentClockTimeMillis`; on Windows this is a
  process-local interpolation over coarse `GetSystemTimeAsFileTime`, not the
  collector's libuv performance epoch. A high-resolution receipt timestamp alone
  does not synchronize those clocks. See Node v24.14.0 `src/inspector_agent.cc`
  and `deps/v8/src/base/platform/time.cc`.
- Collector receipts now explicitly record a fixed Windows 16 ms future
  allowance (other platforms retain 1 ms rounding). Start boundary, active-only
  receipt admission, source identity, opaque object treatment and finite budgets
  remain unchanged. Reports at/beyond the bound and older reports are rejected;
  larger clock changes remain missing evidence. This is protocol-claim timing,
  not authenticated freshness, replay prevention or verified execution.
- Boundary regressions and real Linux Inspector tests passed (16 tests). Exact
  final-head Windows fixtures and installer acceptance remain required.
