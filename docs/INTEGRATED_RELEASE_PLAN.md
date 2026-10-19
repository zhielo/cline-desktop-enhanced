# Integrated engineering workstation release

This is one coordinated integration branch and release, not a claim that all ten product areas or the original 55 commands are complete. No catalog entry, fixture, local test, or generated plan certifies a release. The branch must remain draft while required product acceptance or external acceptance is outstanding.

## Scope and execution order

Keep the existing Tauri/WebView → sidecar → shared Hub/SDK authority. Reuse the investigation, execution, candidate and evidence stores. Add compatible references/read models, not a second execution runtime or destructive storage consolidation.

| Requirement | Deliverable | Current branch increment | Still required for product acceptance |
| --- | --- | --- | --- |
| R01 Workspace | Shared project/artifact/selection navigation across Code, Investigate, Compare, Validate | Existing panes now share optional scoped path metadata across Guide/Analyze/Android/App analysis; explicit AI JSON transfer, optional local remember/clear and scope-bound remount; receipt-bound source snapshots survive pane switches | Full cross-domain structured-selection read model and complete restart journey |
| R02 Verification | Plan → inspect → approve → modify → validate → review with honest outcomes | Exact AI schemas shared with catalog; partial producer results cannot unlock graph consumers; host-derived bounded candidate outcome summaries retain failed checks independently of task completion; explicit build → fresh-hash Inspect verification preparation | Broader candidate/build/verification/sign/device summaries and distinct operational/evidence outcomes |
| R03 Evidence explorer | Precise source/Smali/native/resource selections and linked provenance | Fresh JS/TS flow uses exact hash-backed fact locations; graph consumers retain producer/result/document identities; retained source fact/artifact selection checks exact SHA256 and displays stale/missing/blocked states | Smali/native/resource/virtual-member identity adapters, broader cross-domain navigation and restart selection policy |
| R04 Android | Multidex → entrypoint → method → JNI → preview → rebuild → verify | Bounded Android/candidate implementations plus exact one-hop encoded invoke caller/callee evidence | Transitive caller/callee traversal, supported dynamic-registration analysis, resource-table semantics and unified build/signature/device summary |
| R05 Native | Function dossiers, callers/callees, cross-version matches, engine disagreement, candidate annotations | Previous bounded native and isolated project candidate implementations preserved | Caller discovery, confidence-backed matching and real-engine dossier/comparison acceptance |
| R06 Durable bulk work | Typed dependency outputs, staged effects/approval, restart/resume/cancel | Completed graph_build evidence-graph → graph_query, immutable private snapshots, producer hashes, safe continuation and cleanup | Other explicitly typed outputs, external engines and independently approved candidate/runtime stages; no uncertain side-effect replay |
| R07 Session controls | Persistent mode/model/reasoning/packs/permissions/budgets | Existing per-session/draft reasoning and installed persistence checks preserved | Explicit configuration authority/reconciliation across local/cloud and complete controls acceptance |
| R08 Tool manager | One capability truth across model/UI/batch/docs and target readiness | Shared exact AI interface schemas, route distinction, effect/scope/limitations and readiness-not-probed contracts; all original commands covered | Input format/architecture/engine applicability preflight and installer/repair/version contract consolidation |
| R09 Runtime | Common bounded prepare/approve/start/status/cancel/cleanup lifecycle | Existing independently approved backends preserved; static report chaining cannot start runtime | Unified backend lifecycle and separate authorized Node/native/Android environment acceptance |
| R10 Project knowledge | Scoped searchable provenance, retention/delete/export and local model integration | Existing evidence/private storage/export/local provider functionality preserved | Unified project retrieval, retention/deletion and model integration acceptance |

## Internal dependency checkpoints

1. Freeze all requirements and supported format/platform/backend matrices. Compare overlapping open branches before reusing changes.
2. Shared capability contracts and immutable artifact/reference read model.
3. Independent source/Android/native/UI/tool/knowledge adapters, with focused owned fixtures.
4. Connect typed outputs and candidate/runtime host approval adapters to the existing durable runner. No global allow-all, report-derived paths or model-held approval tokens.
5. Recovery, stale-input, denied approval, missing-engine, cancellation, export/privacy and configuration tests.
6. Full local validation and exact-head Windows build/install/WebView acceptance. Merge only once every required acceptance item has real evidence.

Independent work may proceed concurrently; dependent work must wait for its contracts. One release does not require one unreviewable commit. Build expensive installer artifacts at integrated checkpoints instead of after every text edit.

## Shared command contracts

`analysis_command_catalog` adds `contractVersion: analysis-capabilities/v1` and one capability per catalog command. The existing AI tool factory and catalog both obtain schemas from `investigationCommandInterface`.

Each capability reports its original scope, declared effect, limitations, host-owned authority and `readiness: not-probed`. An interface identifies its exact schema and route. Dual-name interfaces are explicit:

- Static review `run_batch` / `resume_investigation`: existing static notebook file interface.
- AI workflow `run_batch`: `InvestigationSchemas.run_batch`, an approved durable DAG.
- AI workflow `resume_investigation`: exact owning receipt ID and terminal revision.

Schemas and capability descriptions are data, not authority, installation probes or target-compatibility evidence. Cleanup/status commands remain owning-session operations even after Analysis Off.

## Typed graph output chaining

Example AI DAG (provide a fresh operation UUID):

```json
{
  "operation_id": "00000000-0000-4000-8000-000000000001",
  "title": "Build and query selected evidence",
  "parallel": 1,
  "stages": [
    {"id":"build","request":{"operation":"advanced_analysis","advanced_action":"graph_build","target":"selected-report-manifest.json"}},
    {"id":"query","depends_on":["build"],"request":{"operation":"advanced_analysis","advanced_action":"graph_query","target":{"stage_id":"build","output":"evidence-graph"}}}
  ]
}
```

Preview creates no task or snapshot. Execution still requires the existing exact-request human approval. The producer must be an explicit graph_build dependency and return a completed, retained, hash-matching, schema-valid graph. Partial, failed, missing, malformed and truncated producers cannot pass. The host never follows filenames, commands or instructions embedded in a report.

The runner materializes a private, exclusive JSON snapshot only while its graph_query consumer executes. The durable consumer receipt retains producer receipt/stage, result SHA256 and graph document SHA256. It removes the snapshot on success, error or cancellation; unconfirmed cleanup is uncertain. Freshly approved continuation may use a completed producer from the exact previous checkpoint without rerunning it. Changed checkpoints, inputs, implementations or result hashes block reuse.

Limits remain 12 stages, two parallel reads, retained report/document budget 64 KiB, static-only AI stages and no automatic replay of started stages. This does not implement arbitrary output paths, candidate writes, external engines or runtime DAGs.

## Fresh JS/TS flow

`trace_data_flow` supports explicit `source_flow` mode in addition to the legacy saved-report interface:

```json
{
  "operation": "trace_data_flow",
  "target": "/absolute/project/owned.ts",
  "source_flow": {
    "kind": "js-ts",
    "start": {"path":"owned.ts","line":1,"column":7,"kind":"configuration"},
    "end": {"path":"owned.ts","line":2,"column":1,"kind":"resolved-endpoint"},
    "max_depth":6,"max_nodes":100,"max_edges":200
  }
}
```

For `const url = "https://example.invalid/owned";` followed on line two by `fetch(url);`, this obtains fresh owned-parser constant-to-fetch candidates without importing/evaluating source or sending a request. Inspect source facts before choosing exact one-based locations. Paths are relative to the selected directory or file parent. Only configuration/module-value/resolved-endpoint facts are selectable; ambiguous/missing locations fail without fuzzy fallback. Provider file hashes and consumer locations remain explicit for supported closed-module values.

Fresh source flow is always partial: it is not a general taint solver, arbitrary parameter flow, sanitizer validation or runtime execution proof. It rejects mixed saved-graph/engine modes. A missing edge does not prove missing behavior. Source limits remain 128 files, 4096 entries, depth eight, 1 MiB/file, 8 MiB aggregate, symlink rejection and fixed excluded build/cache directories. DAG source-flow stages remain confined existing files and partial evidence blocks dependent stages.

## Mandatory acceptance added by this increment

- Catalog covers all original 55 commands without promoting their implementation scope or readiness.
- Shared AI schemas and static/AI route distinction in the installed catalog.
- Actual graph build/query output chaining through independently approved installed host execution, with preserved input and retained provenance.
- Fresh exact-location source flow in the installed app without target execution.
- Malformed refs, wrong producers/consumers, cycles, omitted dependencies, injected paths, partial/truncated/malformed outputs, cancelled consumers and exact-checkpoint continuation.

The installed release policy now requires 58 stages, including these two new named journeys. Local test results are not installed Windows results. Engine/device acceptance must name its actual authorized environment and cannot be replaced by catalog presence or owned static fixtures.


## Shared artifact navigation increment

Evidence-ledger cards can explicitly select their task target in Analyze while retaining the saved task/request/result provenance in the supervised output. This is navigation only: the current artifact is not rehashed or certified, and no task is prepared or run.

The existing workbench now shares one artifact path across Start here, Analyze, Android tools and App analysis. AI JSON is deliberately not overwritten: **Use shared artifact in command JSON** copies only the target into a valid JSON object after an explicit click. Switching workspace, environment or chat remounts the workbench, resetting pending plans and local pane state; scopes use an unambiguous tuple encoding.

Paths are in-memory by default. **Remember this path on this device** opts into one versioned path-only record for that exact scope. **Clear shared selection and saved path** removes this record and clears the selection; it does not delete source files or stored evidence. Malformed, oversized, authority-bearing and unsupported stored records are rejected, and storage failure leaves in-memory use available with an explicit warning when saved updates/removal cannot be confirmed. No permissions, execution tokens, source contents, hashes or results are persisted by this feature. An input path is unverified metadata, never readiness, an artifact identity or authority to run a tool.

Standalone panes retain their existing local defaults. No runtime engine, installation, preparation, approval or target execution occurs from selecting or remembering a path. Existing diagnostics/status reads still occur when panes open. Shared Smali/native/resource/virtual-member selections and broader cross-domain stale-evidence navigation remain outstanding. The installed policy adds an actual cross-pane/explicit-JSON/remember/clear journey; it is not claimed passed until the new exact commit's Windows checks complete.


### Fresh-session source-pane acceptance correction

The first Windows acceptance run for the shared-path increment exposed a real gap: App analysis returned early without a session, hiding the target field before the first command. The local cross-pane test had covered only an attached session. The local draft pane now exposes path-only selection with inspection disabled and runtime controls absent. Remote environments remain unavailable; no session is created and no status/inspection/runtime request is made by the draft pane. The same target editor is reused after attachment. Regression coverage now exercises both draft and attached sessions, and the existing mandatory installed journey additionally checks the disabled inspection and absent runtime controls. This fixes the product guard rather than deleting a failing acceptance step; Windows success is not claimed until the new exact-head run completes.


## Receipt-bound source selection increment

An explicit **Inspect saved source identity** action on a retained App analysis artifact or finding selects its owning receipt and exact fact ID or saved artifact path. The host resolves the saved path, SHA256 and one-based UTF-16 source coordinates from the receipt, verifies result integrity and workspace/session ownership, and performs one bounded read. The UI does not supply authoritative hashes or replacement paths. Trusted local desktop reads remain available with Analysis Off and never enable Static or Hybrid mode, prepare a plan, grant approval, import/evaluate the target or start a runtime worker.

Supported real JS/TS/JSON/map files must be confined relative workspace members with no linked components and no more than 1 MiB. Matching bytes yield at most nine lines, each capped at 1,000 UTF-16 code units, with exact saved line selection and explicit truncation. BOM and TypeScript Unicode line breaks preserve source coordinate meaning. Invalid coordinates never use fuzzy fallback. Stale, missing, blocked, unsupported and unavailable outcomes retain saved provenance but do not display current source bytes. Matching is only at the checked read: the snapshot is not continuously fresh, execution proof, or authority to execute.

Selection survives workbench pane switches and defaults to memory-only. Path change and explicit clear forget it; workspace/environment/chat changes and remount discard live previews. The later opt-in source reference restart increment restores only an inactive selector for the exact scope, separately from remembered path storage. **Use source path in analysis panes** is an explicit matched-only metadata transfer, not a verified future read or a change to AI JSON. The UI rejects mismatched response receipt/session/fact/path identities and ignores late responses after scope/selection changes.

This is a bounded first-party source viewer, not a full editor, universal source-map resolver, virtual archive reader, Smali/native/resource adapter or complete R01/R03 acceptance. The installed policy adds an actual saved-receipt source selection, hash match, stale/no-preview, restore/recheck and cross-pane clear journey with Analysis Off. That Windows journey is required for the exact release commit; local tests do not claim it passed.


## Retained candidate verification outcomes

`validate_candidate` and `review_candidate_changes` now display task completion separately from bounded check outcomes. The host interprets only the first-party verification receipt with its canonical SHA256, operation, exact prepared input hash and required check set. Partial, failed, unavailable and bounded-checks-passed are distinct. Unsupported or mismatched receipts never infer a pass. Retained summaries include bounded check identifiers/statuses, hashes and limitations, not raw diagnostics or engine output.

Failed static command results can retain a result fingerprint with no output paths. They remain failed, do not unlock graph dependencies, cannot reuse consumed approval tokens and may be explicitly exported from the evidence ledger. Exception-only failures without a result do not invent evidence. Older records without summaries remain unassessed. Retention survives host restart but is not a current filesystem recheck, authenticated producer identity, build/sign/install/device result, behavioral equivalence or execution proof. Failed task summaries are not automatically promoted into the completed-only unified investigation store.

A new mandatory installed journey checks real invalid TypeScript through the installed command route, exact failed receipt/input identity, retained task listing, explicit metadata export, original preservation and replay denial. Existing installed verification checks also require bounded passing summaries. Local regression tests additionally exercise partial/blocked receipts, integrity/scope mismatches, restart retention, UI escaping and absence of automatic execution. The installed journey is a release requirement, not a claim that Windows acceptance has already passed for this change.

R02 remains open for connected producer/candidate/build/verification/device workflows and broader artifact adapters; these summaries do not close the entire product scope.


### Workspace overflow regression

The preceding Windows run built and smoke-tested the NSIS installer but failed installed-WebView acceptance: the persistent composer intercepted the findings-tab click after source selection expanded. Selection details now have a bounded, independently scrollable area; the mode bar is bounded and the workbench clips overflow while preserving space for pane controls. The installed test continues to use a normal hit-tested click, not forced clicks, hidden composer controls or a larger timeout. This fixes the observed layout cause; only a new successful installed Windows run can establish regression acceptance.


## Opt-in source reference restart continuity

The source selection now has its own **Remember this evidence reference on this device** control. It stores only a versioned receipt ID and exact fact/artifact selector for the existing workspace/environment/chat scope. This is separate from remembered artifact paths. Source text, hashes, checked outcomes, tool outputs, permissions, plans and execution tokens are never restored from device selection storage. Storage is optional, untrusted and strictly bounded; malformed, extra-field and unsupported records are rejected.

An opted-in reference survives pane/workbench remount and app restart as **recheck required**, with no automatic source read or preview. Explicit **Recheck selected source** uses the existing trusted host route to resolve the owning saved receipt, validate result integrity and perform a fresh bounded read. Stale/missing/unavailable references never fall back to a filename, silently rerun analysis or imply runtime permission. The user can retry or clear an unavailable receipt reference. Scope changes cannot reuse an old preview; each exact scope may restore only its own inactive opted-in reference.

Unchecking removes the saved reference but leaves the current in-memory selection. Selecting a different evidence reference resets this opt-in; it cannot inherit permission to save from the previous reference. Changing the shared target, clearing source selection or clearing shared selection forgets the live and stored reference; source files and receipts are untouched. Failed storage updates/removal show an explicit warning rather than claiming the saved reference was deleted.

The release policy now requires 58 installed stages. The added journey remembers a real retained artifact through the UI, restarts the installed application/sidecar, requires the inactive reference with no cached preview, checks changed bytes as stale only after explicit recheck, restores/rechecks the owned fixture and verifies explicit removal. This journey is required on Windows for the exact proposed commit; local tests alone do not establish installed acceptance. The preceding fee3d708 Windows build and installed 57-stage acceptance passed; that result does not certify this new increment.

This implements opt-in retained-reference restoration for the bounded first-party source selector; installed restart acceptance remains unverified, not the full cross-domain R01/R03 goal. Smali/native/resource/virtual-member selections and unified producer/build/device verification, broader adapters, configuration authority, runtime acceptance and project retention/retrieval remain as listed in the requirement matrix. PR #141 stays draft pending complete scope and exact-head release acceptance.

### Windows regression and restart-navigation correction

Exact-head `a2cc8d8` completed 52 installed stages, including the new failed-candidate outcome journey, before the pre-restart selector step failed. The screenshot shows Settings/Analysis environment, whose sidebar intentionally replaces the session list. The journey now uses the visible **Cline home** button before selecting the saved session both before and after restart. It does not reload, force a click, bypass navigation with an RPC, omit an assertion or claim restart acceptance from the earlier stages. A helper regression asserts the ordering and failure propagation; the release policy fingerprints the corrected driver.

The separate Windows regression job passed 1,743 sidecar tests and failed the real staged-shell completion fixture with `cancelled` instead of `completed`. Its five-second stage budget included executable rehashing and the real Windows start-token probe, which alone allows five seconds. The correctness fixture now has explicit finite 30-second stage budgets and a bounded outer wait, with failing receipt diagnostics. Production deadlines, process identity checks, approval and cancellation are unchanged. A separate deliberately waiting adapter has a one-second approved deadline and must cancel without starting its dependent, so additional fixture headroom cannot silently remove deadline coverage. Windows success must be established by a new exact-head run; Linux reruns are not substitutes.

## Android candidate build outcome increment

`build_android_candidate` project receipts now identify the first-party `cline-android-project-candidate/v1` protocol and the exact assembled Smali-root set. The existing task ledger derives a bounded build summary only when the prepared project/preview fingerprints, output path, exact ordered patch/assembly/build stages, source-unchanged claim and published output digest agree. Patch stages must match the approved per-file input hashes and paths. Successful summaries explicitly identify a new **unsigned** candidate, retain its SHA256 across ledger restart/export, and never grant replay, signing, device or runtime authority. Legacy, malformed or mismatched receipts remain unavailable; blocked/cancelled builds stay partial and failed builds stay failed. Cleanup warnings make the summary partial. Scheduled private cleanup is not independently certified.

This is a read-model connection over the existing candidate orchestrator, not a second builder, engine attestation, current-file check or a completed R02/R04 workflow. Cross-task build-to-verification identity links, signing, authorized device acceptance and broader candidate workflows remain outstanding. Core integration tests run the actual project copy/patch/orchestrator with explicitly mocked assemblers/builders and assert the receipt protocol/root set; separate sidecar tests exercise approval, retention, restart/export and replay denial with an explicitly synthetic receipt and no builder invocation. Neither is real-engine or real-APK acceptance.

## Windows forced-shutdown and cancellation acceptance corrections

The exact-head `1ee1570` Windows sidecar regression passed, but its separate Hub shutdown gate failed because a watchdog-forced process exit was incorrectly required to finish asynchronous discovery deletion. The real-process test still requires authenticated shutdown, the unchanged five-second exit assertion, the unchanged production two-second watchdog, observed exact-child exit and an unreachable endpoint. It now explicitly retires any matching leftover generation with the existing ownership-checked API **after** death; mismatched replacement identity fails rather than deleting a successor. Filesystem absence is checked without dumping token-bearing discovery JSON. Existing graceful server-cleanup and replacement-generation unit coverage remain required. This does not change production shutdown or claim that forced exit completes graceful cleanup.

The isolated Execute job's one-second cancellation fixture exceeded its 30-second *test* deadline; its eight-second cancellation fixture passed after roughly 25 seconds. The outer hang guard now allows 90 seconds for integrity verification/staging, the existing host deadline, ten-second forced-stop grace and ten-second cleanup helper budget. Target execution, cancellation, cleanup and no-replay policies are unchanged. Both actual Windows cancellation cases remain required; Linux skips are not Windows acceptance.


## Installed restart failure remains open

The `1ee1570` Windows installer built and passed the binary smoke test, but the installed journey failed waiting for the inactive restored-reference message after restart. The collected evidence does not yet distinguish missing WebView device storage from a changed session/workspace scope or render behavior, so this is **not reported as fixed**. The next journey checks the exact existing device record immediately after restart, before navigation, and fails rather than reinjecting or reconstructing a missing reference. It retains a fixed owned failure screenshot before teardown. The existing inactive/no-preview, explicit stale recheck, clear and native termination assertions remain unchanged. The same real Android engine journey now also requires the unsigned candidate outcome's output hash and exact passing stage set. Required installed stage count remains 58; the driver fingerprint is refreshed.


## Explicit Android build-to-verification handoff

The evidence ledger offers **Prepare separate APK verification** only for completed first-party project builds with bounded passing unsigned-publication summaries. The host looks up the original prepared output path (never a caller- or receipt-supplied replacement), checks exact workspace ownership and freshly hashes the current bounded regular file. Missing, unreadable, oversized or changed output blocks preparation. External targets require a fresh explicit acknowledgement rather than inheriting write approval. Partial/failed/unavailable builds cannot prepare this handoff.

A distinct `validate_candidate` Inspect plan binds the exact APK SHA256, requires its own one-use approval and rechecks identity after approval. It retains the source build plan/request/result fingerprints as provenance, not authenticated engine evidence or execution authority. No auto-verification, signing, install, device execution, overwrite or build replay is introduced. APK verification reuses the existing parser/signature checks; an unsigned build is not a passing signed candidate. The new button is explicit; ordinary build completion still does not start a follow-up.

Local fixtures cover independent approval, restored provenance, modified/missing outputs, wrong workspace, external acknowledgement and partial/failed-build denial. They use deliberately non-APK synthetic bytes for identity contracts, not real-engine acceptance. UI tests cover draft-only preparation and explicit approval. The existing real installed Android project stage additionally requires an exact identity-bound awaiting-approval verification draft, rejects an invented approval token and changed candidate bytes, cancels the owned draft and restores the owned fixture. This is preparation acceptance, not signature/device/ART validation; all 58 installed stages remain required. Windows acceptance must pass at the exact proposed commit.

This closes a bounded cross-task identity-link gap, not R02/R04 or the ten-area release. Signing/device summaries, other candidate families and the remaining matrix items are still outstanding. The prior installed source-reference restart failure also remains open pending its exact-record diagnostics.

## Windows canonical receipt fixture correction

At `6497eab`, Windows isolated Execute (including cancellation), Android toolchain and Binary Triage checks passed. The Windows regression failed one synthetic ledger receipt test: a receipt constructed from the raw temporary output path did not match the host-canonical prepared path, so the strict summary correctly stayed unavailable. The installer job stopped in consolidated validation before packaging/installed acceptance; it did not provide the pending restart diagnostic.

The synthetic receipt now uses the exact host-prepared output path, as the actual builder already does. An additional aliased-workspace fixture exercises real filesystem canonicalization, requires the raw alias receipt to remain unavailable, and checks retention/restart using the canonical receipt. Handoff identity fixtures likewise use canonical existing-file paths. Production receipt equality and all release assertions remain unchanged. These fixtures are still not real APK or Windows acceptance; new exact-head Windows checks remain required. The earlier installed restart failure remains open.


## Exact Android method invoke-reference view

`trace_android_method` retains its existing exact selected-bytecode and relationship stages. The latter now uses the already pinned Androguard engine to inspect ordinary encoded DEX invoke operands, rather than parsing disassembly text or inventing calls from method-pool presence. It reports one-hop incoming/outgoing reference candidates, exact caller bytecode offsets/fingerprints, DEX identities/SHA256, referenced pool signatures and covered definition candidates. Duplicate root definitions stop selection. Multiple target definitions remain ambiguous candidates; virtual/interface/super dispatch is not resolved. Custom/polymorphic invokes stay unsupported and counted. Missing engines are blocked explicitly, never replaced with inferred calls.

Fixed scan limits are eight DEX artifacts, 32 MiB decoded DEX input, 256 coded methods, 100000 instructions, 1 MiB aggregate bytecode and at most 200 detail references (or the smaller requested limit). The selected artifact/method is scanned first. Limit hits, decode failures, unsupported invokes, detail truncation and covered work counts are explicit. Root selection without a covered definition cannot create edges. Every view remains partial/static: this is not transitive traversal, dispatch/reachability, ART verification, whole-app completeness or execution. Rejected/uncovered artifacts remain excluded; a unique covered candidate does not establish global uniqueness.

The owned two-method DEX fixture contains reciprocal static references and is never executed. Python tests exercise the real pinned Androguard parser, bad operands, duplicate multidex selection, missing engine and instruction/byte/DEX/detail budgets. The public executor retains the same evidence or explicit missing-engine state. The installed Windows journey must independently reproduce exact origins, offsets, static-only status, truncation and duplicate-definition rejection without modifying either input. Release policy now requires **59** installed stages and fingerprints the extended driver. Local parser success is not installed acceptance, and the preceding installed restart failure remains open.

This advances R04 only. Transitive traversal, dynamic JNI registration, resource-table semantics, build/sign/device summaries and the other ten-area acceptance gaps remain outstanding.


## Normal restart versus forced process termination

The exact-head `05ac0cb` Windows run passed regression, engine checks, NSIS build and installed-binary smoke. Its installed WebView journey failed because the exact saved source-reference record was missing immediately after the process-tree force kill, before navigation. This narrows the failure to device-storage continuity, not a missing inactive-state label; no storage was reconstructed or injected. It does not by itself prove whether normal native Quit persists the record.

The normal restart journey now invokes the existing native `quit_app` command exactly once and requires the exact launched child to exit with code zero before disconnecting CDP and relaunching the same private profile. Missing/nonzero exit, deadline or disconnect failure remains an acceptance failure; no forced-stop fallback turns it into a pass. A native exit can close the renderer invoke transport before its response, so confirmed child exit, not the invoke response, is authoritative. The existing forced process-tree termination remains in failure/final cleanup and other lifecycle checks. All exact-record, inactive/no-preview, explicit stale recheck, clear and Analysis Off assertions remain.

This corrects the **normal restart test lifecycle**, not the product storage implementation, and is not a claim of crash/power-loss durability. No sleeps, storage reinjection, automatic source read or approval restoration were added. Browser storage after abrupt process termination remains unverified and is explicitly outside this normal-restart acceptance. The new exact-head Windows run must establish normal restart continuity; it is not reported fixed based on local harness tests. All **59** installed stages remain required.
