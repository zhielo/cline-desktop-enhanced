# Integrated investigation workflows

These scoped commands use the existing `reverse_engineer` tool and desktop **Advanced AI commands** review panel. They do not create a new shell executor or relax existing prepare → exact approval → one-use execution boundaries. The original 55-command scope ledger is in `ORIGINAL_RECOMMENDATION_COVERAGE.md` and the catalog's `recommendations` field. This increment is not completion of that entire list.

## Source evidence

`trace_electron_ipc`, `audit_preload_bridge`, `map_attack_surface`, `trace_source_symbol`, `explain_behavior`, and `compare_public_api` use the shipped JS/TS parser. Files are read, never imported/evaluated. Symbol commands select one exact named function declaration; ambiguity fails rather than choosing the first result. Function evidence includes source hash, relative path, line/column and an excerpt capped at 16,384 characters. Source collection rejects symbolic links and caps depth at 8, entries at 4,096, files at 128, each source at 1 MiB and aggregate sources at 8 MiB. Neighbor traversal is capped at 8 hops/200 nodes; defaults are 4 hops/100 returned facts. Excluded build/dependency folders and parser limitations remain explicit.

```json
{"operation":"explain_behavior","target":"/absolute/owned-project/src/owned.ts","workflow_query":{"symbol":"ownedFunction","max_depth":4,"max_results":100},"timeout_ms":120000}
```

`compare_public_api` takes a second JS/TS file/directory in `compare_target`. It compares top-level exported declaration names and explicit syntax signatures (parameter/return/type syntax and selected public class members), excluding function bodies. Changed signatures are not automatically breaking changes. Inferred types, resolved reexports and ABI compatibility remain unresolved. `inspect_dependency_risk` reads a selected package.json; optional hash-bound lockfile/advisory evidence is described below. Unknown risk is not a clean bill of health.

`map_dotnet_interop` reads bounded PE/CLI ImplMap and ModuleRef declarations without loading the CLR/native library. It validates referenced metadata rows and returns flags, member token, import/module names and metadata offsets. It does not establish runtime resolution, marshaling correctness or COM mappings.

## Android and native orchestration

- `find_android_entrypoints` reads fresh bounded manifest/root-multidex evidence for exact lifecycle callback declaration candidates and superclass origins. Dynamic listeners, actual framework dispatch and lifecycle reachability remain unresolved.
- `trace_android_method` requires `advanced_options.method` with exact class descriptor/name/descriptor, and coordinates selected bytecode plus relationship evidence.
- `diff_android_resources` compares actual covered ZIP-member SHA256 bytes and optional namespace-expanded XML structure. Legacy APK comparison remains separate; neither CRC/size equality nor byte/structural equality establishes resource-table or behavioral equivalence.
- `preview_android_candidate` accepts a decoded Apktool project, a new absolute `.apk` output outside it and `android_project_patch.patches`. Each entry supplies a confined `smali/...smali` or `smali_classesN/...smali` path and the existing exact-method `patch` fields. It returns whole-project and preview SHA-256 values, exact diffs, planned output and budgets; it does not probe engines, publish an APK or grant write approval.
- `build_android_candidate` with that same request additionally requires `android_project_patch.expected_project_sha256` and `preview_sha256`, and a separate exact-request Modify approval. It snapshots the project privately, applies up to 32 exact-method edits (one per file), assembles every recognized Smali root, and reuses the existing Apktool builder. It checks original/candidate fingerprints and the bounded structural/hash receipt before atomically publishing a new unsigned APK without overwrite. Inputs are limited to 25,000 entries, 512 MiB, 48 directory levels and 32 Smali roots, with a total deadline of at most 10 minutes. Failed stages do not publish; unconfirmed engine termination retains the private workspace rather than deleting active inputs. This is not a sandbox, signing workflow, semantic-equivalence proof, device test or ART compatibility guarantee.
- Without `android_project_patch`, `build_android_candidate` retains its existing immutable unsigned rebuild-and-inspect behavior. A published legacy build receipt survives later inspection failure/cancellation.
- Owned real-engine coverage patches one primary method, assembles primary and secondary roots, rebuilds and decodes the APK, and confirms the changed method plus preserved secondary class and original source. Installed acceptance additionally exercises separate preview/write approvals through the packaged sidecar; unit engine stubs alone are not evidence of a working APK.
- `verify_android_candidate` coordinates inspection, signature checks and optional comparison against `compare_target`. Assembly/build receipts and device acceptance remain separate.
- `resolve_native_symbol`, `trace_native_calls`, `decompile_function_bundle`, and `compare_native_functions` select one bounded ELF function using `function_selector`. Decompilation additionally requires explicit `engine: "ghidra"` or `"ida"`. Comparison selects the same exact symbol/address in both images, not an inferred semantic match. Caller discovery/transitive traversal remain incomplete.
- `inspect_binary_mitigations` parses bounded PE/ELF header declarations only: no image execution, mitigation-enforcement or exploitability verdict.
- `annotate_analysis_project` reuses existing isolated project preview/candidate/rollback with `project_edit` and an exact native selector. It still requires Modify capability and reviewed project-state/pointer requirements, even for preview; no target executable is rewritten.
- `explain_decompiler_disagreement` compares two selected-function evidence JSON files. Imported outputs are untrusted; no winning decompiler or authenticated same-image identity is inferred.

Other-file `compare_versions` performs a bounded fixed-offset byte comparison (16 MiB per file), hashes both inputs and returns at most 200 differing spans with an explicit total/truncation flag.

## Hypotheses and notebook preview

`verify_hypothesis` checks a strict exact declared-node/declared-edge predicate against a validated saved graph or supported first-party static report. The descriptive statement is data, never instructions. Unknown endpoints are inconclusive; absence of a report edge cannot prove absence of runtime behavior.

```json
{"operation":"verify_hypothesis","target":"/absolute/owned/graph.json","hypothesis":{"statement":"Check this declared reference only","kind":"declared-edge","node_id":"a","target_id":"b","relation":"references-candidate","expected":true}}
```

`preview_batch` validates the real existing confined static notebook DAG, returns input/config fingerprints, dependencies, approval points and budgets, and runs no engines. It does not turn a notebook into mixed-effect execution. `run_batch`/`resume_investigation` still use the existing static notebook runner and fingerprint invalidation; candidate batches and runtime work remain distinct workflows.

## Result and release boundaries

Orchestrated stages share one deadline (default 120 seconds; capped at 600 seconds). Real advanced-result provenance wrappers are preserved. Blocked, failed, partial and cancelled child outcomes are distinguished; failed prerequisites do not trigger dependent engine runs, and cancellation retains already-published candidate receipts. These are bounded application controls, not OS isolation or a hard preemptive CPU sandbox.

New commands are included in the blocking advanced regression suite. Installed WebView acceptance additionally exercises exact-function source evidence, declared hypothesis verification, real notebook preview, original preservation and the exact 55-command ledger. Fixture tests do not establish compatibility with arbitrary engines/targets, and no catalog entry certifies release. Require the exact-current-head Windows setup.exe build, installed-binary smoke, installed WebView acceptance and all other applicable required checks before merge.


## Exact-range dual-engine disassembly

`crosscheck_disassembly` invokes both installed **Capstone and Miasm** through the existing supervised Python worker. It uses a single captured byte slice and explicit architecture, file offset, virtual address and byte count. It never executes the analyzed target. Missing either engine blocks the workflow; there is no single-engine fallback. Each engine retains version, decoded byte count and instruction evidence. The merged comparison identifies instruction boundary/byte differences, not semantic correctness or a winning engine. Undecoded bytes and instruction-budget exhaustion produce partial status and never prefix-only agreement. The same `native_crosscheck` action is available in static notebooks for existing checkpoint/resume behavior.

```json
{"operation":"crosscheck_disassembly","target":"/absolute/owned.bin","advanced_options":{"architecture":"x86_64","offset":0,"address":4096,"bytes":4},"max_results":200,"timeout_ms":120000}
```

Supported modes are x86, x86_64, ARM little-endian, Thumb little-endian and AArch64 little-endian. Limits: 65,536 selected bytes, at most 1,000 instructions per engine and the existing supervised time/output budgets. Architecture/mode and code/data identification remain caller responsibilities.

## Hash-bound dependency evidence

Optional `dependency_evidence` selects an absolute npm `package-lock.json` v2/v3 and its SHA-256. Registry versions retain nested package locations; workspace links and unresolved entries remain explicit. The adapter never installs packages, executes scripts or reads registry URLs into output.

```json
{"operation":"inspect_dependency_risk","target":"/absolute/package.json","dependency_evidence":{"lockfile":"/absolute/package-lock.json","lockfile_sha256":"<64 lowercase hex>","advisory_snapshot":{"path":"/absolute/osv-snapshot.json","sha256":"<64 lowercase hex>"}}}
```

The optional imported OSV snapshot shape is `{schemaVersion:1,source:"OSV",retrievedAt:"ISO UTC",advisories:[...]}`. Advisory objects contain `id`, `modified`, optional `withdrawn`, and OSV `affected` package/versions/ranges entries. Only exact `affected.versions` membership for npm is evaluated. Withdrawn records are excluded; ranges are reported as unevaluated. SHA verification binds selected bytes, **not publisher identity, advisory completeness or freshness**. Risk remains unknown, even when no match appears. Select snapshots from trusted sources and review their provenance separately. Limits: 8 MiB per lockfile/snapshot, 10,000 lock entries, 2,000 advisories, 200,000 comparison work units and 2,000 returned matches/range limitations.

## Selected redacted provenance archive

`export_evidence_bundle` with `evidence_archive` reads a hash-bound selected manifest and publishes a **new** `.json.gz` portable evidence container. It requires Modify approval and never overwrites a file. Without this option the legacy forensic-report path remains available. The archive contains selected JSON/text findings, receipts, logs and limitations, with separate original and exported-content SHA-256 hashes; it omits original filesystem paths and never includes raw binary payloads.

```json
{"operation":"export_evidence_bundle","target":"/absolute/evidence/manifest.json","output_file":"/absolute/evidence/export.json.gz","evidence_archive":{"manifest_sha256":"<64 lowercase hex>"},"acknowledge_external_output":true}
```

Manifest shape: `{schemaVersion:1,title:"Selected evidence",entries:[{id:"receipt",path:"receipt.json",sha256:"<64 lowercase hex>",kind:"receipt",format:"json"}]}`. Paths are confined relative files under the manifest directory; symlinks, traversal, duplicate IDs/paths, changed hashes and overwrite attempts fail. Entry kinds: finding, receipt, log, limitations; formats: json or text. Limits: 32 entries, 1 MiB per entry, 8 MiB aggregate input, 12 MiB serialized export, JSON depth 32 / 20,000 nodes per entry. It redacts known sensitive environment values, credential patterns and sensitive JSON keys. **Unknown secrets may remain: review before sharing.** Imported tool/version/producer claims are retained as untrusted evidence, not authenticated attestations. Source files never execute or change.

The installed Windows journey additionally checks explicit API changes, hash-bound lockfile evidence, approved archive publication/original preservation, and real Capstone/Miasm range comparison after installing the full engine pack. This does not certify the remaining runtime or mixed-effect workflow gaps.


## AI durable static batch front door

The desktop now exposes standalone `plan_batch`, `preview_batch`, `run_batch`,
`checkpoint_investigation`, `resume_investigation` and `cancel_batch` tools. These
are host investigation tools, distinct from the older `reverse_engineer`
notebook-operation aliases. They reuse `ExecutionControlService`, not another runner.

- An attached Full Access local owning session and enabled Analysis are required
  for new work; restricted permission profiles are never widened. Checkpoint and
  cancellation remain available for cleanup after Analysis is disabled.
- The strict model schema accepts at most twelve built-in `inspect`, `scan_strings`
  and `compare_apks` stages, two parallel reads, bounded output and per-stage time.
  Dependencies determine order only. All targets must already exist in the workspace
  as regular files no larger than 64 MiB. Produced-input chaining is not implemented.
- Preview validates without creating a plan or execution receipt. Run prepares a
  canonical hash-bound plan, requests independent human approval and consumes a
  host-private one-use token. The model never supplies owner, token, mode or consent.
- Start returns an asynchronous receipt ID, **not success**. Checkpoint reads the
  existing durable revision, input fingerprints, stage results and integrity hash.
  Receipts are owning-session-bound even when two sessions share a workspace.
- Resume accepts an exact certain terminal revision, verifies all original input
  fingerprints and the executing implementation fingerprint, and validates retained
  completed results before reusing dependencies. It prepares a new separately
  approved continuation containing only never-started stages. Failed or started
  stages are never retried automatically; unresolved dependencies block continuation.
  Both preparation and execution recheck reused input evidence. Interrupted-host
  uncertain work requires explicit reconciliation, not replay through this command.
- Top-level and nested failed, blocked, partial, cancelled or uncertain adapter
  statuses cannot unlock dependencies. Returned evidence is retained when adapter
  completion races cancellation; that does not turn cancellation into success.

This front door does **not** yet orchestrate candidate writes, shell, debuggers,
external engines or runtime observation. Those existing separately approved
workbenches remain separate; this is not a claim that all 55 recommendations are
complete. Installed Windows acceptance exercises preview, independent approval,
real built-in inspect/string DAG results, durable checkpoints and completed-stage
replay denial. Cancellation/resume edge cases are additionally covered by focused
runner and approval tests, not claimed as live hardware/runtime coverage.


## Hash-bound candidate validation and recipe review

`validate_candidate` and `review_candidate_changes` are standalone AI tools over the existing static approval/task infrastructure. Open a workspace-confined immutable handle with `open_binary` first. Both commands require fresh independent human approval; models cannot provide session identity, phase, approval tokens or consent. Restricted permission profiles remain restricted.

- `validate_candidate({artifactId, kind})`: choose `javascript`, `typescript`, `dex` or `apk`. JS/TS runs parse diagnostics without evaluating code (1 MiB); DEX checks supported standard 035–040 headers, SHA1/Adler32 and fixed-width table extents (16 MiB); APK uses the existing container inspector and installed `apksigner`. No downloads, signing, rebuilding, target execution or installation. Missing checks are not passes. DEX 041/compact DEX, complete bytecode verification, type checking, JSX/TSX and behavioral equivalence are not supported.
- `review_candidate_changes({artifactId})`: select an immutable candidate-batch manifest. Reuses exact AST/managed/JVM/byte recipe reconstruction and source preservation checks. Missing candidates are partial; mismatched or unverified candidates fail. Only declared input/output pairs, not undeclared files or an entire project. A recipe is not itself human approval.

Receipts use `cline-candidate-verification/v1`, with input hashes, bounded check results, limitations and canonical SHA256 integrity fingerprints, persisted through existing immutable owning-session task evidence. Hashes prove integrity, not producer authentication or correctness. Source and manifest mutation invalidates the operation. These additions do not complete runtime, mixed-effect chaining, whole-project scope or semantic-analysis recommendations.

### Read-only Node runtime observation planning

`plan_runtime_observation({artifactId, observation:{backend:"node-inspector",pid,processToken,endpoint,durationMs,captureConsole}})` accepts an immutable owning-session source handle and an exact live local Node Inspector listener. The independently approved static plan checks the source hash and OS PID/birth/listener ownership before and after producing a canonical hash-bound receipt. Linux/Windows only; selected source is limited to 1 MiB, observation duration to 200–5000 ms. Console capture defaults off; the existing observer caps it at 24 reports.

Planning makes **no socket connection, debugger attachment, target launch, evaluation or resume**. Static mode may prepare this plan, but does not authorize the proposed observation. The receipt's `nextRequest` is a request preview, not a token: use the existing `first_party_analysis_inspector_prepare` / independently approve / `first_party_analysis_inspector_run` workbench in Runtime or Hybrid mode. Hybrid additionally needs its owning static-evidence proposal. The runtime host rebinds and rechecks process identity, source hash, mode and one-use approval; stale plans are not reusable authority.

OS listener ownership does not authenticate the Inspector protocol or prove that the chosen source is loaded. The existing actual observer reconciles loaded-source bytes separately. Native/JVM/Android planning and complete execution tracing remain incomplete. The separate managed Node and metadata commands below have narrower independently approved capabilities; this planner does not authorize them.

## Independently approved runtime metadata capture

`capture_process_tree` and `capture_file_activity` are desktop AI tools, not static executor aliases. Open one immutable workspace file with `open_binary` first. Static/Off modes reject both commands. Runtime requires fresh exact-request Debug approval; Hybrid additionally requires an intact owning-session static receipt/task for the exact current artifact. The model never supplies a permission, PID birth identity or approval token. Host preparation binds process identity; one-use approval is consumed only for the same session, workspace, file hash, options and evidence basis. Two concurrent captures globally and one per owning session maximum. Task cancellation, scope/mode changes, errors and deadlines close observation resources.

- `capture_process_tree`: Linux `/proc` or Windows CIM snapshot; up to 4,096 scanned processes and 128 returned root/descendants. Root PID/birth checked before and after. No names, command lines, environment, paths or memory. The opened artifact is an evidence basis, not proof that it executes in the selected process. Ancestry is non-atomic and descendants can race/reparent. Results are partial, never causal execution traces.
- `capture_file_activity`: `fs.watch` on exactly the selected regular file (maximum 1 MiB at registration), 200–5,000 ms and 1–128 events. Emits only event kinds/times. No contents, sibling names, recursive directories, syscalls or PID attribution. Rename/replacement ends observation. Notification coalescing and missed/read-only access mean even a successful deadline or empty event list cannot prove absence of activity. The watcher never writes the file.

These commands do not attach a debugger, evaluate source, resume/launch/kill the target or establish managed debugger support. The separate managed Node commands below add independently approved debug control; these metadata commands do not grant that authority.


## Bounded managed Node Inspector commands

These desktop AI commands operate only on an explicitly selected owned local Node Inspector endpoint. They do not add native/JVM/Android debugger parity or certify all 55 recommendations.

1. `attach_debug_session({artifactId,pid,endpoint,lifetimeMs})`: open an immutable confined file first. Fresh independent **Execute/debug-control** approval binds host-only PID birth identity, source hash, exact loopback endpoint, owning session/workspace and Hybrid evidence when applicable. Runtime/Hybrid, attached Full Access only. The host reconciles the exact loaded script bytes at attachment and before/after follow-up control. The 128-request lifetime budget reserves three requests for cleanup. A missing/ambiguous script fails without initiating execution. Lifetime defaults to 60 seconds, maximum 120, maximum two connections globally/one per owner.
2. `set_scoped_breakpoints({runtimeSessionId,locations:[{line,column}]})`: a new exact one-use Execute approval; maximum eight total unconditional zero-based locations in the selected script. No expressions, conditions or logpoints. These breakpoints **can pause execution**; no automatic continuation is offered.
3. `capture_execution_trace({runtimeSessionId,durationMs})`: a new exact one-use Execute approval, but the actual implementation is **V8 statistical CPU sampling, not a complete execution trace**. 200–2,000 ms, 1 ms requested sampling interval, maximum 128 selected-script nodes/256 samples. Function names hashed, unrelated scripts/paths excluded. No chronological call log, causal conclusion or absence-of-execution claim.
4. `stop_runtime_session({runtimeSessionId})`: owning connection cleanup, available after Analysis Off without manufacturing new work consent. Attempts owned profiler stop/disable and debugger disable, then closes transport within bounded protocol/close deadlines (at most four seconds). Cancellation, errors, mode/scope changes, lifetime expiry and graceful sidecar shutdown also clean up. Closed receipts are owner-bound and cached for idempotent stop (128 maximum); no reconnect/replay after restart.

**Debugger activation and cleanup/disconnect may pause or resume the target.** This is why even attachment/sampling requests require Execute, not merely passive Debug permission. There is no evaluate, launch, step, explicit resume or target kill command. Inspector engine state can be shared with other clients; exclusive ownership and removal of another client's state are not claimed. Cleanup uncertainty is returned as partial and never treated as proof of target exit or subsequent execution state. All observations are bounded, untrusted evidence, not instructions to the model. Mode/scope changes close connections on a 100 ms host poll. A process restart or source change invalidates follow-up operations.


## Saved static/runtime correlation

`correlate_static_runtime({receiptId,taskIds})` reads one owning static receipt and one to ten explicit saved task snapshots, including at least one runtime task. It never repeats observations or grants consent. Session/workspace and result/snapshot hashes must match; missing, duplicate, corrupt or cross-owner evidence fails closed. Exact artifact-byte matches remain distinct from behavior claims. Retained managed Node CPU samples can link to same-source function-definition-line **candidates**, not sampled instruction/call-path proof; shared lines/nested functions may be ambiguous. Native dossiers retain supported exact process-birth/module/architecture/RVA observation rules, never inferred relocation. Inputs are capped at 12 MiB, output at 1 MiB, candidate links at 64 per sampling task and native dossiers at 50. Unsupported identities remain unresolved. All output is untrusted saved evidence, not instructions; partial original55 coverage remains explicit.


For shared AI/static command interfaces, typed graph-output DAGs, fresh source-flow mode and the full ten-area release acceptance checklist, see [Integrated release plan](INTEGRATED_RELEASE_PLAN.md).
