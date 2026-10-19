# Integrated engineering workstation release

This is one coordinated integration branch and release, not a claim that all ten product areas or the original 55 commands are complete. No catalog entry, fixture, local test, or generated plan certifies a release. The branch must remain draft while required product acceptance or external acceptance is outstanding.

## Scope and execution order

Keep the existing Tauri/WebView → sidecar → shared Hub/SDK authority. Reuse the investigation, execution, candidate and evidence stores. Add compatible references/read models, not a second execution runtime or destructive storage consolidation.

| Requirement | Deliverable | Current branch increment | Still required for product acceptance |
| --- | --- | --- | --- |
| R01 Workspace | Shared project/artifact/selection navigation across Code, Investigate, Compare, Validate | Existing panes preserved; exact shared command interfaces visible | Unified artifact/selection read model and cross-pane navigation/restart journey |
| R02 Verification | Plan → inspect → approve → modify → validate → review with honest outcomes | Exact AI schemas shared with catalog; partial producer results cannot unlock graph consumers | Connected candidate/build/verification summaries and distinct operational/evidence outcomes |
| R03 Evidence explorer | Precise source/Smali/native/resource selections and linked provenance | Fresh JS/TS flow uses exact hash-backed fact locations; graph consumers retain producer/result/document identities | Shared visual selections, cross-domain navigation and stale-evidence display |
| R04 Android | Multidex → entrypoint → method → JNI → preview → rebuild → verify | Previous bounded Android/candidate implementations preserved | Bounded caller/callee traversal, supported dynamic-registration analysis, resource-table semantics and unified build/signature/device summary |
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

The installed release policy now requires 54 stages, including these two new named journeys. Local test results are not installed Windows results. Engine/device acceptance must name its actual authorized environment and cannot be replaced by catalog presence or owned static fixtures.
