# Integrated investigation workflows

These scoped commands use the existing `reverse_engineer` tool and desktop **Advanced AI commands** review panel. They do not create a new shell executor or relax existing prepare → exact approval → one-use execution boundaries. The original 55-command scope ledger is in `ORIGINAL_RECOMMENDATION_COVERAGE.md` and the catalog's `recommendations` field. This increment is not completion of that entire list.

## Source evidence

`trace_electron_ipc`, `audit_preload_bridge`, `map_attack_surface`, `trace_source_symbol`, `explain_behavior`, and `compare_public_api` use the shipped JS/TS parser. Files are read, never imported/evaluated. Symbol commands select one exact named function declaration; ambiguity fails rather than choosing the first result. Function evidence includes source hash, relative path, line/column and an excerpt capped at 16,384 characters. Source collection rejects symbolic links and caps depth at 8, entries at 4,096, files at 128, each source at 1 MiB and aggregate sources at 8 MiB. Neighbor traversal is capped at 8 hops/200 nodes; defaults are 4 hops/100 returned facts. Excluded build/dependency folders and parser limitations remain explicit.

```json
{"operation":"explain_behavior","target":"/absolute/owned-project/src/owned.ts","workflow_query":{"symbol":"ownedFunction","max_depth":4,"max_results":100},"timeout_ms":120000}
```

`compare_public_api` takes a second JS/TS file/directory in `compare_target`. It compares top-level exported declaration names, not resolved reexports, types, signatures or ABI compatibility. `inspect_dependency_risk` reads a selected package.json and distinguishes declared dependencies from unresolved versions and unqueried advisories. Unknown risk is not a clean bill of health.

`map_dotnet_interop` reads bounded PE/CLI ImplMap and ModuleRef declarations without loading the CLR/native library. It validates referenced metadata rows and returns flags, member token, import/module names and metadata offsets. It does not establish runtime resolution, marshaling correctness or COM mappings.

## Android and native orchestration

- `find_android_entrypoints` reads bounded manifest/component evidence from the existing APK security report; callbacks and lifecycle reachability remain unresolved.
- `trace_android_method` requires `advanced_options.method` with exact class descriptor/name/descriptor, and coordinates selected bytecode plus relationship evidence.
- `diff_android_resources` and APK `compare_versions` reuse bounded APK entry comparison. ZIP CRC/size equality is not cryptographic or semantic equivalence.
- `build_android_candidate` requires a decoded Apktool project plus an absolute new `.apk` output. It reuses the existing immutable unsigned builder and then inspects the candidate; it does not patch a project, sign or install. A published build receipt survives later inspection failure/cancellation.
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
