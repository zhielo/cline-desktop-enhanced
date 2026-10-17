# Original recommendation coverage

This is the exact original 55-command checklist, not a statement that all recommendations are implemented. `bounded` means a scoped implementation exists, not installed validation or release certification. `partial` and `not-implemented` are explicit remaining work. Aliases do not certify complete workflows. Runtime remains separately opt-in.

## cross-tool

| Command | Scope | Remaining boundary |
| --- | --- | --- |
| `plan_investigation` | partial | Fixed recipe proposals; no general goal-to-DAG planner or engine preflight. |
| `identify_artifact` | partial | Existing format inspection; nested or ambiguous containers require separate inspection. |
| `map_attack_surface` | partial | JS/TS syntax and APK manifest evidence; no universal entrypoint inventory. |
| `trace_data_flow` | partial | Declared saved-report edges only; unresolved whole-program paths are not inferred. |
| `trace_cross_language` | partial | Saved validated graph paths; no universal JNI or Electron resolver. |
| `explain_behavior` | partial | Exact JS/TS function evidence and relationships; no generated behavioral verdict. |
| `compare_versions` | partial | APK ZIP-entry or bounded byte comparison; not a combined semantic/API report. |
| `query_investigation` | bounded | Existing bounded saved investigation query adapter; no automatic reruns. |
| `verify_hypothesis` | bounded | Exact node/edge predicates in a selected untrusted report; unknown endpoints remain inconclusive. |

## android

| Command | Scope | Remaining boundary |
| --- | --- | --- |
| `index_multidex` | bounded | Existing bounded DEX index adapter retains DEX origin; engine readiness separate. |
| `find_android_entrypoints` | partial | Manifest components only; lifecycle/callback expansion unresolved. |
| `trace_android_method` | partial | Exact method code and reference candidates; no full dispatch/call graph. |
| `map_jni_bindings` | partial | JNI-name and relationship candidates; unresolved dynamic registration is not invented. |
| `preview_smali_patch` | bounded | Exact hash-bound single-method/single-file preview. |
| `patch_smali_method` | bounded | Approved preview publishes one new file; project integration is separate. |
| `validate_smali_project` | bounded | Existing assembler over supported inputs with new output; no ART/device proof. |
| `diff_android_resources` | partial | ZIP-entry size/CRC comparison; no decoded resource semantic diff. |
| `build_android_candidate` | partial | Existing unsigned Apktool rebuild plus inspection; no integrated patch-project pipeline. |
| `verify_android_candidate` | partial | Structure, signature and optional ZIP comparison; build receipts/device checks remain separate. |

## native

| Command | Scope | Remaining boundary |
| --- | --- | --- |
| `resolve_native_symbol` | partial | Selected bounded ELF function evidence; not every binary format or symbol kind. |
| `decompile_function_bundle` | partial | Selected native evidence and explicit Ghidra/IDA output; caller discovery remains incomplete. |
| `trace_native_calls` | partial | Selected direct/indirect call candidates; no transitive call traversal. |
| `compare_native_functions` | partial | Same exact selector in both images; no inferred semantic match confidence. |
| `inspect_binary_mitigations` | bounded | Bounded PE/ELF header declarations only; no mitigation enforcement claim. |
| `annotate_analysis_project` | bounded | Existing isolated exact-state project preview/candidate/rollback; no executable rewriting. |
| `crosscheck_disassembly` | not-implemented | No unified exact-range dual-engine comparison command. |
| `explain_decompiler_disagreement` | partial | Compares imported selected-function evidence; does not authenticate or rerun engines. |

## source

| Command | Scope | Remaining boundary |
| --- | --- | --- |
| `trace_electron_ipc` | partial | Bounded JS/TS syntactic IPC candidates; not observed channel execution. |
| `audit_preload_bridge` | partial | Exposed bridge/configuration evidence; no vulnerability or validator-correctness verdict. |
| `trace_source_symbol` | bounded | One exact JS/TS function declaration and bounded declared neighbors; no universal language support. |
| `preview_ast_transform` | bounded | Existing supported primitive literal transforms; parser-backed exact offsets. |
| `apply_ast_transform` | bounded | Hash-bound approved candidate transform; no arbitrary AST program rewriting. |
| `map_dotnet_interop` | partial | ImplMap/PInvoke declarations only; COM, marshaling and runtime resolution unresolved. |
| `compare_public_api` | partial | JS/TS top-level export declarations; no signature/type/ABI or resolved reexport comparison. |
| `inspect_dependency_risk` | partial | Declared package.json dependencies; resolved versions and verified advisory matching unavailable. |

## runtime

| Command | Scope | Remaining boundary |
| --- | --- | --- |
| `plan_runtime_observation` | not-implemented | Existing separate runtime workbenches; no unified bounded observation-plan command. |
| `attach_debug_session` | not-implemented | Existing one-shot debugger attach is not a persistent managed session. |
| `set_scoped_breakpoints` | not-implemented | Persistent session-scoped breakpoint lifecycle not implemented. |
| `capture_execution_trace` | not-implemented | No unified supervised execution-trace command. |
| `capture_process_tree` | not-implemented | No bounded target-owned process-tree command. |
| `capture_file_activity` | not-implemented | No unified target-scoped file activity capture command. |
| `capture_network_metadata` | partial | Explicit built-in browser scenario metadata only; not arbitrary process interception. |
| `correlate_static_runtime` | partial | Existing Android investigation evidence correlation, not a unified command. |
| `run_device_smoke_test` | partial | Existing separately approved Android worker/device flows; unified command and live hardware validation pending. |
| `stop_runtime_session` | not-implemented | Existing backend-specific cancellation; no unified persistent runtime session lifecycle. |

## bulk

| Command | Scope | Remaining boundary |
| --- | --- | --- |
| `plan_batch` | partial | Fixed investigation recipe alias; not a general mixed-effect dependency planner. |
| `preview_batch` | partial | Real confined static notebook DAG preview; no candidate-write/runtime stages. |
| `run_batch` | partial | Existing bounded static notebook runner; no mixed-effect orchestration. |
| `checkpoint_investigation` | partial | Durable cases and notebook checkpoints exist; no unified checkpoint command. |
| `resume_investigation` | partial | Existing matching static notebook fingerprints; not mixed-effect replay. |
| `cancel_batch` | partial | Existing execution-workspace cancellation; no unified command across runners. |
| `validate_candidate` | partial | Artifact-specific checks exist; no unified dispatch/verification receipt. |
| `review_candidate_changes` | partial | Existing candidate receipt audit and diffs; no unified approved-scope review command. |
| `export_evidence_bundle` | partial | Existing forensic JSON/HTML report adapter; no full redacted provenance archive. |
| `check_release_gate` | partial | Existing exact-head CI/installed checks; no AI command or immutable gate receipt. |

## Release contract

Local unit/fixture tests do not establish installed-engine compatibility. Only merge the exact proposed head after all applicable required CI, Windows setup.exe build, installed-binary smoke and installed WebView acceptance pass. Every later commit invalidates earlier-head release checks. Live debugger/device flows need their own authorized environment acceptance; never infer it from a command name or fixture.
