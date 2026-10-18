# Original recommendation coverage

This is the exact original 55-command checklist, not a statement that all recommendations are implemented. `bounded` means a scoped implementation exists, not installed validation or release certification. `partial` and `not-implemented` are explicit remaining work. Aliases do not certify complete workflows. Runtime remains separately opt-in.

## cross-tool

| Command | Scope | Remaining boundary |
| --- | --- | --- |
| `plan_investigation` | partial | Fixed recipes plus explicit typed objectives and schema-validated read-only batch drafts; no arbitrary natural-language goal synthesis or executed engine preflight. |
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
| `build_android_candidate` | bounded | Preview-bound decoded-project snapshot, exact-method patches, all Smali roots assembled, unsigned Apktool rebuild and hash/structure validation before new-file publication. No signing/install/device proof. |
| `verify_android_candidate` | partial | Structure, signature and optional ZIP comparison; build receipts/device checks remain separate. |

## native

| Command | Scope | Remaining boundary |
| --- | --- | --- |
| `resolve_native_symbol` | partial | Selected bounded ELF function evidence; not every binary format or symbol kind. |
| `decompile_function_bundle` | partial | Selected native evidence and explicit Ghidra/IDA output; caller discovery remains incomplete. |
| `trace_native_calls` | partial | Bounded breadth-first direct-call ELF symbol-entry traversal, cycle deduplication, explicit unresolved/indirect/ambiguous edges and depth/function/edge/byte budgets. No complete CFG, tail-call/import resolution, caller discovery or observed runtime path. |
| `compare_native_functions` | partial | Same exact selector in both images; no inferred semantic match confidence. |
| `inspect_binary_mitigations` | bounded | Bounded PE/ELF header declarations only; no mitigation enforcement claim. |
| `annotate_analysis_project` | bounded | Existing isolated exact-state project preview/candidate/rollback; no executable rewriting. |
| `crosscheck_disassembly` | bounded | Actual Capstone/Miasm exact raw range, explicit architecture/offset/address, boundary and byte comparison. No semantic equivalence or code/data proof. |
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
| `compare_public_api` | partial | JS/TS explicit syntax signatures and public class members; no inferred type/ABI or resolved reexport comparison. |
| `inspect_dependency_risk` | partial | Declared package.json plus explicit hash-bound npm lock v2/v3 and imported OSV exact-version evidence. Range events, publisher authority and freshness remain unresolved. |

## runtime

| Command | Scope | Remaining boundary |
| --- | --- | --- |
| `plan_runtime_observation` | partial | Approved read-only immutable-source plan for live local Node Inspector PID/birth/listener, Linux/Windows; no socket connection, attachment or execution. Fresh Runtime/Hybrid Debug approval remains separate. Native/JVM/Android planning and persistent sessions remain incomplete. |
| `attach_debug_session` | partial | Independently Execute-approved 1–120-second managed local Node Inspector session, exact PID/birth/listener and loaded-source hash. Debugger activation/cleanup may pause/resume. No evaluate/launch/step/explicit resume, exclusive ownership or native/JVM/Android parity. |
| `set_scoped_breakpoints` | partial | Fresh Execute approval for up to eight unconditional zero-based locations in one exact hash-matched managed Node script. Can pause target; no conditions/logpoints/evaluation or automatic continuation. |
| `capture_execution_trace` | partial | Fresh Execute approval for 200–2000 ms selected-script V8 CPU sampling, not a full execution trace. 128 selected nodes/256 samples; names hashed, unrelated script metadata excluded. Missing samples do not prove no execution. |
| `capture_process_tree` | partial | Freshly approved Linux /proc or Windows CIM ancestry snapshot with exact root PID/birth rechecks and bounded output. Non-atomic, not execution tracing or artifact/process execution proof. |
| `capture_file_activity` | partial | Freshly approved exact-file OS notifications, maximum 5 seconds/128 events, cancellation/mode-change cleanup. No contents, recursive watch, syscall or PID attribution; missed/coalesced notifications prevent completeness claims. |
| `capture_network_metadata` | partial | Explicit built-in browser scenario metadata only; not arbitrary process interception. |
| `correlate_static_runtime` | partial | Owning-session hash-checked saved static/task evidence reconciliation, selected Node sample definition-line candidates and supported native module/RVA observations. No new runtime work, causality proof or universal cross-domain mapping. |
| `run_device_smoke_test` | partial | Unified AI adapter over approved Android launch/incident workflow with exact base APK identity and owning status/cancel. No install/root/UI automation/automatic force-stop. Live hardware, splits and regression success remain unverified. |
| `stop_runtime_session` | partial | Owning managed Node connection only, including after Analysis Off. Bounded best-effort owned profiler/debugger cleanup and transport closure; no process kill. Disconnect may resume target; uncertainty stays partial. Not a universal backend stop. |

## bulk

| Command | Scope | Remaining boundary |
| --- | --- | --- |
| `plan_batch` | partial | AI front door validates a 12-stage static DAG over existing hash-bound files, including source/Electron/.NET/mitigation/comparison and saved-graph adapters; writes/runtime/external engines remain separate. |
| `preview_batch` | partial | AI front door previews canonical input hashes (including both comparison files), dependency/budget checks and strict adapter scope. No approval, execution, writes/runtime or external engines. |
| `run_batch` | partial | Freshly approved durable static DAG including bounded source/comparison/saved-graph reads. Partial evidence is retained, blocks dependents and allows independent reads; true failures stop work. No mixed-effect orchestration. |
| `checkpoint_investigation` | partial | AI command reads the latest owning-session durable execution receipt, revision and stage evidence; it does not force a new flush or unite all evidence stores. |
| `resume_investigation` | partial | AI continuation revalidates exact terminal revision, input/implementation/result fingerprints and resumes only never-started built-in static stages with fresh approval. No started-stage/write/runtime replay. |
| `cancel_batch` | partial | Owning-session AI command cancels its durable batch through the existing supervisor; terminal confirmation is read separately. Other runners remain separate. |
| `validate_candidate` | partial | Unified approved hash-bound JS/TS parse diagnostics, standard DEX header/integrity/extents and APK structure/signature checks. No arbitrary-format, type/VM/device/build/semantic-equivalence verification. |
| `review_candidate_changes` | partial | Unified approved exact-recipe audit with immutable receipt hash; missing/mismatched/unverified candidates do not pass. Recipe mode audits declared pairs; explicit project-inventory proposes an unapproved draft and project-files mode checks two exact complete regular-file inventories against the change allowlist, including undeclared additions/deletions/edits. Empty-directory/metadata/hostile-race/behavioral verification remains outside scope. |
| `export_evidence_bundle` | partial | Approved gzip JSON archive of hash-bound selected text findings/receipts/logs with source/export hashes and redaction. Unknown secrets, completeness and producer authenticity remain unverified. |
| `check_release_gate` | partial | Unified independently approved public-GitHub exact-head verifier with authenticated bounded core/engine/installed artifacts and owning immutable receipts. Finite pinned policy only; no signing, private/expired artifact fallback, automatic merge or universal release correctness. |

## Release contract

Local unit/fixture tests do not establish installed-engine compatibility. Only merge the exact proposed head after all applicable required CI, Windows setup.exe build, installed-binary smoke and installed WebView acceptance pass. Every later commit invalidates earlier-head release checks. Live debugger/device flows need their own authorized environment acceptance; never infer it from a command name or fixture.

### Runtime metadata increment

`capture_process_tree` now has a bounded Linux/Windows independently approved desktop AI implementation (exact root birth identity, non-atomic ancestry metadata only). `capture_file_activity` now has exact-file bounded OS-notification capture with cancellation/mode-change cleanup, not process-attributed syscall tracing. Both remain **partial** against the original broader recommendation. The original 55-command ledger remains the source of scope; no overall completion or release certification is implied.
