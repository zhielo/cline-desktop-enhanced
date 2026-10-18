/** Exact original 55-command scope ledger. Never a release/tool-readiness attestation. */
export const RECOMMENDATION_COVERAGE = [
	{
		group: "cross-tool",
		command: "plan_investigation",
		scope: "partial",
		limitations:
			"Fixed recipes plus explicit typed objectives and schema-validated read-only batch drafts; no arbitrary natural-language goal synthesis or executed engine preflight.",
	},
	{
		group: "cross-tool",
		command: "identify_artifact",
		scope: "partial",
		limitations:
			"Existing format inspection; nested or ambiguous containers require separate inspection.",
	},
	{
		group: "cross-tool",
		command: "map_attack_surface",
		scope: "partial",
		limitations:
			"JS/TS syntax and APK manifest evidence; no universal entrypoint inventory.",
	},
	{
		group: "cross-tool",
		command: "trace_data_flow",
		scope: "partial",
		limitations:
			"Declared saved-report edges only; unresolved whole-program paths are not inferred.",
	},
	{
		group: "cross-tool",
		command: "trace_cross_language",
		scope: "partial",
		limitations:
			"Saved validated graph paths; no universal JNI or Electron resolver.",
	},
	{
		group: "cross-tool",
		command: "explain_behavior",
		scope: "partial",
		limitations:
			"Exact JS/TS function evidence and relationships; no generated behavioral verdict.",
	},
	{
		group: "cross-tool",
		command: "compare_versions",
		scope: "partial",
		limitations:
			"APK ZIP-entry or bounded byte comparison; not a combined semantic/API report.",
	},
	{
		group: "cross-tool",
		command: "query_investigation",
		scope: "bounded",
		limitations:
			"Existing bounded saved investigation query adapter; no automatic reruns.",
	},
	{
		group: "cross-tool",
		command: "verify_hypothesis",
		scope: "bounded",
		limitations:
			"Exact node/edge predicates in a selected untrusted report; unknown endpoints remain inconclusive.",
	},
	{
		group: "android",
		command: "index_multidex",
		scope: "bounded",
		limitations:
			"Existing bounded DEX index adapter retains DEX origin; engine readiness separate.",
	},
	{
		group: "android",
		command: "find_android_entrypoints",
		scope: "partial",
		limitations:
			"Manifest components only; lifecycle/callback expansion unresolved.",
	},
	{
		group: "android",
		command: "trace_android_method",
		scope: "partial",
		limitations:
			"Exact method code and reference candidates; no full dispatch/call graph.",
	},
	{
		group: "android",
		command: "map_jni_bindings",
		scope: "partial",
		limitations:
			"JNI-name and relationship candidates; unresolved dynamic registration is not invented.",
	},
	{
		group: "android",
		command: "preview_smali_patch",
		scope: "bounded",
		limitations: "Exact hash-bound single-method/single-file preview.",
	},
	{
		group: "android",
		command: "patch_smali_method",
		scope: "bounded",
		limitations:
			"Approved preview publishes one new file; project integration is separate.",
	},
	{
		group: "android",
		command: "validate_smali_project",
		scope: "bounded",
		limitations:
			"Existing assembler over supported inputs with new output; no ART/device proof.",
	},
	{
		group: "android",
		command: "diff_android_resources",
		scope: "partial",
		limitations:
			"ZIP-entry size/CRC comparison; no decoded resource semantic diff.",
	},
	{
		group: "android",
		command: "build_android_candidate",
		scope: "bounded",
		limitations:
			"Preview-bound decoded-project snapshot, exact-method patches, all Smali roots assembled, unsigned Apktool rebuild and hash/structure validation before new-file publication. No signing/install/device proof.",
	},
	{
		group: "android",
		command: "verify_android_candidate",
		scope: "partial",
		limitations:
			"Structure, signature and optional ZIP comparison; build receipts/device checks remain separate.",
	},
	{
		group: "native",
		command: "resolve_native_symbol",
		scope: "partial",
		limitations:
			"Selected bounded ELF function evidence; not every binary format or symbol kind.",
	},
	{
		group: "native",
		command: "decompile_function_bundle",
		scope: "partial",
		limitations:
			"Selected native evidence and explicit Ghidra/IDA output; caller discovery remains incomplete.",
	},
	{
		group: "native",
		command: "trace_native_calls",
		scope: "partial",
		limitations:
			"Selected direct/indirect call candidates; no transitive call traversal.",
	},
	{
		group: "native",
		command: "compare_native_functions",
		scope: "partial",
		limitations:
			"Same exact selector in both images; no inferred semantic match confidence.",
	},
	{
		group: "native",
		command: "inspect_binary_mitigations",
		scope: "bounded",
		limitations:
			"Bounded PE/ELF header declarations only; no mitigation enforcement claim.",
	},
	{
		group: "native",
		command: "annotate_analysis_project",
		scope: "bounded",
		limitations:
			"Existing isolated exact-state project preview/candidate/rollback; no executable rewriting.",
	},
	{
		group: "native",
		command: "crosscheck_disassembly",
		scope: "bounded",
		limitations:
			"Actual Capstone/Miasm exact raw range, explicit architecture/offset/address, boundary and byte comparison. No semantic equivalence or code/data proof.",
	},
	{
		group: "native",
		command: "explain_decompiler_disagreement",
		scope: "partial",
		limitations:
			"Compares imported selected-function evidence; does not authenticate or rerun engines.",
	},
	{
		group: "source",
		command: "trace_electron_ipc",
		scope: "partial",
		limitations:
			"Bounded JS/TS syntactic IPC candidates; not observed channel execution.",
	},
	{
		group: "source",
		command: "audit_preload_bridge",
		scope: "partial",
		limitations:
			"Exposed bridge/configuration evidence; no vulnerability or validator-correctness verdict.",
	},
	{
		group: "source",
		command: "trace_source_symbol",
		scope: "bounded",
		limitations:
			"One exact JS/TS function declaration and bounded declared neighbors; no universal language support.",
	},
	{
		group: "source",
		command: "preview_ast_transform",
		scope: "bounded",
		limitations:
			"Existing supported primitive literal transforms; parser-backed exact offsets.",
	},
	{
		group: "source",
		command: "apply_ast_transform",
		scope: "bounded",
		limitations:
			"Hash-bound approved candidate transform; no arbitrary AST program rewriting.",
	},
	{
		group: "source",
		command: "map_dotnet_interop",
		scope: "partial",
		limitations:
			"ImplMap/PInvoke declarations only; COM, marshaling and runtime resolution unresolved.",
	},
	{
		group: "source",
		command: "compare_public_api",
		scope: "partial",
		limitations:
			"JS/TS explicit syntax signatures and public class members; no inferred type/ABI or resolved reexport comparison.",
	},
	{
		group: "source",
		command: "inspect_dependency_risk",
		scope: "partial",
		limitations:
			"Declared package.json plus explicit hash-bound npm lock v2/v3 and imported OSV exact-version evidence. Range events, publisher authority and freshness remain unresolved.",
	},
	{
		group: "runtime",
		command: "plan_runtime_observation",
		scope: "partial",
		limitations:
			"Approved read-only immutable-source plan for a live local Node Inspector PID/birth/listener, Linux/Windows. No socket attachment or execution. Actual runtime needs separate Runtime/Hybrid Debug approval; native/JVM/Android planning and persistent sessions remain separate.",
	},
	{
		group: "runtime",
		command: "attach_debug_session",
		scope: "partial",
		limitations: "Independently Execute-approved 1–120-second managed local Node Inspector session, exact PID/birth/listener and loaded-source hash. Debugger activation/cleanup may pause/resume. No evaluate/launch/step/explicit resume, exclusive ownership or native/JVM/Android parity.",
	},
	{
		group: "runtime",
		command: "set_scoped_breakpoints",
		scope: "partial",
		limitations: "Fresh Execute approval for up to eight unconditional zero-based locations in one exact hash-matched managed Node script. Can pause target; no conditions/logpoints/evaluation or automatic continuation.",
	},
	{
		group: "runtime",
		command: "capture_execution_trace",
		scope: "partial",
		limitations: "Fresh Execute approval for 200–2000 ms selected-script V8 CPU sampling, not a full execution trace. 128 selected nodes/256 samples; names hashed, unrelated script metadata excluded. Missing samples do not prove no execution.",
	},
	{
		group: "runtime",
		command: "capture_process_tree",
		scope: "partial",
		limitations: "Independently approved Runtime/Hybrid Linux /proc or Windows CIM ancestry snapshot, exact root PID/birth checks and 128-process output cap. Non-atomic metadata only; not an execution trace or proof the basis artifact ran in the selected process.",
	},
	{
		group: "runtime",
		command: "capture_file_activity",
		scope: "partial",
		limitations: "Independently approved Runtime/Hybrid exact-file fs.watch notifications, 5-second/128-event caps, cancellation and mode-change cleanup. No recursive, syscall or PID-attributed tracing; coalesced/missing notifications prevent completeness claims.",
	},
	{
		group: "runtime",
		command: "capture_network_metadata",
		scope: "partial",
		limitations:
			"Explicit built-in browser scenario metadata only; not arbitrary process interception.",
	},
	{
		group: "runtime",
		command: "correlate_static_runtime",
		scope: "partial",
		limitations:
			"Owning-session hash-checked saved static/task evidence reconciliation, selected Node sample definition-line candidates and supported native module/RVA observations. No new runtime work, causality proof or universal cross-domain mapping.",
	},
	{
		group: "runtime",
		command: "run_device_smoke_test",
		scope: "partial",
		limitations:
			"Unified AI adapter over existing separately approved Android launch/incident workflow: exact installed base APK identity, selected device, bounded package-scoped observations, owning status/cancel, mode/profile cancellation. No install/root/UI automation or automatic force-stop; no-crash is not a passing regression. Live hardware and split identity remain unverified.",
	},
	{
		group: "runtime",
		command: "stop_runtime_session",
		scope: "partial",
		limitations: "Owning managed Node connection only, including after Analysis Off. Bounded best-effort owned profiler/debugger cleanup and transport closure; no process kill. Disconnect may resume target; uncertainty stays partial. Not a universal backend stop.",
	},
	{
		group: "bulk",
		command: "plan_batch",
		scope: "partial",
		limitations:
			"AI front door validates a 12-stage static DAG over existing hash-bound files, including source/Electron/.NET/mitigation/comparison and saved-graph adapters; writes/runtime/external engines remain separate.",
	},
	{
		group: "bulk",
		command: "preview_batch",
		scope: "partial",
		limitations:
			"AI front door previews canonical input hashes (including both comparison files), dependency/budget checks and strict adapter scope. No approval, execution, writes/runtime or external engines.",
	},
	{
		group: "bulk",
		command: "run_batch",
		scope: "partial",
		limitations:
			"Freshly approved durable static DAG including bounded source/comparison/saved-graph reads. Partial evidence is retained, blocks dependents and allows independent reads; true failures stop work. No mixed-effect orchestration.",
	},
	{
		group: "bulk",
		command: "checkpoint_investigation",
		scope: "partial",
		limitations:
			"AI command reads the latest owning-session durable execution receipt, revision and stage evidence; it does not force a new flush or unite all evidence stores.",
	},
	{
		group: "bulk",
		command: "resume_investigation",
		scope: "partial",
		limitations:
			"AI continuation revalidates exact terminal revision, input/implementation/result fingerprints and resumes only never-started built-in static stages with fresh approval. No started-stage/write/runtime replay.",
	},
	{
		group: "bulk",
		command: "cancel_batch",
		scope: "partial",
		limitations:
			"Owning-session AI command cancels its durable batch through the existing supervisor; terminal confirmation is read separately. Other runners remain separate.",
	},
	{
		group: "bulk",
		command: "validate_candidate",
		scope: "partial",
		limitations:
			"Unified approved hash-bound JS/TS parse diagnostics, standard DEX header/integrity/extents and APK structure/signature checks. No arbitrary-format, type/VM/device/build/semantic-equivalence verification.",
	},
	{
		group: "bulk",
		command: "review_candidate_changes",
		scope: "partial",
		limitations:
			"Unified approved exact-recipe audit with immutable receipt hash; missing/mismatched/unverified candidates do not pass. Only manifest-declared files; no undeclared-file baseline or whole-project scope review.",
	},
	{
		group: "bulk",
		command: "export_evidence_bundle",
		scope: "partial",
		limitations:
			"Approved gzip JSON archive of hash-bound selected text findings/receipts/logs with source/export hashes and redaction. Unknown secrets, completeness and producer authenticity remain unverified.",
	},
	{
		group: "bulk",
		command: "check_release_gate",
		scope: "partial",
		limitations:
			"Existing exact-head CI/installed checks; no AI command or immutable gate receipt.",
	},
] as const;
