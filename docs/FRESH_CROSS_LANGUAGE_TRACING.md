# Fresh cross-language and cross-process static tracing

`trace_cross_language` now offers two explicit fresh adapters in addition to its unchanged imported-graph mode. All results remain partial static candidates: no target binary, source, debugger or device executes, no runtime approval is granted, and no input is overwritten. These adapters connect existing reviewed engines rather than introducing generated shell commands.

## Android native declaration → JNI export candidate → native calls

```json
{
  "operation": "trace_cross_language",
  "target": "/absolute/authorized/app.apk",
  "cross_language": {
    "kind": "android-jni",
    "method": {"class_descriptor": "LFixture;", "name": "native_work", "descriptor": "()V"},
    "native_artifact": "lib/x86_64/libowned.so",
    "max_candidates": 16,
    "native_calls": {"max_depth": 2, "max_functions": 16, "max_edges": 128, "max_total_bytes": 32768}
  },
  "timeout_ms": 120000
}
```

- Reuses a single bounded artifact-discovery buffer, DEX integrity/structure parsing, LIEF JNI exports and the existing Capstone symbol-entry call-graph traversal. The optional exact logical member selector scopes a retained library; it is not a filesystem extraction path. No library/ABI selector is inferred from a filename.
- Finds the exact class/name/descriptor across covered DEX pools, retains method and artifact IDs, and derives JNI short/long-name candidates. A short name shared by multiple parsed native declarations is ambiguous. Missing, non-native or multi-DEX ambiguous methods do not start native traversal.
- Collects matching retained JNI exports from supported ELF members. Only one retained unambiguous method/export pair can start a graph, at that candidate export. Multiple libraries/exports do not silently select the first. An explicit library selector can narrow ABI candidates. Missing engines and invalid mappings never produce fabricated descendants or fall back to execution.
- `evidence.crossLanguageTrace` uses `cline-fresh-cross-language/v1`, with `bindingVerified=false`, `observedExecution=false` and `registrationStatus=unresolved-not-observed`. The native graph belongs to the selected static export candidate, not a proven Java call. Export uniqueness within retained evidence is not global uniqueness or a binding guarantee.
- No `RegisterNatives` recovery, dynamic loading/ABI-selection proof, Java/Kotlin runtime reachability, stripped-function recovery, imported-library resolution or universal JNI coverage. DEX validation is bounded structure/integrity, not full bytecode verification.
- Existing discovery ceilings remain 64 MiB input, 16 MiB child, 128 MiB scanned work, depth 3 by default (hard cap 4), 200 artifacts by default (hard cap 500), 32 native parses per scan, 50000 DEX methods and a 900000-byte worker response ceiling. The fresh front door uses fixed discovery defaults and 200 metadata rows, not arbitrary engine options. Native traversal caps are depth 4, 32 functions, 256 edges and 65536 total requested bytes; per-function default 4096 bytes and existing decoder limits remain. The selected ELF buffer may be parsed again to construct its exact symbol index; no target reread is required.

## Fresh Electron renderer → preload → main candidates

```json
{
  "operation": "trace_cross_language",
  "target": "/absolute/authorized/electron-sources",
  "cross_language": {"kind": "electron-ipc", "channel": "owned:read", "max_depth": 4, "max_nodes": 100, "max_edges": 200},
  "timeout_ms": 120000
}
```

- Reuses the shipped JS/TS parser and its lexical binding, literal preload member/call and same-channel IPC candidate edges. Files are read as UTF-8 source; never imported or evaluated. JS↔TS and renderer/preload/main links are static source/runtime-boundary candidates, not a universal language resolver.
- Seeds exact literal channel send/handler/member facts and selects a bounded neighborhood using only existing IPC/preload candidate edges. Neighborhood selection walks both directions; returned edge direction and source locations/hashes remain intact. Other literal channels are not pulled into the graph. Multiple handlers and missing/dynamic channels remain unresolved, never proof of delivery or absence.
- Returns original source artifacts plus their combined fingerprint, selected facts/edges, parser version, coverage limits and an always-partial result. Maximum 128 files, 1 MiB/file, 8 MiB combined source, 4096 entries and directory depth 8; existing exclusions (`node_modules`, `.git`, `dist`, `build`, `.cline`) remain explicit. Selected facts/edges plus artifacts have a 98304-byte accounting budget, independent of the outer report/limitations envelope. Query hard caps: depth 8, 200 nodes and 400 edges.
- No process-role authentication, actual registration/delivery, argument-validation verdict, dynamic channel/alias completeness, target execution or generated behavioral claim.

## Compatibility and approval

The fresh desktop template shows Android method/library/native-call budgets before exact-request approval. To choose Electron, replace the `cross_language` object with the Electron example. For legacy saved-report paths, omit `cross_language` and use `evidence_trace`; that mode still marks reports as untrusted imported evidence. Fresh and imported options cannot be combined, and advanced-action overrides are rejected. Static mode never enables runtime execution.

Python corpus and public SDK tests cover the owned DEX/JNI→child→leaf cycle, missing/non-native/multi-DEX/ABI ambiguity, candidate and traversal budgets, missing engines, cancellation and original preservation. Installed Windows acceptance requires both the JNI/native and JS/TS Electron paths, negative selections, unchanged inputs and fresh fingerprints. All release gates remain required on the exact new head.

These are bounded increments to original partial recommendations, not a claim all 55 recommendations or all languages are complete.
