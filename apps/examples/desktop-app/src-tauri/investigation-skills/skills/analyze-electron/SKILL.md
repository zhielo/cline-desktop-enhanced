---
name: analyze-electron
description: "Inspect JS/TS, Electron application trees and bounded ASAR inputs using Cline’s integrated semantic/application graphs. Use for IPC, preload/renderer/main relationships and saved feature traces; not executing the application or proving whole-program taint."
license: Apache-2.0
compatibility: Requires Cline Desktop integrated investigation tools; no REA installation.
metadata:
  version: "1"
---

# Analyze a JavaScript or Electron application

## Admit sources explicitly

Use the exact owning local session/workspace and user-selected target. New `javascript_analysis` inspection requires its existing Analysis mode. For integrated graph evidence, explicitly request both options:

```json
{"operation":"javascript_analysis","target":"<owned relative target>","javascript_options":{"semanticGraph":true,"applicationGraph":true}}
```

Do not provide `compareTarget` with semantic analysis. Analyze comparison targets separately and load compare-applications. Ordinary source inspection remains available without graph options. Do not turn on Analysis, expand privileges, approve execution or fetch external modules automatically. No REA install, CLI, MCP server or separate backend is required.

## Read retained evidence

Retain the returned receipt ID, result hash, profiles, source manifest and partial coverage. Use bounded `analysis_evidence` views: application-summary, application-nodes, application-edges, semantic-summary, semantic-nodes, semantic-relations, semantic-unknowns, semantic-fingerprints and semantic-contexts. Select IDs/literals from returned evidence, not invented IDs. Saved reads remain available while Analysis is Off.

For a known retained Electron channel:

```json
{"operation":"analysis_evidence","evidence_query":{"receiptId":"<owning receipt>","view":"application-trace","applicationTrace":{"seed":{"kind":"channel","value":"<retained literal>"},"direction":"both"},"applicationSection":"edges","limit":20}}
```

Use actual nextOffset values for pagination and preserve the same receipt/query. Do not infer absence from a filtered page, unmatched seed or exhausted admission budget. Trace relationships retain observed syntax versus inferred/static relationships; providerCalls=0 means no provider was called, not that target behavior was verified.

## Preserve scope

The application root commits a virtual admitted path/hash/size manifest, not the original whole container. Existing file/byte/ASAR budgets apply. JSON, HTML, source maps and native-addon metadata contribute only when admitted. Source-map labels are untrusted and never fetched or executed. `.node` metadata is not native decompilation. File-local semantic nodes bind to application nodes; this is not a complete cross-module taint solver. Dynamic imports, unresolved modules, shadowing and omitted code remain unknown.

Return a concise module/IPC/preload map with receipt-backed examples and exact source locations, a focused saved trace, unresolved frontiers and any next separately authorized analysis. Never import/evaluate target code or launch Electron to make the static result appear complete.

## Saved Inspector source reconciliation

Use the advertised saved static/runtime correlation tool only with an owning static receipt and selected retained runtime tasks. `inspectorSources` compares source hashes and lexical locations without attaching or reading files. Preserve exact-location byte mismatches and duplicate-byte ambiguity. Location-only matches are unverified. Parsed/loaded does not mean executed; a byte match does not authenticate the VM or establish behavior. Missing scripts can reflect a bounded observation window. Do not fetch source maps or rerun capture merely to fill a saved-evidence gap.

## Recover inert bundle factories

For one immutable UTF-8 JS bundle at most 1 MiB, use advertised `recover_bundle_sources` after `open_binary`. Read saved `bundle-recovery` evidence for exact module IDs, original half-open UTF-8 byte ranges, hashes and inert base64 fragments. This first-party engine recognizes literal Webpack/Rspack/esbuild factories only, not Wakaru/general deobfuscation parity. Zero recovered modules is an unsupported/absent observation, not proof that the input is unbundled.

Only when the user wants an export, use `publish_bundle_recovery` with the original artifact ID, exact saved receipt/report hash and a new absolute managed `.json` output. This requires separate Modify approval and Full Access. It stages a no-overwrite provenance package; original bytes are rechecked and retained. Never run/import fragments, overwrite originals, infer source-map accuracy, or install recovered code.
