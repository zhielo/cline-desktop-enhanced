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
