# Pinned capability audit

Reference: `morluto/rea` commit `d0067ba34a39ea47dd7e11bb2e6169bc0938cc3f`, MIT, copyright 2026 morluto. The original license is retained at `sdk/packages/core/src/analysis/semantic-engine/upstream/LICENSE` and in compiled notices.

- `capabilities.json`: all 212 public contracts reachable from `TOOL_CONTRACTS`, in registration order, with their upstream effect audit, descriptions, source locations, schema expressions, static dependency roots and lexical test references.
- `contract-dependencies.json`: 443 source files in the registry's static literal import/export/import-type/require closure, including types. Each record commits the original SHA256 and its edges. This is not a provider-script/runtime dependency inventory, SBOM or availability test.
- Seven contracts have **partial-source-port** routes. All remaining records deliberately say **not-source-ported-or-audited**, even when Cline has an independent overlapping implementation. An operation name or lexical test mention does not demonstrate equivalent capability, effect enforcement or coverage.
- Admission budgets, virtual manifest identity, partial historical inputs and missing native/runtime Evidence remain explicit. No whole-application acquisition, reconstruction, native-engine or REA-superiority certification is implied.

Regenerate with `CLINE_SEMANTIC_REFERENCE_ROOT` set to a separate clean development checkout of the exact pinned revision:

```bash
bun scripts/rea-capability-inventory.mjs
bun scripts/rea-capability-inventory.mjs --check
```

This audit is development-only, not a production dependency. No REA installation, CLI, MCP server or separate analysis runtime is added. The source-validation workflow checks the committed audit on Linux and Windows. `INTEGRATED_SEMANTIC_SOURCE.md` describes the actual app routes and limitations.

## Shipped workflow guidance

The original `cline-investigation` portable skill pack supplies six instruction-only guides over existing Cline routes. It is authored for this app, not a copied REA MCP/CLI setup recipe. It adds no external REA runtime, executable plugin, engine or approval bypass. Packaged resource hashes, local-only session projection, namespace/disable behavior and installed restart acceptance are explicit release gates. See `../INTEGRATED_SEMANTIC_SOURCE.md` for commands and limitations.

This does **not** change any of the 212 contract migration statuses. In particular, native, managed, runtime reconciliation, acquisition/reconstruction and specialist algorithm ports do not become complete because a guide describes their supported Cline alternatives. A successful instruction selfcheck does not certify a model-driven investigation or superiority to REA.

## Electron fuse reader

`inspect_electron_fuses` has a direct source-backed route through `javascript_analysis` with explicit `electronFuses:true`. This covers the original streaming file parser and report derivation for one confined PE/ELF/Mach-O executable, not automatic macOS app-bundle resolution or the full upstream provider lifecycle. Original algorithms/fixtures carry pinned provenance. Saved raw-wire/implication reads never start or modify the target. Current-head installed validation is required before claiming packaged availability.
