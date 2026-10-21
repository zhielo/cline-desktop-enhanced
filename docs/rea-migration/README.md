# Pinned capability audit

Reference: `morluto/rea` commit `d0067ba34a39ea47dd7e11bb2e6169bc0938cc3f`, MIT, copyright 2026 morluto. The original license is retained at `sdk/packages/core/src/analysis/semantic-engine/upstream/LICENSE` and in compiled notices.

- `capabilities.json`: all 212 public contracts reachable from `TOOL_CONTRACTS`, in registration order, with their upstream effect audit, descriptions, source locations, schema expressions, static dependency roots and lexical test references.
- `contract-dependencies.json`: 443 source files in the registry's static literal import/export/import-type/require closure, including types. Each record commits the original SHA256 and its edges. This is not a provider-script/runtime dependency inventory, SBOM or availability test.
- Six contracts have **partial-source-port** routes. All remaining records deliberately say **not-source-ported-or-audited**, even when Cline has an independent overlapping implementation. An operation name or lexical test mention does not demonstrate equivalent capability, effect enforcement or coverage.
- Admission budgets, virtual manifest identity, partial historical inputs and missing native/runtime Evidence remain explicit. No whole-application acquisition, reconstruction, native-engine or REA-superiority certification is implied.

Regenerate with `CLINE_SEMANTIC_REFERENCE_ROOT` set to a separate clean development checkout of the exact pinned revision:

```bash
bun scripts/rea-capability-inventory.mjs
bun scripts/rea-capability-inventory.mjs --check
```

This audit is development-only, not a production dependency. No REA installation, CLI, MCP server or separate analysis runtime is added. The source-validation workflow checks the committed audit on Linux and Windows. `INTEGRATED_SEMANTIC_SOURCE.md` describes the actual app routes and limitations.
