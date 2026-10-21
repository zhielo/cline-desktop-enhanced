---
name: compare-applications
description: "Compare two retained JS/Electron application receipts, exact export shapes, or a partial admitted source manifest against a bundle using Cline saved evidence. Use for version differences and source-to-bundle questions; not behavioral equivalence or complete reconstruction."
license: Apache-2.0
compatibility: Requires Cline Desktop integrated investigation tools; no REA installation.
metadata:
  version: "1"
---

# Compare retained application evidence

1. Establish what the comparison means: versions, an exact export’s return shape, or admitted reference sources versus bundle. Obtain session-owned application-graph receipt IDs for both inputs. If inspection is needed, use analyze-electron with separate explicit requests; never silently rerun or launch a target.
2. Inspect each application-summary. Record result/graph hashes, profiles, virtual source identity, coverage and omitted counts. Distinct receipts may have identical content; version/export workflows require distinct receipt IDs. Hash identity alone does not certify behavioral equivalence.
3. Query `analysis_evidence` with the left receiptId, right compareReceiptId and the selected supported view:
   - application-comparison: version/module/relationship differences over retained graphs.
   - application-exports: exact exportSelectors.left and exportSelectors.right, each containing modulePath and exportName taken from evidence. Do not guess an export path or name.
   - application-source-bundle: left admitted source manifest is the historical reference; right receipt is the application bundle. This reference lacks complete VCS/import inventory and is not original source recovery.
4. Use the current schema’s applicationSection for an array returned by that workflow and bounded limit/nextOffset pagination. An absent section is an error, not permission to choose a different comparison silently. Retained queries remain available in Analysis Off and do not start providers.
5. Report observed changes, candidate relationships and unknowns separately. An incomplete graph cannot prove unchanged behavior, no removed functionality, complete source correspondence or a successful reconstruction. Preserve unmatched/ambiguous export and module evidence instead of treating it as equality.

## Output

Include both receipt IDs and hashes, exact question and selected export/module scope, supported additions/removals/shape changes, uncertainty and coverage, plus any next test that would be needed. Separate a static finding from a requested runtime scenario. Do not sign, rebuild, launch or install anything, install REA, or grant approval through a skill.
