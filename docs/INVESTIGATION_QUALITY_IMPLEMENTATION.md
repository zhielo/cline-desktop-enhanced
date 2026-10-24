# Investigation quality implementation

Base: `8318e4ad12467bf2ce82eeb7cc426fbff7bb3809`.
Reviewed REA reference: `f9fabdfcb2c241b18fec0acb5c3b4a14f76f4805`.

This is a completion ledger, not a claim that this branch implements every item.
No REA runtime, CLI, MCP registration or installation is a production dependency.
No new IDA license-file, plugin-name or license-discovery gate is permitted.
An optional provider's actual invocation failure must not disable another provider.
Vendor runtime errors remain errors; this project does not bypass vendor licensing.

| Workstream | Existing foundation | Required completion evidence | State |
| --- | --- | --- | --- |
| Evidence and unknowns | UnifiedEvidenceStore, correlation, InvestigationStore | Scoped immutable references; durable revisioned questions; contradiction retention; restart and legacy reads | Implemented; full release gates pending |
| Native dossiers/value flow | Exact Ghidra/IDA selectors and bounded call-target evidence | Real Ghidra argument/return def-use fixtures, bounded frontiers, IDA-specific availability | Partial: selected-function flows implemented; interprocedural work remains |
| JS static/runtime reconciliation | Saved static receipts and approved runtime snapshots | Content/location/ambiguity/mismatch fixtures; no I/O during reconciliation | Implemented for saved passive Inspector reports; broader coverage remains |
| Bundle recovery | Source acquisition and application graphs | Reviewed engine identity; Windows process/resource boundary; staged no-overwrite publication; real bundle fixtures | Not completed |
| Model evaluations/skills | Six guides and installed acceptance | Known-answer model journeys with fixed scoring; real routes, not only mocks or file presence | Guides updated and integrity checked; new live-model evaluations not completed |
| Artifact readers | Existing format discovery and worker | Go build info, Rust auditable metadata, PyInstaller inventory, supported IL2CPP versions; malformed/bounded fixtures | Not completed |

## Release conditions

One implementation PR, with reviewable commits. Do not merge as “all complete”
while a required row is incomplete or only mocked. Run all existing required
core/engine/installed gates against the exact final source and build the Windows
installer from that source. Missing licensed providers remain optional and
explicitly unverified, not a failure of an unrelated supported provider.
No startup, shell, terminal or global timeout upgrade is included.

## Evidence authority

Hashes establish content consistency, not producer authentication or correctness.
Question status is workflow metadata, not a verified conclusion. Only refer to
evidence already retained in the owning case. Keep unsupported or absent
historical fields unknown. Reopening a case never reruns analysis.

## Implemented in this branch

- `manage_investigation_unknowns`: local authenticated owning-workspace metadata
  route. Exact case and question revisions prevent stale updates. Supporting and
  contradicting links require existing same-case evidence IDs and result hashes.
  Links accumulate, role reversal is rejected, and historical cases preserve their
  old audit hashes without synthesizing missing fields. Workspace cases are not
  claimed to be private to a single chat session.
- Investigation UI: record questions, review statuses and notes, add retained
  evidence links, and display contradictions. Reading and reviewing metadata
  never starts an analysis provider. Restricted tool profiles stay restricted.
- Saved Inspector reconciliation: recognize the retained passive Inspector
  protocol, bind source identity to the task target, distinguish exact bytes plus
  location, location-only, contradictory bytes and duplicate-byte ambiguity.
  Do not export network source labels, fetch source maps, attach or read files.
- Ghidra: additive optional argument and return def-use records. Fixed budgets:
  16 arguments per call, 32 dependency sources, 16 frontier records, 256 visits,
  depth 8, 64 returns. Parameters, constants and local call-return sites remain
  dependency candidates; memory, phi/cycles and unsupported operations remain
  frontiers. This is not interprocedural value equivalence or target execution.
- IDA adapter licensing behavior is unchanged: no license-file/plugin-name gate
  was added. Actual Hex-Rays initialization remains an actual runtime operation,
  and its errors do not authorize a fallback or disable Ghidra. IDA has not been
  executed in this environment and is not certified by the Ghidra tests.

## Validation so far (not a release certificate)

- Expanded local core run: 601 passed, 4 skipped.
- Final focused core/native/Inspector run: 43 passed, 1 skipped, including
  reconciliation of a real running owned Node Inspector report.
- Desktop/store/model-bridge/UI/skill-integrity run: 94 passed.
- SDK build and desktop plus WebView type checks passed.
- Actual Ghidra 12.1.4 on compiled owned ELF fixtures passed parameter-to-call,
  call-return, parameter-plus-constant and memory-load-frontier assertions.
  See `validation/investigation-quality-owned-ghidra.json`. The fixture process
  was analyzed, not executed. Exact-name ambiguity was observed and correctly
  rejected during development; no nearby-function fallback was added.
- Windows installer build, installed acceptance, the consolidated release
  validator and the remaining three workstreams are not yet complete.

Do not mark this branch ready for merge or describe all six workstreams as
complete from these local checks. Missing parity fixtures are not successful
checks; no "same or higher than REA" certification is claimed.
