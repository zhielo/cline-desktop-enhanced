# Reviewed native-project edit candidates

This workflow edits an **isolated analysis-project candidate**, never the original target binary or your open GUI database. Ghidra additionally uses its native transaction to roll back failed in-process edits. IDA has **no native undo guarantee here**: failed changes are confined to an unpublished candidate. A separate native reopen verifies persisted state before publication.

## Preview → candidate → review → optional pointer rollback

1. Choose Reviewed native project candidate in Analysis workbench and explicitly choose Ghidra or licensed IDA. Use an exact function entry address (or an unambiguous exact symbol). Target is the original native artifact, not a live process or GUI database.
2. In Targeted decompiler options JSON prepare a preview:

```json
{"function_selector":{"address":"0x1000"},"project_edit":{"mode":"preview"}}
```

Replace the example address with this artifact's actual entry. Prepare the immutable plan and review the separate private-project/state/pointer approvals. Read `before` and `headSha256` from the engine-normalized result; do not guess the prototype or function name.

3. Submit a **new, separately approved** candidate request. Copy the exact three before-state fields and head value from preview; `null` means there is no published candidate yet.

```json
{"function_selector":{"address":"0x1000"},"project_edit":{"mode":"candidate","expected_state":{"name":"fixture_main","comment":"","prototype":"int fixture_main(void)"},"expected_head_sha256":null,"changes":{"comment":"Reviewed finding","name":"reviewed_main","prototype":"long reviewed_main(int value)"},"confirm_candidate_write":true}}
```

These fixture values are illustrative, not valid observations from your app. Omit any change not intended. Names accept a bounded C identifier; comments are bounded strings; prototype input is one bounded function declaration, not code, directives, typedef batches or function bodies. No arbitrary scripts, target execution, address patching or device actions are accepted.

4. A successful result returns `projectPath`, `manifestPath`, `headSha256`, before/after state and rollback contract. The candidate's native save is followed by a **separate engine process reopening the saved project** at the exact resolved entry. Failed parser/read-back/save/reopen, cancellation or changed identities prevent publication. Open the returned candidate explicitly for review; the workflow never replaces a GUI project or claims ABI/semantic correctness of your chosen type.
5. To roll back, submit another separately approved `project_edit` with mode `rollback`, the **current** head hash and `confirm_pointer_rollback: true`. No function selector or changes are needed. Rollback verifies immutable candidate/manifest bytes and restores only the previous active-candidate pointer, or clears it for the first candidate. It does not undo work already performed in an external GUI, restore a target binary or fix a device. No engine process is launched by the pointer-rollback callback, although the same engine/config identity must remain available for this tool's scope checks.

## Integrity and concurrency

- Artifact, fixed adapter and command/config hashes scope each lineage. Inputs are byte-verified snapshots. A matching current published candidate is cloned before editing; later edits do not mutate previous candidate bytes.
- Exact function before-state and head checks reject stale review. Name/comment read-back also rejects changes to fields not requested. Type application is checked with native parameter/return/varargs comparisons in Ghidra and `tinfo_t.equals_to` in IDA, then full normalized function state is checked again after reopening. Engine normalization does not prove semantic/ABI equivalence or recover an unknown type automatically.
- Candidate files are bounded regular non-link descendants: at most 4096 files, 32 levels/8192 traversal nodes, 512 MiB per file and 1 GiB total. SHA-256 manifests bind project files and the input snapshot; candidate metadata/receipts are bounded handle-checked reads.
- Cooperating processes hold a cross-process lease during clone, engine work, verification and pointer publication. Published candidate metadata is immutable and content-addressed. Cancellation is rechecked after final identity reads and pointer-file sync, before the atomic rename commit boundary. Atomic, synced-file pointer replacement is verified after publication; cancellation after that boundary cannot silently undo a committed pointer. If verification fails, the error says publication outcome is uncertain: inspect current state and prepare a new plan rather than automatically replaying.
- These are local integrity/coordination checks, **not signatures, an OS sandbox, a lock on external GUI writers or protection from privileged host tampering**. Installed native loaders/plugins process the artifact; hostile samples need a separately provisioned isolation environment. License errors are failures, never bypassed.
- Read-only profiles cannot invoke this edit/pointer workflow. Workbench plans classify it as Modify and require reviewed native state, isolated project writes and explicit acknowledgement that pointer changes are not GUI replacement. Opening or refreshing never edits anything.
- Failed/preview staging projects are retained privately for diagnosis, not automatically deleted, promoted or exported. Prototype/comment input is private analysis data and may be sensitive; no plaintext upload occurs in this workflow.

## Evidence and remaining validation

Owned protocol fixtures cover both project layouts, preview, candidate cloning, independent reopen, stale review, failure after save, persisted mismatch, cancellation, byte tampering, directory junctions and pointer rollback. Fixed-source checks and IDA Python syntax validation are not execution with a licensed/native engine. Actual installed Ghidra and licensed IDA compatibility remain operator validation requirements, as does physical KSUN-device validation. A successful Windows build tests the software/fixtures and packaging, not those unavailable installations or hardware.

The scope is function names, comments and prototypes in private candidates. It intentionally excludes automatic in-place GUI-database replacement, global type-library/struct migrations, live process mutation and claims of universal reverse-engineering automation.
