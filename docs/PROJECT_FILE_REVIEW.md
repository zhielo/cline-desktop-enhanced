# Candidate project file review

`review_candidate_changes` has three explicit read-only scopes. Every scope uses the existing independently approved Inspect workflow; no scope writes, applies, repairs, builds, runs, signs or installs a candidate. The selected JSON document is an immutable owning-session `open_binary` artifact.

- `recipe` (default): existing exact source/output patch-recipe audit, unchanged.
- `project-inventory`: inventory **every regular file** in two disjoint child directories of the selected document directory. Return exact complete inventory hashes and a proposed change allowlist. The result is **partial / previewed-not-approved**, never a passing change review or consent. More than 256 changed files blocks a complete draft.
- `project-files`: require exact full baseline and candidate inventory hashes, then check every changed relative file path and its exact before/after SHA256 against the selected manifest's allowlist. Undeclared additions, removals or edits fail even if their content is valid. Extra/no-op or wrong-hash declarations also fail.

## Workflow

1. Keep an untouched baseline and an isolated candidate below the same workspace directory. Do not put the inventory request/manifest inside either tree. Roots must be disjoint, not aliases or nested copies.
2. Create a new inventory request document. For example:

```json
{
  "protocol": "cline-project-inventory-request/v1",
  "baseline_directory": "original",
  "candidate_directory": "candidate"
}
```

3. Open that document with `open_binary`. Ask the AI to call `review_candidate_changes` with its `artifactId` and `scope: "project-inventory"`. Inspect the separate full-directory-read approval. Denial runs nothing.
4. Inspect every proposed changed path and before/after hash. The returned `proposedManifest` is **untrusted proposal data**, not human authorization. If the changed-file count exceeds 256, no complete manifest is proposed; reduce the deliberately selected scope without hiding unexpected changes.
5. Only after separate authorization, save the selected manifest as a **new file outside both roots** using the normal approved file-edit workflow. This command never publishes a manifest or silently adopts the proposed allowlist. Remove changes you did not authorize; do not bless unexpected changes merely to obtain a green result.
6. Open the new immutable manifest, then call `review_candidate_changes` with `scope: "project-files"`. Inspect its separate approval. The host binds the manifest hash and scope. Any later file or manifest changes require a fresh review; hashes and old receipts are not authority for later mutations.

A review manifest uses protocol `cline-project-review/v1`, `baseline` and `candidate` objects with `directory` and `inventory_sha256`, and `approved_changes` entries with `path`, `before_sha256` and `after_sha256`. `null` before means addition; `null` after means deletion. Identical before/after values are not changes. Unknown authority, ignore, shell or network fields are rejected.

## Inventory fingerprint specification

SHA256 the UTF-8 encoding of compact JSON in this fixed field order:

```text
{"protocol":"cline-project-inventory/v1","files":[{"path":"relative/path","bytes":N,"sha256":"64-lowercase-hex"}]}
```

Sort files by exact relative path using ordinal string comparison, not locale sorting. Paths use `/`. File entries have exactly the ordered `path`, `bytes`, `sha256` fields. Empty trees use an empty array. Inventory mode computes this without executing files. The expected inventory binds all regular files, including unchanged files and dotfiles, not only the proposed changes.

## Bounds and limitations

- 4,096 entries per tree; depth 16; 16 MiB per file; 64 MiB combined baseline/candidate bytes per pass; two complete passes; caller cancellation and existing maximum 120-second task budget.
- No ignore rules, symlinks, junctions, hard-linked/special files, overlapping roots or ambiguous portable paths. Relative path encoding is limited to 1,024 UTF-8 bytes; case-alias collisions and Windows-reserved path spellings are rejected.
- All changes are checked. Review evidence includes at most 200 detailed changed-file rows with an explicit total/truncation flag. Inventory proposals are never truncated into an apparently complete allowlist.
- Names, counts, sizes and hashes only; file contents are not copied into the review evidence. Hashes are still sensitive metadata and are not a secret-detection guarantee.
- Empty directories, modes/ACLs/timestamps, alternate streams, dependency correctness, producer authenticity and behavior are outside this **file-content/name** contract. Two stable scans detect ordinary mutations, not a hostile-filesystem sandbox or an atomic OS snapshot. Preserve the baseline through an independent trusted workflow.
- A completed file-scope check is not a passing build, a release gate, behavioral equivalence or completion of the original 55-command recommendation scope.
