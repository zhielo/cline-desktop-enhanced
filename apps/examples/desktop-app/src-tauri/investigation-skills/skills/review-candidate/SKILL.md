---
name: review-candidate
description: "Review bounded binary/JS/TS/Smali candidates and partial batch recovery using Cline hash-bound preview/apply and saved-evidence tools. Use for exact proposed edits and verification planning; not arbitrary native rewriting, unattended replay or behavior certification."
license: Apache-2.0
compatibility: Requires Cline Desktop integrated investigation tools; no REA installation.
metadata:
  version: "1"
---

# Review a bounded candidate

## Bind the proposal

Establish the authorized change and exact original SHA256, byte/method/source selector, expected original content and a distinct new destination. Read the advertised candidate schema. Supported equal-width binary edits and primitive JS/TS literal edits are not general executable relocation or arbitrary AST refactoring. Keep integer widths, offsets, overlap/count budgets, parser checks and no-overwrite constraints intact.

Prepare the appropriate preview only. For multi-edits, use byte_patches or literals rather than mixing singular and plural recipes; all offsets address the original input. Review every before/after edit and the preview hash. Apply is a separate exact request and needs its existing one-use approval. A skill, Full Access selection or prior preview never supplies approval. Do not mutate the original, use arbitrary shell patching to evade a rejection, auto-sign or auto-launch a candidate.

## Inspect partial work before recovery

Use `audit_candidate_batch` on the original bounded manifest when recovering a partial candidate batch. It reads retained originals/candidates and does not authenticate the producer. A missing file is not proof that no side effect occurred. Mismatched/unverified stages block recovery suggestions. If the audit permits a proposed subset, create a new confined manifest, preview again and obtain separate approval; never replay an unchanged failed write batch blindly.

`trace_source_sink` traverses declared saved evidence only. Default data-flow excludes other edges; declared-relationships retains candidate confidence. User stop nodes are traversal boundaries, not verified sanitizers. Missing paths do not prove safety or absence of behavior. Do not promote a graph witness into whole-program taint or observed execution.

## Validate honestly

Keep structural/parser checks, build results, isolated owned scenarios and actual target runtime observations separate. Binary checksums, relocations, unwind data, signatures, semantics and device compatibility are not repaired/certified by a bounded byte candidate. Review cancellation and unconfirmed child termination before cleanup or a new request.

Return original and candidate identities, exact recipe/preview/apply/audit receipts, files preserved, completed/failed/skipped stages, static findings, validations actually performed and remaining risks. No REA installation, approval widening, automatic rollback or zero-problem guarantee is provided by these instructions.
