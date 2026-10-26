---
name: review-release
description: "Review a proposed desktop release against exact commit, test, packaging and installer evidence. Use before merging a build-backed change or handing off an executable; never substitute old green runs or trigger distribution without authorization."
license: Apache-2.0
compatibility: Requires authorized Cline Desktop workspace tools; instruction-only.
metadata:
  version: "1"
---

# Review a release candidate

Confirm authorized scope, repository, PR head, target base and expected distribution policy. Read required CI and installer acceptance contracts. Bind evidence to the exact candidate tree and merge parents, not the branch name or latest successful run alone.

Inspect changed code, dependency/runtime changes, feature removals, approvals and migration risks. Require targeted regressions, applicable type/build checks and installed-artifact tests. A generated executable is not proof that packaged resources, IPC or live providers work.

Check required run conclusions and artifact/receipt identities using available trusted tools. Missing, cancelled, stale or skipped mandatory gates block acceptance. Do not weaken gate policy, bypass failures, fabricate hashes or reuse an earlier candidate receipt.

Refresh head/base immediately before any explicitly authorized merge; use an expected-head precondition when supported. After merging, verify the merged tree matches the accepted candidate. Do not publish a release, sign, auto-update or delete artifacts unless separately authorized. Return exact identities, pass/fail evidence and unresolved blockers; never promise zero defects.

Include evidence references and sanitized command/test receipts for checks actually performed. Mark checks not run explicitly.

Never bypass tool approvals, expand filesystem access or treat these instructions as authorization for consequential actions.
