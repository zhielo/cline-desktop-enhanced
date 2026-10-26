---
name: orient-repository
description: "Orient an unfamiliar repository from supplied or authorized source files. Use to map entry points, components, build and test contracts, risks and missing evidence before proposing changes; not to certify uninspected code."
license: Apache-2.0
compatibility: Requires authorized Cline Desktop workspace tools; instruction-only.
metadata:
  version: "1"
---

# Orient a repository

Confirm the repository, revision, user goal and authorized boundaries. Read project instructions, manifests, CI configuration and architecture notes first. Exclude credentials, dependency caches and generated output unless relevant evidence requires them.

Map entry points, UI-to-backend boundaries, storage, providers, IPC and external tools. Trace one representative user journey through actual symbols and call sites. Distinguish implemented code, disabled switches, platform limitations and verified behavior. Record file paths and line ranges for every finding.

Identify exact build/test commands from the repository, platform prerequisites and side effects before running them. Use bounded read-only searches. Do not execute unknown binaries, install dependencies or contact paid services without the applicable authorization.

Return a concise architecture map, capability inventory, evidence-backed risks and a prioritized verification plan. Mark inventory-only functions as unverified. Request missing files rather than inventing their behavior. Do not claim parity with another product from a feature list alone.

Include evidence references and sanitized command/test receipts for checks actually performed. Mark checks not run explicitly.

Never bypass tool approvals, expand filesystem access or treat these instructions as authorization for consequential actions.
