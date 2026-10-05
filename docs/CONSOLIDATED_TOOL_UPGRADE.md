# Consolidated tool-platform upgrade

## Release contract

One consolidated implementation branch and one final Windows installer build after implementation and verification. Do not merge main, create a release tag, publish a release, or claim an upgraded installer until separately authorized. A rebuild of unchanged main does not deliver these upgrades.

## Current status — implementation incomplete

Baseline: 2e4f41342e50d7599b686c7173e8d9eb7859e380.

This initial staging commit contains an independently exercised bounded-worker helper and its regression tests. The helper is NOT yet wired into run_commands. No new tool pack is implemented by this commit, no production app behavior is changed, and it is not a completed release.

A separate, intermediate native-analysis/job-lifecycle checkpoint was previously recovered and built in a sandbox. The sandbox subsequently lost that working copy again. Its source package is an intermediate recovery input, not a verified installer, and is not included in this commit. Historical test passes must not be attributed to a different recovery or revision.

Node runtime checks passed for the exact helper: sequential default, at most two selected independent workers, ordered outputs, invalid concurrency rejection, and empty input. The new Vitest file still requires execution in the SDK workspace. Full SDK, desktop, Windows, licensed-engine, and isolated-worker validation for the eventual release remain outstanding.

This branch uses the work/ prefix so it does not start the existing feat/** Windows installer trigger. Keep implementation here until the complete, reviewed source is ready; then create one feat/** build branch from the exact validated commit.

## Required implementation packs

- Shared platform: capability registry, permission broker, owned job lifecycle, end-to-end deadlines, bounded cancellation, evidence hashes, paging, honest restart/recovery limitations, and verified artifact receipts.
- Engineering intelligence: code graphs, language-server navigation, impact analysis, structured tests and coverage, build jobs, API contracts, dependency audit.
- Native/Android research: ELF/PE/Mach-O metadata, explicit address translation, function queries, binary differences, DEX queries, JNI mapping, APK manifest/resource/signing inspection, independent-engine comparison.
- Isolated runtime lab: sandbox jobs, reviewed tracing recipes, debugger sessions, scoped memory snapshots, scoped network captures, correlated timelines.
- Security/operations: security and secret scans, SBOM generation, policy checks, exact-revision workflow builds, installer verification, crash triage, performance profiles, storage health, read-only database inspection, disposable migration checks, reproducible container environments.

## Safety and truthfulness gates

- Registration, executable detection, licensed capability, adapter support, permission, and runtime verification are distinct states.
- Unknown target binaries must never execute on the normal host.
- Runtime tools remain unavailable without a verified isolated worker supporting the requested operation. Do not fabricate a worker or provide a host fallback.
- Model-provided confirmation flags, URLs, keys, claimed attestation, or environment overrides cannot grant authority.
- Keep static inspection, project execution, attach/resume/write, network, device, and repository-write permissions separate.
- Revalidate target/script identity and consequential destinations after approval.
- Process exit, database integrity, artifact identity, and export coverage are separate outcomes. Existence or exit code alone is not proof of success.
- Protect last verified native databases; quarantine unverified outputs without deleting evidence.
- Mark partial coverage, unsupported operations, missing prerequisites, and unverified cleanup explicitly.
- Retry only idempotent operations; reconcile ambiguous remote writes before retrying.
- Preserve all existing customizations and validation gates. Update CUSTOMIZATIONS.md and scripts/verify-custom-fork.ts with actual behavior changes.

## Completion evidence

Contract tests for each implemented adapter must cover benign success, malformed data, timeout, cancellation, partial output, ownership, changed-input rejection, bounds, restart and redaction. Installed Windows smoke tests must exercise the enabled packs. Record the exact source commit, test receipts, installer hash and provenance. Licensed native and real-worker checks cannot be replaced by mocks.

Implementation requires a target-machine capability inventory, representative authorized fixtures, and non-secret worker protocol/capability information. Credentials must use a secure connection flow, never repository files or chat.

No final installer build should be launched from this staging commit as if it delivered the complete roadmap.
