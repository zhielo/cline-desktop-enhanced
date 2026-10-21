# Semantic source port validation record

## Local results

Validated on Linux against pinned REA source revision `d0067ba34a39ea47dd7e11bb2e6169bc0938cc3f`.

| Check | Result |
| --- | --- |
| SDK build (all packages) | Passed |
| Repository-wide TypeScript checks (`bun run types`) | Passed, including CLI/VS Code consumers and core smoke configurations |
| Repository CI lint gate | Passed |
| Desktop sidecar bundle | Passed |
| Custom-fork preservation | 309 source contracts passed |
| Source provenance | 138 source/test files verified |
| Analysis, tool schemas, permissions, routing and definitions regression | 548 passed; 1 Windows-only test skipped on Linux |
| Exact upstream differential comparison | 12 owned file-local fixtures passed (one parameterized test) |
| Desktop analysis UI and sidecar tests | 26 passed |
| Owned worker, persistence and saved trace smoke | Passed |
| Whitespace and workflow YAML checks | Passed |

These are development results, not installed-Windows acceptance. CI results must be reviewed independently; a green build does not establish full capability parity.

## Release blockers and remaining migration

- Windows matrix and installer workflow must pass on the published branch.
- An installed Windows app must pass opt-in analysis, persisted evidence, tracing, cancellation, permission denial and historical-evidence checks.
- Cross-module application graph linking and complete artifact selection have not been ported.
- Bundle recovery, native high-p-code tracing, managed workflows, runtime reconciliation, reconstruction obligations and remaining specialist providers are not completed by this patch.
- Full REA capability parity and superiority remain unproved. The differential corpus establishes equality only for its tested file-local programs.
- Saved queries currently load and validate a bounded whole graph. Fixed-RSS/streaming guarantees and a new OS sandbox are not provided.

Keep this change in draft. Do not merge or describe it as a mature full REA replacement based solely on these local checks.
