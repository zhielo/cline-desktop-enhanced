# Verification speed without weaker release gates

## Two tiers

- `bun run validate:quick`: dependency-free feedback after Bun is available. Checks generated ARM64/Android fixtures, validator contracts, verification-speed contracts and Windows workflow hardening. Fixed arguments, no shell interpolation, bounded processes and fail-fast. It is not a release certificate and does not run all tests.
- `bun run validate:advanced` plus required CI: the complete blocking validation, engine fixtures, fresh Windows installer, installer smoke and installed WebView journey still run for the exact candidate. No path filters, cache-hit bypass, cross-commit test-result reuse or reduced stage counts were added.

The Windows installer and regression workflows run the quick tier before helper downloads, packaging tools, Rust setup and dependency installation. Full validation keeps its existing resource-safe single-worker schedule and complete gate names.

## Caches

- Bun download cache: OS, architecture, exact supported Bun version and both root/instrumentation lockfiles. Frozen dependency installation always runs; `node_modules` is not restored as a test-result cache.
- Cargo: architecture, exact toolchain, lockfile, Rust source/build/config fingerprints and source commit. An immutable lock-only key previously prevented saving fresher compiler outputs after exact hits. The source-commit suffix also refreshes outputs when embedded frontend/sidecar inputs change. NSIS bundles are excluded from the compiler cache. Restore is confined to the same toolchain/architecture/lock prefix. Cargo and the Tauri build still run, and old NSIS outputs are removed before selecting one fresh installer.
- Next: only `.next/cache`, keyed by OS/architecture/Bun/lock/source commit with a same-lock restore prefix. Neither exported frontend output nor installed-app evidence is accepted from this cache.

Existing same-job, exact-source, exact-run-attempt core receipt reuse for the engine phase is retained. No new unchecked build-skip flag was introduced.

## Timing and optimization decisions

`scripts/summarize-verification.mjs` adds a diagnostic job summary from bounded, same-source/same-run validation receipts and exact-sequence installed action journal pairs. It lists the ten slowest recorded gates/actions, includes failed outcomes, and omits child logs, paths, requests and environment values. It cannot approve a release. Missing durations remain unavailable. Concurrent durations are not additive wall time; journaled actions do not cover the entire installed journey.

Observed baseline: PR142's Windows job ran 48m07s, consolidated core validation 14m15s, NSIS build 10m31s, installation smoke 2m19s and installed WebView acceptance 7m31s. Within the core report, sidecar regression took about 230s and complete workspace typechecking about 199s. These are observations from one hosted run, not controlled benchmarks or a promise of faster future runs.

The installed journey shares approvals, profiles, runtime rollbacks and retained evidence across phases. It must not be split naively or have survival-observation windows shortened. Isolated sharding and additional build-output reuse remain follow-up work requiring explicit dependency contracts and independent acceptance. Measure cold and warm runs before claiming a speed improvement; retain the serial path if resource contention worsens reliability.

## Conditional packaging checks

Root package/lock and packaging changes trigger `desktop-test` in addition to the normal check set. The finite release policy recognizes its two exact check names. If either appears, both must be completed successfully for the exact head and trusted Actions app; skipped, missing, duplicate, failed or unknown checks still block release. When this path-triggered workflow is absent, the existing twenty required checks remain mandatory. This fixes a reproduced false rejection without accepting arbitrary additional checks.

## Exact-head release check routing
Desktop app, consolidated validator and custom Windows release workflow changes also trigger the extension, testing-platform and cross-platform E2E path filters. The release verifier continues to require successful named checks for the exact head; a path-filter skip is not accepted as a substitute for those required checks. The optional compiler caches never reuse a test result or installer.

PR E2E runs restore the Bun download cache read-only. Cache publication is limited to successful non-PR runs, retaining its one-minute limit. This prevents a passing PR test run from being cancelled solely by an optional upload at the overall job deadline; the twenty-minute E2E job limit is unchanged.

## Bounded Android fixture groups
Windows SDK evidence exposed a mismatch: the complete Python corpus had a 60-second child-process timeout inside a 20-second Vitest deadline. The SDK test now executes four sequential, dynamically discovered unittest groups, with each child bounded to 18 seconds under the unchanged 20-second test deadline. Each group validates its exact modulo partition of the full discovered case inventory, its count and successful completion. All current 80 cases are covered exactly once; optional-engine skip rules are unchanged. The other full Python gate still runs the complete corpus normally. No application runtime budget, global test timeout or release requirement was increased.

### Final candidate verification protocol

Mark the PR ready for review before freezing its final verification commit. The
`ready_for_review` event intentionally starts fresh E2E checks and may cancel
older same-head runs; those cancellations must not be treated as successful
release evidence. Use one final source commit after that transition so the
strict release collector receives an unambiguous exact-head check set. Do not
change code while that candidate builds unless a concrete defect is found.

Local checks for this change include the full workspace type check and lint
(lint warnings are reported, not promoted to clean output), fork preservation,
15 focused Android SDK tests, all 80 dynamically discovered Python corpus
cases across four groups, 48 workflow regressions and 45 release-gate tests.
Local results never replace the fresh Windows installer, installed WebView
acceptance, artifact digest validation or prospective merge-tree identity.

### Installed acceptance transport

The full installed journey must reuse one page-local authenticated WebSocket
with correlated request IDs, not create and close a new connection for every
RPC. Keep at most 32 pending calls and the existing 90-second call deadline.
A handshake error, close, malformed reply, timeout or native endpoint rotation
rejects outstanding calls without replaying them, including approval commands.
A later explicit call can discover a new endpoint; earlier requests are never
copied to it. Page reload/native restart creates a new page-local transport.
Product capability authentication and approval boundaries remain unchanged.

The failed frozen run built and smoke-tested the installer, then recorded an
authenticated transport error during an approval call after the project-file
inventory checks. This establishes a transport failure, not a compiler or
installer failure; the original browser error did not expose a precise cause.
Tests now cover 500 correlated calls on one socket, concurrent response ordering,
pending limits, endpoint rotation, redaction, malformed messages, handshake
errors and deadline cleanup with no automatic replay. Fresh full installed
acceptance is still required before merge.

### Inspector protocol fixture clock

The emulated owned Inspector fixture now emits CDP-style fractional epoch
milliseconds using the same high-resolution clock as the collector. Mixing
Windows' coarsely quantized `Date.now()` with fractional receipt timestamps can
make a live fixture report appear to be in the future. Failure output now lists
discard reasons and source-match counts. The production past/future guards,
300-millisecond fixture observation window, 20-second test deadline, exact
passive command sequence, replay rejection and source binding are unchanged.
Five repeated local Inspector/collector runs passed (15 tests each); the full
16-file static parser group passed with 109 tests and two platform skips.
Fresh Windows execution remains necessary to validate the correction there.
