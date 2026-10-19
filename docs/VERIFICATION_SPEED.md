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
