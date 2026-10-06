# Post-integration correctness and efficiency audit

## Baseline and scope

Baseline: main merge `38c595b08d2d7e8d7640e5e2e677e12ba6392008` (PR #102).
This is a targeted source audit and regression pass, not an assertion that the entire monorepo is bug-free. Review covered task approvals/retention, Android capture/result persistence, transport/capture receipt boundaries, session-recovery entry points and terminal output retention. No user device or production account was accessed.

## Confirmed defects and changes

1. **One-time approval race:** concurrent `consume` requests both passed the token check before asynchronous file hashing and both returned running. An in-flight claim now rejects the duplicate before hashing and live approval state is rechecked after hashing.
2. **Cancellation/expiry resurrection:** cancellation or approval expiry during hashing did not prevent execution promotion. The post-hash check now rejects both cases.
3. **Live ledger eviction:** adding a new plan at the cap silently removed an older pending/running plan. Retention now evicts terminal records only, protects in-flight claims, and explicitly rejects preparation when live work fills the cap.
4. **Plaintext output privacy:** an existing empty, negating, directory or symlink `.gitignore` was accepted and capture files were published. A managed regular ignore-all rule is now mandatory before contacting the worker and is rechecked for publication. Existing unsafe ignore rules are not overwritten. Staging cleanup also encloses write and sync errors.
5. **Advertised upload budget:** Android capture enforced only the desktop cap, not a smaller signed worker maximum. Both limits are now respected before upload.
6. **Collector result anomaly:** invalid status could be signed as-is, while validation/serialization/output-budget errors after execution left a started nonce stuck running. Bounded validation now records a sanitized, signed failed receipt and preserves one-shot nonce semantics.

## Efficiency change

Terminal head/tail UTF-8 truncation now uses byte-boundary slicing with an unchanged-text fast path. This removes full code-point arrays and per-character concatenation. Unicode fixtures exercise 2, 3, 7, 80 and 1024-byte budgets, including exact omitted-byte accounting. An isolated Bun 1.3.14/Linux microbenchmark trimmed a 983,040-byte synthetic Unicode string to a 65,536-byte prefix and suffix, asserting identical outputs. After three warmups, medians over fifteen runs were 37.37 ms on the baseline and 4.07 ms with byte slicing. These figures describe this one synthetic operation, not overall application speed, production latency, Windows ConPTY performance, or measured memory savings.

## Regression evidence

Before implementation changes, the new TypeScript regression cases reproduced ten failures on the baseline; a worker regression also failed on an invalid signed collector status. Existing tests remained enabled. After the fix, the targeted approval/capture suites and expanded process-output suite passed, as did the Python worker corpus. The existing comprehensive validator passed all 16 local gates (SDK build, desktop/core typechecks, required sidecar regression suite, installer configuration, task report, authentication, recovery, Hub deadlines, chat UI, customization, real Hub shutdown and focused SDK safety). The three Android worker suites passed 28 tests. Full engine validation was not requested: these are controller fixtures, not live Android, native engine or proprietary decompiler evidence. All workspace typechecks completed successfully. Full workspace lint completed with zero errors, 38 warnings and 129 informational diagnostics; these remain a separate non-blocking cleanup backlog, not a claim of a warning-free repository. The compiled Linux desktop-backend startup smoke test also passed, including its authentication checks and embedded Hub. Windows installer creation and exact-head CI remain separate from these Linux working-tree checks.

## Deployment limits

- Captures require a dedicated output directory with an exact `*` rule followed by LF or CRLF. Users with incompatible rules should select a new dedicated directory, not disable the guard.
- Ignore rules prevent accidental normal Git discovery, not encryption, force-add, already-tracked files, malicious local processes, or filesystem race attacks by a compromised host.
- Worker signing, isolation, Frida/KSUN authorization and safe device cleanup remain operator requirements; tests use owned fixtures, not real phone execution.
- The Linux audit environment cannot validate native Windows ConPTY/NSIS or proprietary IDA/Ghidra installation behavior. Windows exact-head CI and manual device/decompiler smoke checks remain necessary.
- No provider credential, root configuration, artifact retention policy or release publishing policy is weakened.
