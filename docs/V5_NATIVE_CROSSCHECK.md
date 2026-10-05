# Conservative native entry reconciliation

## Verified implementation

Tested source: `6bede76d31062faef907d27ea526ec9ca721e7bb`.

Required consolidated source/engine job passed in 4m11s; total workflow duration 4m15s:
https://github.com/zhielo/cline-desktop-enhanced/actions/runs/37316598263

Evidence:
https://github.com/zhielo/cline-desktop-enhanced/actions/runs/37316598263/artifacts/11348222485

Downloaded evidence ZIP SHA-256 was independently computed and matched the published digest: `43a99e45f654caeb8043214963a94933223aac0d37886a335f8eddc9f561cb6e`.

`native_crosscheck` runs fixed Ghidra and Rizin adapters on a selected native target with one shared time budget. It accepts existing native function-selection/budget options, not caller commands or scripts. Both reviewed engine paths must be configured; missing capabilities fail closed.

Comparison requires identical actual copied-byte SHA-256 and byte count. Ghidra records image base, address space, executable format and explicit per-function address; Rizin records byte order. Only compatible x86 32/64-bit ELF loaded virtual addresses in the ram space are currently reconciled. Exact integer subtraction normalizes differing load bases without JavaScript-number rounding or wraparound. Older evidence, overlays, other architectures, contradictory identity and missing byte order never become guessed matches.

The compact report separates entry-location agreement, unique literal name-only candidates, unmatched selections and unresolved evidence, preserving source program hashes, versions and coverage. Names never establish agreement. Ghidra high-p-code and Rizin assembly CFG block counts are deliberately not compared. Recovery/selection truncation remains partial even if a wrapper says completed. Hashes bind data identity, not privileged-tamper protection or engine correctness.

## Required evidence

- 26 reconciliation boundary regressions join the 204-test focused SDK safety group.
- Desktop/core types, SDK build, full desktop sidecar suite, installer configuration, task report, chat UI and customization gates passed.
- All full pinned Python engine, Miasm IR, authenticated-crypto and real Z3 model corpora passed.
- Real Ghidra owned-ELF adapter: 1 pass, 14 assertions.
- Real Rizin owned-ELF adapter: 1 pass, 8 assertions.
- Real same-owned-ELF Ghidra/Rizin reconciliation: 1 pass, 12 assertions, including matching copied-byte hash, explicit entry-location agreement, retained engine versions and no semantic-equivalence claim.

The compiled owned fixtures are parsed/decompiled, never executed. An initial CI run rejected a BigInt literal under the existing desktop compiler target; using `BigInt(1)` retained exact width checking without raising the target, changing assertions or skipping gates.

This adds location reconciliation, not native semantic equivalence, whole-function boundary agreement, runtime tracing, automatic patching, managed Windows packs or a V5 installer. The wider V5 roadmap remains incomplete.
