# Conservative native entry reconciliation

`native_crosscheck` runs the fixed Ghidra and Rizin adapters on a selected native target with one shared time budget. It accepts only existing native function-selection/budget options, not caller commands or scripts. Both reviewed engine paths must be configured; missing capabilities fail closed.

The comparison requires identical actual copied-byte SHA-256 and byte count. Ghidra now records image base, address space, executable format and explicit per-function address; Rizin records byte order. Only compatible x86 32/64-bit ELF loaded virtual addresses in the ram space are currently reconciled. Exact integer subtraction normalizes differing load bases without JavaScript-number rounding or wraparound. Older evidence, overlays, other architectures, contradictory identity and missing byte order never become guessed matches.

The compact report separates entry-location agreement, unique literal name-only candidates, unmatched selections and unresolved evidence, preserving source program hashes, versions and coverage. Names never establish agreement. Ghidra high-p-code and Rizin assembly CFG block counts are deliberately not compared. Recovery/selection truncation remains partial even if a wrapper says completed. Hashes bind data identity, not privileged-tamper protection or engine correctness.

The required portable unit suite and Linux same-owned-ELF two-engine corpus join the existing validation gates. The owned compiled fixture is parsed/decompiled, never executed. Source checks have passed locally; the new two-engine real corpus must pass committed CI before this milestone is considered verified.

This adds location reconciliation, not native semantic equivalence, whole-function boundary agreement, runtime tracing, automatic patching, managed Windows packs or a V5 installer. The wider V5 roadmap remains incomplete.
