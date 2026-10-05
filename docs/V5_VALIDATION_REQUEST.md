# V5 source validation request

Validate native_crosscheck with the desktop-compatible BigInt constructor, keeping exact address-width guards and all 26 reconciliation regressions. The previous c1f2495 source job correctly failed the desktop type gate on a BigInt literal; SDK tests and Python/Z3 corpora passed, but native engine stages were skipped. Do not weaken the compiler target or skip checks.

Require explicit Ghidra base/entry coordinates, Rizin byte order and both real static engines on the same owned ELF, alongside every existing source/Python/Z3/Ghidra/Rizin gate. This is a Linux source/evidence job, not a Windows installer.

Location reconciliation is not semantic equivalence or whole-program recovery. Managed packs, runtime isolation/tracing, Android/JNI and investigation UI remain unfinished. No merge or release.
