# Integrated APK incidents

The Analysis workbench's **APK incidents** tab coordinates device observations independently of the chat turn. Starting requires a hash-bound, single-use plan. A response loss is reconciled by refreshing saved cases; it must never be handled by repeating execution. SQLite checkpoints survive a view reload. Another process's running case is control-unavailable, not automatically reclaimed or replayed.

## Capture and diagnosis

Select an exact ADB serial, an owned workspace APK, its manifest package, manual reproduction steps and expected regression behavior. Observe an already-running app, explicitly launch it, or explicitly validate a candidate. The requested reproduction window is at most 120 seconds, with no new snapshot started after its deadline. In-flight ADB calls have separate deadlines; the whole task is bounded to the requested window plus 180 seconds. Capture retains at most 30 process snapshots/8 package-named PIDs per snapshot/256 KiB retained logs/20 crash records. Device SDK/ABI/fingerprint are observed without `su`, changing root policy or starting Frida. KernelSU and Frida remain unverified until a separately approved runtime workflow establishes them.

Before and after reproduction, a bounded base-APK read verifies the installed hash/package. This does **not** verify split APK contents or app data. The crash buffer is sampled in memory and only matching package records are retained; baseline records are excluded as historical. Java/native/ANR labels describe available records, not all possible failures. Missing processes are not automatically called OS kills. No complete ANR trace, kernel low-memory trace or tombstone collection is claimed. Sensitive fields are redacted heuristically; log capture still requires explicit consent and local evidence may contain private data.

## Correlation

Java correlation binds an operator-supplied mapping hash to the observed APK hash and provides bounded class/method candidates. A hash binding is not proof of mapping generation provenance. Ambiguous overloads remain unresolved; full retrace/line recovery is not implemented.

Native correlation verifies that the exact library bytes belong to the observed APK ABI member and requires matching module SHA-256, ELF GNU build ID, ABI and an executable file-backed PC range. ELF symbols resolve only an unambiguous range; stripped/overlapping functions remain unresolved. Load bias/module provenance are operator-supplied, not independently runtime-attested. Use existing approval-gated IDA/Ghidra exact-function tooling for further analysis. This is not universal deobfuscation, key recovery or automatic reconstruction of encrypted DEX.

## Patch validation and rollback

Original and candidate APKs must match the declared package. Candidate identity is checked again at execution; an approved private snapshot must pass the real `apksigner` verification before installation. Package replacement, execution, a dedicated test device and rollback plan each require acknowledgement. After installation, the installed base-APK hash must match the candidate before observation. Signature/key incompatibility or ambiguous install results fail without automatic uninstall or retry.

A separate rollback plan binds the original/candidate identities to a recorded candidate installation and verifies the currently installed candidate before restoring the signed original. Data/schema migrations are **not** undone; downgrades may be rejected by Android and will not be forced. An ambiguous change requires manual device inspection. Cancel stops observation but cannot undo an already performed install.

Completed means the bounded workflow finished, not that the bug is fixed. Save operator reproduction/regression notes. Absence of matching crashes alone never sets a `fixed` verdict.

## Readiness and evidence

Tool inventory distinguishes discovered executables from ADB command execution. Owned-fixture health uses the existing `analysis_readiness` executor through an explicit static plan and returns its engine evidence unchanged. Proprietary engines/licenses and runtime task readiness are not inferred from presence.

Artifact context menus include **Inspect evidence / archive**: canonical originating workspace, file hash, container classification and an explicit bounded member preview. ZIP64/encrypted/unsafe/ambiguous paths, unsupported compression, integrity mismatch, changed container hashes and expansion limits block preview. Archive members are never extracted or automatically executed. Binary members expose hash/size only. Remote workflows are explicitly blocked rather than resolving paths on the wrong local machine.

## Verification limits

Portable regression fixtures validate the workflow and parsers. No physical KSUN device, proprietary decompiler or production Windows installation has been validated by those fixtures. The exact committed Windows installer and regression workflows must pass before merge, followed by device-specific testing.
