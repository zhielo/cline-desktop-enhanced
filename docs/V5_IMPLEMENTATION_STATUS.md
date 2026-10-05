# V5 implementation status

## Verified static milestones — not the complete V5 roadmap

Latest tested implementation: `6bede76d31062faef907d27ea526ec9ca721e7bb`.

Consolidated source/engine workflow passed in 4m15s (job 4m11s):
https://github.com/zhielo/cline-desktop-enhanced/actions/runs/37316598263

Evidence artifact:
https://github.com/zhielo/cline-desktop-enhanced/actions/runs/37316598263/artifacts/11348222485

Downloaded ZIP SHA-256 was computed and matched the published artifact digest: `43a99e45f654caeb8043214963a94933223aac0d37886a335f8eddc9f561cb6e`.

The earlier Ghidra/Z3/Rizin milestone at `6f519f55c650cd18663e3284c3b0aeebde8521e9` also passed its required source and engine job. The newer milestone adds conservative entry-location reconciliation, not whole-function semantic agreement.

## Implemented and connected

- `native_program`: Ghidra 12.1.4 bounded static functions, pseudocode, high-p-code and CFG, privately copied artifact hashes and explicit null outputs. Entry provenance distinguishes address containment, uniquely incoming-free structural high-CFG inference and unresolved entry. Structural inference is not native-entry proof. Explicit image base, address space, executable format and per-function entry coordinates are now exported.
- `native_semantics`: fixed Z3 5.1.0.0 p-code DAG overapproximation worker, validated private JSON, bounded simplification and branch candidates. Unsupported operations, cycles and missing definitions become unconstrained cutpoints. Model-level equivalence is not native execution or whole-function equivalence; memory aliasing, calls, phi nodes and path feasibility are not modeled.
- `native_functions_rizin`: Rizin 0.9.1 bounded static inventory through private snapshots, actual copied-byte SHA-256, precision-safe addresses, fixed plugin/script-disabled and executable-I/O-disabled commands, output limits, cancellation and deadlines. Host-owned absolute `CLINE_RE_RIZIN` configuration is required. Byte order is now retained.
- `native_crosscheck`: both fixed static adapters under one shared deadline, identical artifact hash/byte requirement, exact relative-address normalization and width guards. Compatible explicit x86 ELF locations only. Entry-location agreement, name-only candidates, unmatched selections and unresolved coordinates remain separate. Assembly and high-p-code block counts are not compared. This is not native semantic equivalence.
- SDK schema/executor and workbench selectors, required boundary tests, preservation contracts and source-only validation workflow.
- Transformation byte-budget defaults resolve at call time; invalid or larger-than-current budgets are rejected. The original expansion regression remains mandatory.

## Required validation evidence

All blocking source gates passed: preservation, SDK build, core/desktop types, full sidecar regressions, installer configuration, task reports, chat UI, customization and focused SDK safety suites. Reported test groups: 11, 174, 68, 204 and 1254 passes; these are separate group counts, not a globally unique total. The SDK safety group includes all 26 reconciliation cases, 17 native evidence cases and 11 Rizin boundary cases.

All full pinned Linux Python engine, Miasm IR, authenticated-crypto and real Z3 model corpora passed. Real Ghidra SDK recovery passed 14 assertions; real Rizin passed 8. The new same-owned-ELF two-engine comparison passed 12 assertions, retaining matching copied-byte hash and location evidence without a semantic proof. No target binary was executed.

Ghidra/Rizin release archives are checksum checked. The Corretto provider archive checksum and Java version are logged; its latest URL is not a fixed-version reproducibility pin. These CI-installed engines have not been bundled into a V5 Windows installer. Native Windows Ghidra/Rizin/crosscheck execution remains unverified.

## Still unfinished

- Managed portable packs, dependency/license manifests, rollback, fixture health and Windows Python/tool bundling.
- Broader ARM/Android/PE reconciliation, function-boundary/IR/behavior comparison and native semantic validation.
- Real QBDI isolated tracing worker, VM provisioning, measured network denial, cancellation and teardown; signatures are not measured attestation.
- Opcode/register/flag/memory-aware taint, trace-guided Triton/angr and higher-order deobfuscation/virtual-handler recovery.
- FlowDroid execution, Android lifecycle/multidex/split/reflection coverage, JNI correlation and authorized observed RegisterNatives/Frida capture.
- Authorized selected-buffer/derived-artifact capture with separate plaintext export and retention approval.
- Synchronized investigation UI, semantic comparison, evidence-aware AI, resumable content-addressed jobs and support diagnostics.
- Final consolidated Windows validation and one installer candidate.

No V5 installer was dispatched, PR merged, tag/release created, VM deployed or user-PC installation performed. V4 remains the previously verified and merged installer milestone. V5 is not complete.
