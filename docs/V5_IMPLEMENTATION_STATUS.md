# V5 semantic reverse-engineering lab: development checkpoint

Base: verified V4 merge bb8325361d5c28507d3b79becec206bd72bcaa1f.
Branch: dev/semantic-re-v5-20261005, outside the existing feat/** installer trigger.

This checkpoint commits the native-program recovery modules only. They are not yet exposed as an operation: SDK schema/executor/workbench wiring, preservation ledger/verifier changes and required tests must follow together.

The fixed Ghidra script exports bounded decompiled pseudocode, function CFGs and high p-code. The host adapter privately snapshots regular-file input, binds SHA-256, filters Java injection variables and inherited secrets, cancels process trees and validates a strict 1 MiB evidence schema. It does not execute the target, accept caller scripts or establish OS containment. Decompiler interpretation is not native equivalence.

Validation has NOT completed. The local checkout and prepared files disappeared before fixture/build execution; no successful engine test, SDK build or installer is claimed. Remote source is the recovery authority. Ghidra 12.1.4 release archive reviewed checksum: ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db.

Remaining: managed tool packs; Rizin reconciliation; isolated QBDI worker/provisioning; semantic trace/taint; Triton/angr path reasoning; scoped MBA/opaque-predicate proofs; candidate CFG/virtualized-code reconstruction; Android/FlowDroid/JNI correlation; approved decoded-buffer capture/export; semantic diff; investigation UI; resumable jobs, caches and diagnostics. Remill and licensed integrations remain separate work. No VM, licensed installation, secret or release has been created. Full recommendations are unfinished.
