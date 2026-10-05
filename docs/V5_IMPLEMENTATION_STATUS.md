# V5 implementation status

## Verified static milestone — not the complete V5 roadmap

Tested implementation commit: `6f519f55c650cd18663e3284c3b0aeebde8521e9`.

Consolidated Linux source/engine validation succeeded in 4m03s:
https://github.com/zhielo/cline-desktop-enhanced/actions/runs/37308654937

Evidence artifact:
https://github.com/zhielo/cline-desktop-enhanced/actions/runs/37308654937/artifacts/11344468743

Artifact SHA-256: `0d1e08b82dc78c283affc9ef05bf8a91bd1af9f0e6c7f5f407885b6ca2def08f`.

## Implemented and connected

- `native_program`: Ghidra 12.1.4 static recovery of bounded functions, pseudocode, high-p-code and CFG. Private snapshots bind the reported input hash to actual copied bytes. Explicit null outputs are retained. Entry provenance distinguishes address containment, uniquely incoming-free structural high-CFG inference and unresolved entry; ambiguous/cyclic-root claims are rejected. Structural inference is not native-entry proof.
- `native_semantics`: fixed Z3 5.1.0.0 p-code DAG overapproximation worker, strict validated private JSON input, bounded simplification and branch candidates. Unsupported operations, cycles and missing definitions become unconstrained cutpoints. Model-level equivalence is not native execution or whole-function equivalence; loads/stores, aliasing, calls, phi nodes and path feasibility are not modeled.
- `native_functions_rizin`: Rizin 0.9.1 bounded static function inventory through a private snapshot, exact copied-byte SHA-256, precision-safe addresses, fixed plugin/script-disabled and executable-I/O-disabled commands, output limits, cancellation and deadlines. Host-owned absolute `CLINE_RE_RIZIN` configuration is required.
- SDK schema/executor and workbench selectors for these actions, mandatory boundary tests, preservation contracts and source-only validation workflow.
- Transform byte-budget defaults now resolve at call time; invalid or larger-than-current budgets are rejected. The original expansion regression remains mandatory.

## Validation evidence

All source prerequisites and blocking source checks passed, including core/desktop types, sidecar regressions, installer configuration, desktop chat/customization and SDK safety groups. Reported test groups: 11, 174, 68, 178 and 1254 passes; these are separate group counts, not a claim of globally unique tests.

Required full pinned Linux Python engine, Miasm IR and authenticated-crypto corpora passed. Real fixed-worker Z3 corpus passed. Real Ghidra SDK adapter on an owned compiled ELF passed 14 assertions, including nonempty p-code, entry binding and copied-artifact hash. Real Rizin SDK adapter on a separate owned compiled ELF passed. These fixtures are static-analysis/model tests; no target binary was executed.

Ghidra/Rizin release archives are checksum checked. The Corretto provider archive checksum and Java version are logged; its latest URL is not a fixed-version reproducibility pin. None of these CI-installed tools has been bundled into a V5 Windows installer.

## Still unfinished

- Managed portable packs, dependency/license manifests, rollback, fixture health and Windows Python/tool bundling.
- Cross-engine address/semantic reconciliation; Rizin assembly block counts and Ghidra high-p-code blocks are different abstractions and cannot be directly treated as semantic agreement/disagreement.
- Real QBDI isolated tracing worker, VM provisioning, measured network denial, cancellation and teardown; signatures are not measured attestation.
- Opcode/register/flag/memory-aware taint, trace-guided Triton/angr and higher-order deobfuscation/virtual-handler recovery.
- FlowDroid execution, Android lifecycle/multidex/split/reflection coverage, JNI correlation and authorized observed RegisterNatives/Frida capture.
- Authorized selected-buffer/derived-artifact capture with separate plaintext export and retention approval.
- Synchronized investigation UI, semantic comparison, evidence-aware AI, resumable content-addressed jobs and support diagnostics.
- Final consolidated Windows validation and one installer candidate.

No V5 installer was dispatched, PR merged, tag/release created, VM deployed or user-PC installation performed. V4 remains the previously verified and merged installer milestone. V5 is not complete.
