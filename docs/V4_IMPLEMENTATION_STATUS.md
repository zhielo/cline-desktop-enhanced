# V4 capability status

Implemented source: imported CFG dominance/loops/SCCs; explicit-location trace slices and overwrite-aware influence; data-only notebook/graph authoring; immutable worker/artifact-bound approval and signed submission receipts; bridge hardening; mandatory portable Windows engine execution.

Source tests and source recovery are not installer proof. Verify the dedicated-branch GitHub Actions installer run, installed-app/sidecar smoke and verified artifact before treating packaging as successful. CI commits materialized source before starting the installer workflow.

The six-engine corpus executes LIEF ELF parsing, Capstone disassembly, Z3 expression equivalence, Miasm bounded IR, Androguard DEX indexing and authenticated AES-GCM decryption/failure. Missing engines fail. These dependencies are CI-only, not bundled into the installer, and do not validate Triton/QBinDiff, QBDI or licensed tools.

Not implemented: real QBDI worker/deployment, FlowDroid lifecycle analysis, Remill, JEB/IDA-D810, full unflattening/devirtualization, key recovery and automatic/measured VM provisioning. Imported dependencies are not opcode-semantic taint or actual trace acquisition. Signed capabilities are operator claims, not hardware attestation; local cancellation does not prove remote teardown. Full recommendations remain unfinished. No automatic merge, tag or release.
