# Advanced-analysis V4 implementation status

This is an in-progress dedicated branch, not a completed implementation of every recommendation. No V4 installer has been built or verified yet. Main, tags and releases remain unchanged.

The portable engine corpus requires an explicitly configured absolute Python interpreter and pinned dependencies; missing engines fail rather than skip. It exercises the real SDK-to-worker path for Capstone disassembly, Z3 expression equivalence, Miasm bounded lifting, LIEF ELF parsing, Androguard DEX indexing, AES-GCM decryption and authentication failure. The owned fixtures never execute target code. The six-engine portable subset does not include Triton, QBinDiff, QBDI or licensed tools. Dependencies are not bundled into the desktop installer.

Local recovery work previously passed the full blocking source suite, 31 focused program-evidence/authoring/transport tests and the portable corpus (19 assertions). An unexpected local workspace reset occurred before those source changes were committed. Those historical passes do not certify this branch or a Windows installer. Source recovery, fresh validation, visual QA and installer packaging are still required.

Remaining scope includes an actual isolated QBDI worker, real Android lifecycle/dataflow integration, Remill, licensed JEB/IDA-D810 integration, full control-flow recovery and automatic VM provisioning. Client transport, imported dependency analysis and package presence must not be represented as real runtime execution or semantic equivalence.
