# Bounded Rizin checkpoint

The static recovery module uses a private artifact snapshot with actual copied-byte SHA-256, bounded JSON, deadline/abort and process-tree termination, fixed aaa/iIj/aflj commands, -NN to disable user scripts/plugins and -x to disable executable I/O. Precise 64-bit hex addresses are retained; unsafe JSON-number addresses are rejected. No caller commands or native target execution.

Standalone validation observed 12 passing tests, including actual official Rizin 0.9.1 recovery of an owned compiled ELF; 27 assertions. The 11 portable parsing/boundary tests are retained here without the local-only fixture paths. This is NOT yet wired into the SDK action schema/executor/UI or consolidated CI, and no Windows Rizin execution, managed-pack installation, semantic equivalence or isolation is verified.

Rizin assembly CFG block counts and Ghidra high-p-code block counts describe different abstractions; differences are not automatically semantic disagreements. No extra installer or validation run is triggered by this module checkpoint. V5 remains incomplete.
