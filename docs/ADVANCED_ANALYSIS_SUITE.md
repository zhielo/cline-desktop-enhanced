# Advanced analysis — integration release candidate

This is a partial implementation, not all recommendations completed.

## Working operations

Use the existing reverse_engineer tool with operation `advanced_analysis` and advanced_action: toolchain, suite, triage, apk_inventory, dex_index, native_inventory, native_disassemble, simplify_expression, compare_expressions, triton_expression, match_native_functions, transform_blob.

Install reviewed optional packages from `sdk/packages/core/scripts/requirements-advanced-analysis.txt` in a dedicated Python virtual environment; set the host's CLINE_RE_PYTHON to its absolute interpreter path. The desktop does not install packages, activate licenses or execute a sample.

- DEX: standard header/table bounds and tested Androguard 4.x classes, methods, native declarations and invoke operands. Not a complete call graph or lifecycle dataflow.
- ELF: LIEF structure, symbols, relocations and JNI export candidates. No verified JNI registrations.
- Disassembly: explicit architecture and bounded file-offset/address/bytes through advanced_options. No function discovery.
- Z3/Triton: JSON bit-vector ASTs, never user code. Equivalence is under the supplied expression model only.
- QBinDiff: two BinExport files (target and compare_target), maximum 1,000 functions per export. Heuristic similarity, not semantic equivalence.
- Transform: advanced_options.steps supports hex/base64/zlib/gzip. Provenance receipts only, not decryption or derived-binary writing.

Expression example:
```json
{"bits":32,"expression":{"op":"xor","args":[{"var":"x"},{"var":"x"}]},"compare":0}
```
Operations: add/sub/mul/xor/and/or/shl/lshr/not/neg. At most 2,048 nodes, depth 32. Z3 checks have a 2-second budget; Triton is bounded by the outer worker deadline.

## Trust and coverage

128 MiB input, 10,000 ZIP entries, 512 MiB declared expansion, 1,000 result rows, 1 MiB stdout, five-minute maximum deadline. No extraction or target execution. Credentials are filtered; parser stderr is discarded; process-tree cancellation is supported. This is not OS containment: hostile inputs still warrant a disposable VM.

The full request remains bound to existing prepare/approve/consume tokens. Optional JSON reports are exclusive-create and output-scoped. Input hashes, engine versions, limitations, statuses and bundle hashes accompany evidence. Package presence is not health verification.

## Not implemented

QBDI runtime tracing, native trace taint, FlowDroid lifecycle analysis, Remill and advanced CFG/microcode transformation passes, JEB/IDA-D810 licensed workflows, virtual-dispatch recovery. Corresponding declared actions return blocked. No attested worker is provisioned or remote execution enabled by this change.

Windows engine execution and NSIS setup.exe packaging must be completed before release. The static workbench controls were visually inspected in an isolated fixture, not in a native packaged application. Do not label this a finished high-end platform or a successful Windows build.


## Evidence graph

`graph_build` takes a JSON manifest `{"schemaVersion":1,"results":[<advanced-result>,...]}` containing the `result` objects from exported analysis reports, not the whole wrapper. It returns evidence.graph; save that graph alone to query it. `graph_query` accepts advanced_options.graph_query with kind, literal text, startId, depth (0..8), and limit (1..1000). No Cypher, SQL, scripts or regex from the caller are executed. Graphs carry report hashes, artifact identities, stable IDs, coverage notes and unresolved/candidate edges. They do not authenticate imported reports or claim a complete call/JNI graph.

## Durable static notebooks

A notebook is a strict JSON document:
```json
{"schemaVersion":1,"title":"Owned APK investigation","cells":[{"id":"inventory","action":"apk_inventory","target":"sample.apk"},{"id":"dex","action":"dex_index","target":"classes.dex","dependsOn":["inventory"]}]}
```

Use notebook_validate to preflight all cells without execution, then notebook_run to run the static DAG. Maximum 20 cells, 512 MiB aggregate declared inputs, five-minute overall engine deadline, 128 MiB per artifact. All paths are forward-slash relative paths canonically confined to the notebook's folder; parent traversal, external paths and escaping symlinks are rejected. Engines do not execute targets. States are privately checkpointed in the host-managed analysis cache. Completed results are reused only for matching adapter version, engine metadata, input hashes, options and dependency result hashes. Partial/failed/running cells rerun; corrupted state is discarded. Checkpoints are atomic, not cryptographically authenticated against privileged local tampering.

These are backend/tool operations; graph editing and notebook-authoring UI are not shipped in this increment.


## Bounded static IR and expression passes

`lift_native_ir` and `deobfuscation_pass` now use a real Miasm 0.1.5 adapter for x86/x86_64/ARM/Thumb/AArch64 little-endian instruction bytes. Set explicit architecture, file offset, virtual address and byte range through advanced_options. Only one decoded basic block is lifted, with at most 1,000 input instructions and 256 generated IR blocks. The expression pass retains IR before/after and reports its changes. No target execution, reachable CFG exploration, native rewriting or independent whole-program equivalence proof is claimed. This is not Remill, IDA-D810, virtualized-code recovery or full control-flow unflattening.


## Known-key authenticated blob decryption

`decrypt_blob` supports AES-256-GCM and ChaCha20-Poly1305 for owned/authorized ciphertext. The target contains ciphertext followed by its 16-byte authentication tag. Set advanced_options.decrypt.algorithm and nonce_hex (24 hex characters / 12 bytes); optional aad_hex supplies associated data. analysis is triage (default) or structured. Optional advanced_options.steps decodes a bounded base64/hex/zlib/gzip prefix chain before authentication. Input and decoded ciphertext are limited to 16 MiB. Wrong keys, nonces, tags or associated data fail authentication and produce no recovered-content report.

The host owner must explicitly configure CLINE_RE_ALLOW_DECRYPTION=1, an absolute trusted CLINE_RE_PYTHON, and CLINE_RE_PRIVATE_KEY_FILE pointing to exactly 32 raw key bytes that already match the encrypted file. Do not generate a new random key expecting it to decrypt existing ciphertext. Do not put keys into tool arguments, notebook JSON, chat, environment values or the repository. On POSIX the key file must be owned by the current account and inaccessible to group/others; on Windows the owner must provision restrictive ACLs. The environment contains only a private file path, not key bytes, and the grant is withheld from other analysis actions.

This adapter returns authenticated provenance, hashes, triage and optionally static DEX/ELF/APK evidence. It does not export plaintext binaries or attempt key recovery. Native/archive parsing uses a mode-0600 temporary file deleted after the stage. Secure erasure, guaranteed key-memory zeroing, OS containment and Windows engine validation are not claimed. Decryption is deliberately excluded from notebook cells to prevent unreviewed key use by a notebook manifest.

## One consolidated validation command

Run `bun run validate:advanced` after installing the frozen dependencies. SDK prerequisites run first; independent blocking suites run in parallel with a default concurrency of 2. Logs and summary.json are written under .cline-validation and uploaded by the Windows workflow, including failed runs. Nonzero status blocks packaging. Set CLINE_VALIDATION_PARALLEL to an integer 1..4 only when the host has sufficient resources.

For engine-backed fixture coverage, configure the reviewed Python environment and run `bun run validate:advanced --engines`. Without this option, optional engine fixtures are explicitly not requested; they do not become tested because package metadata is present. NSIS build and installed-binary smoke remain separate required stages after source validation. Missing runtime/licensed capabilities listed above remain missing.
