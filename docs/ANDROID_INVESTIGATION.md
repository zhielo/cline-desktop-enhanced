# Android static investigation foundation

## Available now

Use **Analysis workbench → Advanced analysis**, select the function and review/approve the exact request. The same strict options are available through the `reverse_engineer` tool. Inputs are untrusted data, not executable instructions.

| Function | Input | Actual result |
| --- | --- | --- |
| `artifact_discovery` | APK/ZIP, DEX, blob or native file | Bounded recursive container/compression inspection, embedded DEX candidate carving, hashes and lineage |
| `android_relationships` | Same | The discovery result plus DEX loader/reflection pool references and derived JNI symbol-name candidates |
| `android_method` | Same plus exact selector | Matching method metadata, access flags, native declaration, bounded code range/raw-byte fingerprint where present; ambiguity across artifacts |
| `investigation_query` | Returned `investigationIndex.file` | Paginated saved artifact/method/reference/JNI-name evidence; no engines or targets execute |

The first three functions use the same fixed static scanner and produce a common evidence schema. They require an available Python executable, not Androguard/LIEF. The host launches it with `-I`, filtered environment, process-tree cancellation, output/time limits and a temporary private working directory. No user-supplied Python runs.

Example discovery options:

```json
{"discovery":{"max_depth":3,"max_artifacts":200}}
```

Example exact method selector (DEX descriptors, not Java source syntax):

```json
{"method":{"class_descriptor":"Lcom/example/Loader;","name":"load","descriptor":"([B)V"}}
```

Example saved-index query:

```json
{"investigation_query":{"kind":"jni-name-candidate","text":"native","offset":0,"limit":50}}
```

For a query, set the input target to the returned index file; it is not the original APK. The workbench may require explicit approval for a cache path outside the workspace. Model/tool calls must preserve their normal permission boundaries. `report_output_file` remains an explicit separate JSON export, not an index-path selector.

## Evidence and coverage

- Input: at most 64 MiB; expanded child: at most 16 MiB; total processed bytes: 128 MiB; nesting: 0–4; artifacts: 1–500; ZIP entries: at most 10,000; expansion ratio: at most 100. Defaults: depth 3, 200 artifacts. DEX pool/class-data, aggregate parameter/prototype/string-text, 50,000 parsed methods per investigation, 16 MiB retained method-text and 64 embedded-candidate budgets also apply. These bound work/recorded metadata, not an OS memory quota.
- APK/ZIP traversal checks every member name for traversal, absolute/drive paths, backslashes, duplicates, symlinks and encryption before reading any member. It reads in memory without extracting targets onto the host. CRC/expanded-size errors retain partial/rejected evidence. Unsafe or encrypted ZIP is rejected, not decrypted.
- Standard DEX 035–040: magic, size, endian, Adler32/SHA1, table/map bounds, string/type/prototype/method indices and bounded class-data/code-item ranges. **Not** complete Dalvik instruction/debug/try-handler verification or ART acceptance. Modified checksum-invalid DEX is retained as a rejected candidate. No attempt repairs it behind the user's back.
- Opaque/native blobs are searched for embedded standard DEX signatures with bounded declared lengths. ELF at the input/member start remains a signature candidate, not a structurally verified ELF. Use existing `native_inventory` for LIEF evidence and explicit-range disassembly for Capstone. Embedded ELF carving is not implemented.
- IDs bind content, artifact parent/path/offset and method index. Same-byte DEX under different member names has distinct artifact identity. Decompression lineage does **not** claim a physical byte offset in the compressed parent.
- Loader/reflection method pool references are not proof of an invoke or execution. JNI short/long names derive from native declarations, including UTF-16 JNI escaping. No export join or observed `RegisterNatives` binding is implied.
- Raw method byte fingerprints are not semantic equivalence proofs, recovered source or deobfuscation results. Missing exact matches mean “not found in covered artifacts,” never proof that hidden code does not exist.
- Entropy is descriptive only. High entropy is not proof of encryption; compressed/random content can behave similarly. The scanner does not recover unknown keys or encrypted bytecode.
- Output records, methods, loader references, selected methods and relationship counts expose truncation. If serialized evidence exceeds 900,000 bytes, the worker returns a failure and the user must lower limits; it never silently cuts JSON or claims success.

## Persistence

Successful and partial results are stored beneath the managed reverse-engineering cache's `investigations` directory. The index binds source hash, engine version, coverage and the full recorded evidence with a canonical SHA-256 ID. Atomic hard-link publication exposes a complete document without overwriting an existing index. Duplicate investigations reuse a verified identical index. Unsupported filesystems fail closed.

The cache may contain sensitive class names/strings/path metadata even though it stores no raw binary plaintext or key values. POSIX files/directories request private modes; Windows ACLs, disk encryption, retention and deletion remain operator responsibilities. Do not upload indexes without reviewing them. No secure deletion is claimed. JSON schema/size/content hash validation catches corruption; hashes are not signatures or authentication against a local attacker who can rewrite content and hashes.

## Not a runtime sandbox

Fixed code, input budgets and no target execution reduce risk but do not implement OS isolation. Do not run hostile APKs/ELFs on the desktop host. Runtime analysis requires an authorized disposable Android emulator/device or isolated VM, separate artifact upload and execution approval, and a verified worker. Existing runtime-client protocol support is not proof that a worker has been provisioned.

## Not yet implemented

1. Reliable DEX↔ELF export joins, proven static call-site edges and runtime `RegisterNatives` correlation.
2. Targeted Ghidra/IDA/JADX adapters that retrieve only chosen methods/functions, plus validated native CFG/address mappings.
3. Authorized isolated runtime capture of dynamically loaded/decrypted DEX and mapping captured hashes to loader events.
4. Transformation provenance with independent semantic/equivalence proofs and rollback; broad unflattening/devirtualization.
5. Provisioned disposable workers, strict desktop command-channel authentication audit/fix and production retention controls.

Optional engines, package inventory, static candidate names and imported traces must never be labeled as these capabilities. Keep these stages separate, with malformed-input fixtures, approval tests, real engine tests and Windows installed-app smoke before merge.

## Validation

`bun scripts/generate-android-investigation.mjs --check` ensures source/embed parity. The mandatory SDK tests run the stdlib Python corpus, actual supervised worker, strict input schemas and immutable index checks. Existing source preservation, long-session recovery, engine smoke, Windows installer and installed-sidecar tests remain blocking. A Linux source build is not Windows installer evidence.
