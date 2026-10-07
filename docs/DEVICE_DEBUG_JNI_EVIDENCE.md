# Selected device diagnostics and signed JNI evidence

This integration extends the existing signed Android/Frida collector and APK incident workflow. It does not introduce another arbitrary-script or root-shell tool. It implements selected device-report collection and authenticated registration queries, not a full-device forensic acquisition or automatic patching system.

## Selected crash/ANR reports

In **Analysis → APK incidents**, select **Read selected tombstone / ANR reports (no launch)**. Supply the original workspace APK, exact package, explicitly authorized device serial and 1–6 exact report paths, one per line. Supported paths are `/data/tombstones/tombstone_00` through `_99` and `/data/anr/anr_` text filenames containing only letters, numbers, underscores, dots and hyphens. Protobuf tombstones, arbitrary directories, global bugreports, traversal and duplicate paths are rejected. This version does not automatically enumerate other apps' system crash-directory contents.

**Root is off by default.** Enable it only for those selected reads and acknowledge `explicit-root-read-without-policy-change` in the prepared approval. KernelSU denial ends the capture; no retry, unprivileged-to-root escalation, root-policy change or authorization bypass occurs. The operator must already know/authorize the report paths. Some devices use unsupported stat/head formats or different paths; such evidence is blocked rather than guessed.

The incident verifies the installed base APK matches the approved workspace APK before and after, checks device identity and uses fixed ADB read commands only. It never installs, launches, force-stops, clears logs or attaches Frida. A selected-device `get-serialno` is rechecked around collection. Symlinks/nonregular files are blocked; size/inode/mtime must stay consistent during reading. These metadata checks do not eliminate every filesystem race or prove hardware identity.

Each source read is capped at 200,000 bytes. Prefix-only evidence is labelled explicitly. Package-marker filtering removes unmatched process sections before returning/persisting text; this is marker-based attribution, not a cryptographic claim about report contents. Acknowledgement covers reading the operator-selected report files, which can contain other process headers before filtering. Common credential syntax is redacted, but private data/credentials are not guaranteed absent.

Private report files use SHA-256 names and restrictive modes under the Cline data cache. Their journal entries contain source/completeness metadata and bounded parsed counts/findings, not the full text. **View hash-bound report** rereads a bounded regular file, checks its identity/hash and provides the full retained scoped text plus parsed native/thread/lock evidence. Historical report age is not established; lock-wait candidates are not proven deadlocks or root causes. “Captured” is not “fixed” or a proof that no crash occurred. Full-file reads remain limited, and source completeness is distinct from package-scoped retained content.

## Signed live JNI query

In **Analysis → Execution lab → Signed live JNI evidence**, select a completed approved `android_capture` task. Use an exact Java class descriptor, method name and full JNI descriptor; optionally select PID and loader identity. Opening/refreshing/querying only reads existing evidence and never submits another worker job.

The query selects the receipt path already bound to that completed plan, verifies the stored filename/hash, rechecks the existing signed Ed25519 envelope against the current pinned worker key, and binds worker identity, request hash, APK SHA-256, nonce and device observation to the approved capture. Arbitrary imported JSON, mutated receipt bytes, stale/changed pinned keys, another request's receipt and missing captures are rejected. Verification currently requires the configured worker identity/key/credential settings, but querying does not contact the worker. Changing/removing that configuration can block old receipt verification; no fallback trust is invented.

The existing signed `RegisterNatives` collector's observations are **operator reports, not hardware attestation**. Multiple PID/loader observations stay ambiguous. Class-loader identity hashes are not globally unique and absence of observed registrations is not absence of JNI activity.

If a registration references a captured native disk module, its approved output file must match the signed SHA-256/size. The result reports ELF ABI/build-ID metadata. That establishes only captured-disk identity, not the loaded memory bytes. Frida module-relative offsets are not automatically equivalent to ELF virtual addresses. `confirmRelativeAddressIsElfVA: true` is an explicit operator coordinate assertion; only a unique existing executable function symbol at that exact entry may then be proposed. Stripped/aliased symbols stay unresolved. The candidate is not executed, fed automatically to a decompiler, or presented as verified runtime equivalence.

## Validation and remaining work

Owned protocol fixtures cover signature/request/hash rejection, exact registration filtering, ambiguity, root consent, no-launch capture, private report reading, path/metadata/serial bounds and stale-workspace UI responses. The signed collector was already present; these fixtures are not real Android execution.

No physical KSUN device, real Frida root authorization, device-specific toybox command corpus or actual crash reproduction was available in this agent environment. Persistent IDA/Ghidra worker pools and automatic transactional project/type edits are still not implemented by this phase. These remain distinct work items, not capabilities implied by a successful build.

## Subsequent worker integration

Managed selected-function Ghidra/IDA worker adapters and bounded process reuse are now implemented; see `docs/MANAGED_ENGINE_WORKERS.md`. This does not replace licensed-engine validation. Transactional type edits and real-device validation remain outstanding. Earlier remaining-work notes describe the initial device/JNI phase.
