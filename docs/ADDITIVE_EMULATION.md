# Optional additive emulation profiles

These are deliberately bounded modeled-behavior adapters, not whole-app verification or a replacement for a native debugger. **Existing Unicorn instruction-block and Speakeasy PE routes remain intact.** No framework is auto-installed or bundled into the desktop installer.

| Engine | Exact supported profile | Explicit exclusions |
| --- | --- | --- |
| Qiling 1.4.6 / Unicorn 2.1.4 | Little-endian Linux x86-64 / ARM32 / ARM64 static ET_EXEC, entry execution, stdout/stderr write and exit only | PT_INTERP, dynamic ELF, TLS, libc, host filesystem, arbitrary syscalls/rootfs/hooks |
| unidbg 0.9.9 / Unicorn2 | Android ARM32/ARM64 ET_DYN with no DT_NEEDED dependencies; constructors + JNI_OnLoad, optionally one exact static JNI `(I)I` export | APK, external libraries, custom Java return stubs, target syscalls, general JNI/object/string dispatch |
| rnidbg `06251628767c577a0579ee8c2b834ed688393bfd` / upstream Unicorn fork | **Experimental**, Android ARM64, same narrow primitive JNI profile | ARM32, full Android/SDK assets, dynamic RegisterNatives selection, arbitrary hooks and native fallback |

A header-compatible file can still fail loading, initialization or its exact selected method. Unsupported dependencies stay blocked rather than fabricated. A primitive `scenarioCheck: passed` is only a matching explicit exit/return assertion; the receipt remains `partial`, with `outcome: unverified`. It does not certify native behavior, maliciousness, application correctness or framework parity.

## Planning and human execution

The AI tool is named **`reverse_engineer`**. Its `operation: "plan_emulation"` accepts `emulation_plan` with `engine`, `architecture`, typed `scenario`, `instruction_limit` (default 10,000, maximum 100,000), and the exact `expected_sha256`. The owning investigation equivalent accepts an immutable `artifactId` and `options`. Both are **read-only admission planners**: no engine import, worker connection, download, upload, target execution or approval. The result contains an unapproved next-request draft, its hash and explicit limitations.

In Analysis → Runtime, choose “Qiling / unidbg / rnidbg fixed profiles”. The same shared target is used from the static “Investigate modeled native behavior…” entry. Choose an engine explicitly, then architecture and typed scenario. Check engine readiness and prepare a new task. An attached **local Full Access owning session in Runtime or Hybrid** is mandatory. Static/Off and restricted permissions never authorize execution. Hybrid additionally requires intact owning-session static evidence for the **same artifact hash** and the question being investigated.

Approval binds artifact bytes, engine, architecture, scenario, budgets, owning session/mode, worker endpoint, Ed25519 key, runtime fingerprint and profile digest. Separate upload and authorized-execution acknowledgments remain required. Tokens are one-use. Changes require a new plan. Mode changes invalidate/cancel that session's pending or active additive-emulation tasks; cancellation requests worker process-group termination, not an automatic retry. Transport cancellation does not itself prove cleanup. The worker independently enforces its deadline. No engine switching, fallback, shell recipe or automatic replay is provided.

## Operator deployment (Linux worker only)

Provision a disposable **network-disabled VM**, no host shares or credentials, read-only runtime, a separately quota-limited writable job volume, TLS and a nonprivileged service identity. These instructions and signed manifests **do not create or attest VM isolation**. Never run unknown binaries on a developer host merely because an emulator is involved. The service binds loopback; expose only through the operator's authenticated TLS boundary. A worker is single-job with a bounded persistent nonce ledger. Preserve that ledger across service restarts so interrupted jobs cannot be replayed. A fresh process and empty guest state are used per job. Use disposable VM snapshots externally; the Python process is not a security sandbox.

Build using the checked-in scripts from a trusted checkout:

1. Create a separate Python 3.13 environment. Install `workers/emulation/requirements-transport.txt`. Qiling additionally requires the exact `requirements-qiling.txt` closure; do **not** change the Speakeasy environment, which uses a different Unicorn version.
2. `bash workers/emulation/build-fixtures.sh` builds only the checked-in owned fixtures (Clang/LLD required).
3. unidbg: Java 25 + Maven, `mvn -B -q -f workers/emulation/unidbg/pom.xml package dependency:copy-dependencies -DskipTests`. Its complete adapter dependency jar set is SHA256-checked against `dependencies.sha256`, including the bundled native backends. The selected backend is explicitly Unicorn2; no native/Dynarmic fallback.
4. rnidbg: Rust 1.85.1, Clang/LLD, CMake, OpenSSL/pkg-config; `bash workers/emulation/build-rnidbg.sh` downloads the exact SHA256-pinned source archive, applies only `upstream-compat.patch`, and builds the fixed adapter with `Cargo.lock` and no default backend features. No upstream sample APK/SDK library is loaded or distributed by the adapter.
5. With the **service's Python interpreter**, seal an inventory using `workers/emulation/runtime_inventory.py ENGINE OUTPUT --fixtures workers/emulation/fixtures/build` and appropriate `--java-home`, `--unidbg-build` or `--rnidbg-binary`. Keep inventory/runtime files operator-owned and read-only. Every inventoried file, the collector/profile, interpreter and dependencies are rehashed before execution; the collector rechecks after modeled execution. OS kernel, libc, hardware and VM isolation are outside this fingerprint's attestation scope. Rebuild/reseal deliberately after changes; old desktop approvals then become stale.
6. Generate your own worker Ed25519 key and strong bearer token outside the repository. Set `CLINE_RE_WORKER_KEY_FILE`, `CLINE_RE_WORKER_TOKEN`, `CLINE_RE_WORKER_STATE`, `CLINE_RE_WORKER_ID`, `CLINE_EMULATION_ENGINE`, `CLINE_EMULATION_INVENTORY`, `CLINE_RE_ISOLATED_WORKER=disposable-network-disabled` and a distinct `CLINE_RE_WORKER_PORT`. Start the selected environment's Python with `-I -B workers/emulation/server.py`. Startup refuses readiness unless sealed owned fixtures cover every advertised architecture and all actually pass. Qiling v2 requires a bounded stdout write and exit-7 fixture on all three architectures. Empty, missing, duplicate/extra-architecture or unsealed fixture coverage is not readiness.
7. On the desktop, configure each engine independently using `CLINE_EMULATION_QILING_ENDPOINT`, `_PUBLIC_KEY`, `_TOKEN`; substitute `UNIDBG` or `RNIDBG` for the other engines. Endpoints must be HTTPS origins. Existing `CLINE_ANALYSIS_SANDBOX_*` settings are never overwritten or borrowed. Restart the desktop after operator environment changes.

The worker admits at most 16 MiB input and 64 MiB declared ELF mappings. Per-job hard process address space is 8 GiB (includes the JVM/native runtime, **not** a 64 MiB hard guest RAM claim); output-file size is bounded at 64 MiB to accommodate verified native runtime extraction, file descriptors at 128, serialized evidence at 1 MiB, captured Qiling guest output at 64 KiB/200 trace rows. Parent-owned timeout is 1–120 seconds. The operator must additionally enforce VM CPU, aggregate disk and network limits. Guest output is hashed rather than presented as executable instructions.

## rnidbg feasibility findings and reviewed patches

The pinned Unicorn backend did not build or run its primitive fixture as received. The patch is narrow and explicit:

- Export the existing typed `UnicornArg` and backend for the adapter, rather than accepting arbitrary guest addresses/scripts.
- Enable ARM and AArch64 binding features without all default architectures, matching the upstream ARM64-register feature gate.
- Match the actual `SvcCallResult` variants in the Unicorn syscall handler (the Dynarmic path already used these), preserving error-stop behavior.
- Move the owning saved context rather than shallow-cloning a raw native context pointer; the original triggered a reproducible use-after-free SIGSEGV.
- Recognize an **exact Unicorn return PC at `until`** as task completion; otherwise a normal return incorrectly reentered the scheduler indefinitely.

The fixed adapter adds instruction-budget and SVC0-denial guards. None of these edits modify the desktop's existing Unicorn package/worker. Hundreds of upstream warnings and extensive unsafe internals remain reasons for the **experimental** label. The owned test proves only the documented slice, not that upstream rnidbg is production-mature.

## Licenses and distribution boundaries

Qiling and Unicorn have GPL-family licensing; unidbg and rnidbg have Apache-2.0 upstream licensing, with separately licensed native/transitive components. Do not infer all assets in an upstream archive share its top-level license. No OS rootfs, APK, proprietary SDK or unreviewed test assets are redistributed by this change. The desktop only transports requests to separately provisioned workers. If distributing a worker/runtime, independently review all pinned component notices, corresponding-source obligations, assets and deployment terms. Runtime hashing is not a vulnerability scan or license clearance.

## Acceptance scope

The additive-engine CI matrix builds each pinned real adapter, seals its runtime, and runs owned startup/JNI/ELF fixtures, signed job binding, no-replay, mismatched expectations, instruction budgets, real denied guest syscalls, unsupported JNI, fresh-state and process-group cancellation checks. Existing Speakeasy transport tests still run. SDK tests cover strict model schemas, no-execution planning and ELF admission; desktop tests cover independent registration, signature/profile/runtime/scenario binding, stale approvals, mode denial, cancellation and existing UI regressions.

Installed Windows acceptance adds read-only plans for all six supported engine/architecture pairs and proves **Static denial and unavailable-worker denial** in the installed binary. It does not claim an external Linux VM was installed on Windows or real-engine execution occurred there. A successful installer build is not an engine-readiness or target-behavior receipt.

## Qiling static multi-architecture profile v2

Qiling uses architecture-specific Linux syscall numbers: x86-64 write/exit/exit_group = 1/60/231, ARM32 = 4/1/248, ARM64 = 64/93/94. All other guest syscalls are stopped before dispatch. The runtime checks Qiling's detected architecture against the admitted ELF before running it. No rootfs, external libraries, OS file access or new native execution fallback is added.

The profile file/digest changes deliberately. Every worker environment must be explicitly resealed/restarted with the reviewed new profile; old fingerprints and approvals remain incompatible, including unchanged unidbg/rnidbg profiles sharing that file. A signed manifest must list exactly the reviewed architecture set without duplicates. Legacy x86-only manifests do not become ARM-ready by inference.

Clang/LLD CI builds separate static Linux entry/forbidden-syscall fixtures for all three architectures, distinct from Android JNI shared libraries. Real worker acceptance verifies startup, signed binding, exact captured-output hash and exit, denied syscalls, wrong expectations, instruction budgets, fresh state, no replay and process-group cancellation per architecture. These are modeled owned-fixture checks, not native behavior, installed Windows provisioning or VM-isolation attestation.
