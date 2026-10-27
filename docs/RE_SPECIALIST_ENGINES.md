# Specialist reverse-engineering profiles

These are optional, narrow additions to the existing analysis tools. They do not replace the existing eleven-engine setup gate, install REA, remove vendor licensing, authorize target execution, or certify REA parity. All model-facing operations retain the existing analysis mode, workspace, approval and process supervision checks.

## What is implemented

| Profile | Route | Scope | Deliberate exclusions |
| --- | --- | --- | --- |
| angr | `reverse_engineer` → `advanced_analysis` → `angr_symbolic` | One selected raw AMD64 region, up to 64 KiB; one symbolic argument; bounded instruction steps and active states | No general PE/ELF loading, whole-program symbolic execution, arbitrary scripts, hooks, libraries or native verification |
| Joern | `reverse_engineer` → `advanced_analysis` → `joern_query` | One UTF-8 JavaScript or Java source file, up to 1 MiB; fixed call-site, identifier-reference and source/sink candidate queries | No model-supplied Scala, arbitrary queries, project imports, native target launch or complete data-flow claims |
| Speakeasy | Approved **direct runtime workbench**, `emulate_windows` | x86/x64 user-mode PE default entry, up to 16 MiB; signed bounded API-model evidence | Not a model-callable static operation; no arbitrary exports, scripts, drivers, shellcode, network mode or host mounts |
| Frida | Existing isolated Android capture | Read-only client/device protocol handshake before install/launch; failures remain explicit | Handshake does not attest the server version, root state, device ownership or complete app coverage |
| Qiling / unidbg / rnidbg | Read-only plan_emulation and separately approved optional isolated worker | Fixed ELF/JNI profiles; see [ADDITIVE_EMULATION.md](ADDITIVE_EMULATION.md) | No bundled OS rootfs, APK, custom JNI stubs or native fallback |

The earlier blanket Qiling deferral is superseded only by the narrow optional profiles in [ADDITIVE_EMULATION.md](ADDITIVE_EMULATION.md). This is not general Qiling/rootfs or Android parity.

## Setup and readiness

### angr

Use a separate Python environment. The tested profile is Python 3.13, angr 9.2.185, pycparser 2.22 and bitstring 4.3.1. Set `CLINE_ANGR_PYTHON` to its absolute interpreter path using trusted host configuration. Desktop installer bundling is not implied.

In Setup Center, **Test angr** runs a fixed owned byte fixture and verifies the expected model input (42). This receipt is historical owned-fixture evidence, not target compatibility. Changed configured interpreter paths, specialist code or runtime configuration invalidate the prior receipt. Historical receipts do not attest an unchanged interpreter binary at the same path; execution always retests the engine.

Example tool parameters (with an approved workspace file containing raw AMD64 bytes):

```json
{"operation":"advanced_analysis","target":"/approved/selected-amd64.bin","advanced_action":"angr_symbolic","advanced_options":{"symbolic":{"find":1048582,"avoid":[1048588],"register":"rdi","minimum":0,"maximum":255,"max_steps":128,"max_states":32}}}
```

The synthetic load base is 0x100000. Entry/find/avoid must refer to the selected region. Other registers start zero; no ABI, stack or library model is supplied. Found inputs are **model-specific candidates**. No active states, errors, escaped paths and exhausted budgets are inconclusive, not proof of unreachability.

### Joern

Only the reviewed **Linux** launcher path is enabled. Windows batch launch is blocked; do not interpret catalog visibility in a Windows installer as native Windows Joern readiness. A separate Linux application/runtime deployment is required for this profile; no new remote model route is added.

1. Acquire the official `joernio/joern` v4.0.662 `joern-cli-linux-x86_64.zip` and review a compatible JDK 25 installation, including its license and redistribution terms. The preparation script verifies the official archive SHA256 before extraction.
2. Run `python scripts/prepare-joern-runtime.py ARCHIVE JDK_HOME NEW_DESTINATION`. This copies the reviewed JDK, preserves executable parser bits and prints the runtime's complete content-manifest fingerprint. It does not download or execute either input.
3. Configure trusted host variables `CLINE_JOERN_HOME` and `CLINE_JOERN_MANIFEST_SHA256` from that output, plus the existing absolute `CLINE_RE_PYTHON` if needed. Do not accept runtime paths or fingerprints from model arguments.
4. Run **Test Joern** in Setup Center. A call-site query must find the owned fixture call. The runtime's exact inventory and file hashes are checked on every invocation, not just PATH presence.

Example:

```json
{"operation":"advanced_analysis","target":"/approved/input.js","advanced_action":"joern_query","advanced_options":{"joern":{"language":"javascript","query":"callers","selector":"readInput","input_basis":"source"}}}
```

Other fixed queries: `references` (exact identifier) and `source-sink` (exact source-call selector plus `sink` call selector). `callers` reports matching **call sites**, not a complete interprocedural caller graph. Mark decompiler-derived input `input_basis: "decompiler-output"`; its uncertainty is retained. Graph paths are candidate source relationships, not observed execution. Missing paths and unresolved calls remain unknown.

### Resource enforcement

The specialist child fails closed when its OS limit cannot be established. Linux enforces an 8 GiB **per-process virtual-address-space** limit, CPU deadline and bounded file/output sizes. This is not an RSS limit or aggregate process-tree memory guarantee. Windows angr uses a Job Object with a 2 GiB job commit limit and kill-on-close; real Windows CI acceptance is required. Joern has a 512 MiB Java heap per JVM, two fixed subprocess stages and an outer parent deadline; parser native processes also inherit Linux address-space limits. Resource limits are not security sandboxes.

The parent verifies the input hash, memory-boundary declaration and bounded protocol, and attaches its own request and worker-code hashes. An engine failure never becomes a successful setup or target result. Source graphs and symbolic findings preserve candidate/model semantics.

## Isolated Speakeasy service

**Provisioning is not automatic.** An administrator must supply a disposable, network-disabled Linux VM, no host shares or sensitive credentials, an external TLS endpoint reachable by the desktop, and enforced egress isolation. The service's acknowledgement and signed capability are operator assertions, not hardware/VM attestation. Native emulator dependencies are not a sandbox. Use owned fixtures until that deployment is independently verified.

Install `workers/re-analysis/requirements.txt` into a separate Python 3.13 environment. It pins the tested Linux dependency versions, including setuptools 80.9.0 for the Unicorn 1.x compatibility dependency. These version pins are not a wheel supply-chain/signature attestation.

Operator-only environment:

- `CLINE_RE_ISOLATED_WORKER=disposable-network-disabled`
- `CLINE_RE_WORKER_KEY_FILE`: private Ed25519 PEM file, restricted permissions
- `CLINE_RE_WORKER_TOKEN`: high-entropy secret (at least 32 characters)
- `CLINE_RE_WORKER_STATE`: private durable job-state directory
- Optional `CLINE_RE_WORKER_ID` and `CLINE_RE_WORKER_PORT` (default 8766)

Start `python workers/re-analysis/server.py`. It binds only loopback; the operator supplies TLS termination and request/connection limits. Only one upload/execution is accepted at a time. The server hashes its collector, Python identity and installed emulator runtime files. A changed runtime blocks execution until a reviewed restart/reconfiguration.

Desktop trusted configuration uses `CLINE_ANALYSIS_SANDBOX_WORKER`, `CLINE_ANALYSIS_SANDBOX_PUBLIC_KEY`, and secret `CLINE_ANALYSIS_SANDBOX_TOKEN`. Use the existing isolated-runtime workbench and choose **Speakeasy Windows emulation**. The approval binds operation, input hash, worker key/id, endpoint and runtime fingerprint. Upload and execution retain separate acknowledgements. There is no static/model execution bypass.

Every result is signed and bound to nonce, request, artifact, worker and runtime. Repeating a nonce retrieves retained output without replay; changed input with the same nonce is rejected. Restarted in-flight jobs remain interrupted. Cancellation requests terminate the collector process group and discard partial output; a transport cancellation alone does not prove remote cleanup. The independent worker deadline remains active. Retention is finite (one hour of result validity; 4096 nonce tombstones and a 32 MiB stored-result budget); operator maintenance must not delete live nonce state or recreate an old approval.

Reports are always **partial modeled behavior**, not observed native Windows behavior or complete coverage. Host licensing remains unchanged.

## Validation and release gates

- Contract tests reject unapproved actions/scripts, bad budgets, changed hashes, missing memory proof, stale runtime binding and unsupported platforms.
- Owned angr input-42, real Joern parse/query and real Speakeasy generated-PE fixtures exercise actual engines, not only mocked discovery.
- Existing consolidated desktop tests include the new core and runtime-client suites. Existing installer and release gates are retained.
- `specialist-engine-validation.yml` adds Linux/Windows angr, Linux Speakeasy and pinned Linux Joern acceptance. Windows installer and installed UI acceptance must pass on the exact PR head before merge.
- A live Frida Android deployment, operator VM/TLS/egress configuration and arbitrary user-target compatibility have **not** been validated by local fixture tests. Missing hardware/operator prerequisites remain blocked, never silently passed.
