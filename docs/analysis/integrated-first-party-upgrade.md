# Integrated first-party analysis upgrade

This changes first-party capabilities; it does not incorporate REA code, add REA installation, or certify whole-product superiority. Keep the PR draft until the exact-head Windows jobs pass.

## Delivered scope and explicit boundaries

| Requested area | Implementation | What remains outside this patch's proof |
| --- | --- | --- |
| OS-isolated JavaScript | Windows x64 zero-capability AppContainer, verified before target resume; single-process job object denies child creation and bounds memory; private staging, fixed pinned helper/runtime, bounded controller-owned capture; independent single-use Execute plan and approval | Single-process standalone CommonJS only; child-process-dependent scenarios are unsupported. No Electron GUI/dependency loading, VM-grade filesystem secrecy or Linux fallback. OS/all-application-package-readable files may remain readable. Actual Windows CI must pass. |
| Native decompilation and relocation | Actual selected-function Ghidra C/signature/high-pcode direct/indirect candidate evidence; bounded Capstone register candidate propagation; independent Debug-approved Windows process-birth/module/address/RVA observation and actual 32-byte memory/file hashes | Candidate recovery is not observed call execution. Ambiguous/memory targets stay unknown. A module/RVA/32-byte observation does not prove whole-image relocation or semantic equivalence; no arbitrary guessed provider load bases. Existing configured decompiler required. |
| Preload and .NET semantics | Static profile 7: lexical immutable preload function aliases and awaited IPC, bounded richer signature grammar, checked bounded straight-line Int32 stack/locals/arguments expression model | Branches, calls, exception-bearing methods and unsupported IL stay partial/unknown. Not a full .NET interpreter or complete interprocedural analysis. Old immutable receipts remain readable and hashes unchanged. |
| Scenario reconciliation | Reviewed exact stdout SHA-256 and exit expectation, separately authorized artifact/request, kernel-verified execution and controller-owned observation; supported/contradicted/inconclusive output | Only standalone process-interface behavior is compared. Timeout/overflow cannot prove success; target text/provider declarations never become internal behavioral truth. Cross-domain semantics are not inferred from byte matches. |
| Installation and faults | Packaged pinned isolation resources in normal and analysis-runtime Tauri manifests; actual Windows AppContainer denial/cancellation/birth fixtures; existing NSIS installation hooks extended with fresh/upgrade/damaged-payload rollback/userdata retention | NSIS hook fixture is not whole-product database rollback or complete installed EXE acceptance. Windows jobs and full installer smoke tests remain merge gates, not simulated local passes. |
| REA comparison | Actual npm rea-agents 6.4.0 CLI versus production compiled profile-7 static worker, same owned bytes, alternating order, 3 repetitions, raw outputs and hashes | Static-only small feature-discovery corpus, not universal accuracy/false positives/native/managed/GUI/device/LLM comparison. Different shipped runtimes/internal memory budgets. No superiority established. |

## Approval and lifecycle

Chat analysis stays Off/Static/Runtime. Active execution is a distinct explicit action in the first-party workspace, not enabled merely by Runtime mode or Inspector/Debug permission. Prepare shows the exact request and required approvals. Editing the request or changing session, environment or mode invalidates preparation/pending approval. No automatic rerun. Execute and native Debug use distinct task kinds and one-use approvals; exact bytes/resources/process birth are rechecked.

AppContainer helper is built from the included C# source and the minimal compiled Bun entry. It never imports desktop settings/Hub APIs or inherits API-key environments. Its zero-capability lowbox token and job assignment are checked while suspended. Host-managed bounded stdout/stderr captures are not target-generated receipts. Cleanup failure discards success. Controller crashes do not promise instantaneous helper termination: the helper has its own bounded timeout, terminates its job and attempts private-stage/profile cleanup.

## Actual local evidence

- Real Ghidra 12.1.4 + Java 21 analyzed the owned ELF without executing it: selected-function pseudocode and known direct candidate; unresolved indirect memory/register target remained unknown. See `owned-ghidra-selected-function.json`.
- Real pinned LIEF 1.0.0 / Capstone 5.0.9 Python corpus: 38 passes, one Androguard-only exclusion. Not an Android runtime pass.
- C# compiled with .NET Framework 4.8 references and C# 5 language restrictions. Compilation is not AppContainer runtime proof.
- Required local validation and Windows workflow receipts must be read at their exact source revision; this document never upgrades platform exclusions into passes.

## REA benchmark

See `rea-static-benchmark-6.4.0.json` for run timings, check results, source/output/corpus digests and limits. Twenty-four completed runs: 4 corpora × 2 engines × 3 repetitions. Cline supported 9/12 declared static feature-discovery checks; REA supported 8/12. Median cold-process end-to-end times were approximately 667 ms and 3,589 ms respectively on this Linux host. Setup time excluded. Concurrent repository validation ran on the shared host; timings are descriptive, not an uncontended speed certification. These results are not a whole-product ranking.

Cline resolved the selected computed request endpoints where REA's static result did not; REA exposed a dedicated timer-family detection where Cline did not. Both lacked the benchmark's declared dedicated child-process/resource-family check. Timer detection is not full timer lifecycle proof. No inference from mere matching strings is used to award those family checks.

Reproduce using a separately downloaded/pinned npm package and the repository grader: `node scripts/benchmark-rea-static.mjs --cline-worker <absolute-worker> --rea-cli <absolute-package/scripts/rea.mjs> --out <evidence-directory>`. Compile the production worker with `bun build scripts/benchmark-first-party-entry.ts --compile --outfile <worker>`; use the grader's exact argument format and fixtures. No API key/LLM is needed for REA static commands. Never install target-controlled dependency scripts just to run this comparison.
