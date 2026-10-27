# Setup maturity: remaining delivery and acceptance work

This is a scope/acceptance record, not a claim that the items below are implemented. The output-directory repair and read-only framework directory do not complete engine provisioning or architecture expansion.

## Confirmed repair in this change

- IDA/Ghidra owned Setup Center projects previously lived under the durable data directory, outside the default reverse-engineering output allowlist. They now use private canonical OS temporary directories; durable receipts are unchanged.
- Real executor tests verify the shared output guard accepts these directories without external-output acknowledgement. Mocked engine acceptance tests also assert correct paths. The existing pinned real-Ghidra CI job now also invokes the production Setup Center function on Linux and Windows with its durable data directory outside OS temp. That acceptance is pending CI, not claimed as a local real-engine pass. This is not an installed Windows UI run or an IDA engine run.
- The existing backend capability catalog is rendered in Setup Center. Separate cards expose supported scope and configuration-only state for all four optional frameworks without networking, secret projection or inferred readiness.

## 1. App-managed isolated engines — high priority, NOT IMPLEMENTED

Deliver actual Install / Repair / Test / Remove for Qiling, unidbg, rnidbg and Speakeasy on supported Windows hosts, including app-managed Python/JDK/native dependencies. Do not require the user to provision an external worker manually. This must replace the current provisioning gap, not hide it behind a button.

Before declaring installation ready:

1. Select and implement a real Windows-managed containment backend. Keep guest execution separate from the host and avoid host shares, network access and native fallbacks. Emulator libraries and process limits are not VM isolation.
2. Produce versioned immutable artifacts with reviewed provenance, exact file manifests, redistribution notices, bounded extraction and integrity verification before activation. Speakeasy and Qiling have incompatible Unicorn dependency versions and need separate runtimes.
3. Add atomic activation, repair, rollback, quota enforcement and retained known-good versions. Removal must refuse live/unknown jobs and preserve user projects and evidence.
4. Execute real owned fixtures using the same installed app route the user will click. Test cancellation, interrupted download/activation, offline operation, corrupt artifact rejection, cleanup and restart. UI must show missing prerequisites and progress honestly.
5. Preserve existing request/artifact hashes, one-use approval, bounded execution and signed transport requirements for remote workers. Local managed execution needs its own truthful identity/containment contract, not a forged remote-vm claim.

## 2. Qiling static architecture coverage — IMPLEMENTED, FINAL CI REQUIRED

Qiling v2 adds little-endian static Linux x86-64, ARM32 and ARM64 ELF entry. Architecture-specific dispatch and sealed fixtures are implemented; local pinned-engine owned tests passed. Exact-current-revision Clang-built CI acceptance remains required. This is not general upstream Qiling parity.

SDK admission, profile identity, signed manifest coverage, architecture-specific syscall numbers, owned success/forbidden-syscall fixtures, startup capability tests and UI now agree. Existing Unicorn, unidbg, rnidbg and Speakeasy routes remain. Dynamic ELF/rootfs/library/TLS and additional architectures remain explicitly unsupported. Run the existing real-engine CI matrix before merging; startup fixtures must cover every advertised architecture.

## 3. Interrupted setup recovery — NOT IMPLEMENTED

Current admission locks deliberately remain held if termination is unconfirmed. A parent PID disappearing is not proof that its children exited. Add an explicit trusted recovery flow backed by exact process birth identities, supervised tree termination receipts or a verified OS boot-identity change. Never clear the lease merely because a request timed out. Reject PID reuse and concurrent recovery. Test crash/restart and orphaned-child cases on Windows.

## 4. Model exposure inventory — PARTIAL

The directory shows registered routes, not the current model's actual tool set. Add session-scoped evidence combining enabled tool definitions, attached client capabilities, mode, installed runtime, fresh owned-test identity and per-request permission state. Expose both to AI discovery and the UI through one read-only projection. Tests must cover disabled tools, headless/remote sessions, Off/Static/Runtime/Hybrid modes, stale identities and forbidden approvals. Do not contact providers or run tests while reading inventory.

## 5. Installed acceptance and performance — OUTSTANDING

The actual Ghidra Setup Center function is now wired into pinned Linux/Windows real-engine CI; require its successful receipt. Add installed UI/command coverage and an actual optional IDA owned-test run, not only direct scripts/mocks. An unavailable optional engine stays untested, not passed; vendor-license preflight/self-attestation must not become an extra gate. Report actual launch/plugin errors.

For the four managed emulators, collect exact-source installed Windows end-to-end evidence before claiming Install → Test → Use. Measure cold start, peak memory, setup duration, UI responsiveness, failure recovery and cancellation against a recorded baseline before claiming optimization. Do not weaken existing release gates or infer arbitrary target compatibility from owned fixture tests.

## Ghidra acceptance matrix follow-through

Implemented: independent owned x86-64 / ARM32 / ARM64 selected-function receipts; actual imported language checks; selected/all controls with retained selection; bounded processor/decompiler identity invalidation; shared read-only desktop discovery/status. All three real local Ghidra 12.1.4 / Temurin 21 tests passed. Existing receipt schema is intentionally stale until retested. Linux/Windows CI and a new installed Windows UI stage are required before merge; installed validation is not yet claimed here. This narrows the Ghidra part of item 5; optional real IDA testing and managed-emulator installation/performance remain outstanding.
