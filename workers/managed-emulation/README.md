# Managed-local inert transport foundation — development only

This source is **not** the Emulation Framework Pack, its installer, a VM
lifecycle broker, a distributable guest image, or a containment certificate.
It changes no installed application route, engine readiness, existing worker
transport, WSL distribution, Hyper-V registration, VM, or host settings.
There are intentionally no user setup instructions here.

## Implemented slice

- A Rust host probe uses Windows `AF_HYPERV` only. The Linux guest probe uses
  `AF_VSOCK` only. There is no IP, DNS, TCP, HTTP or shell fallback.
- The fixed Linux VSOCK port is 35555. Its Windows service GUID is
  `00008ae3-facb-11e6-bd58-64006a7986d3`, following Microsoft's Linux VSOCK
  template. Address encoding is tested; it is not a VM ownership check.
- Only an authenticated `owned-probe` challenge is accepted. A response binds
  the challenge to the fixed inert-fixture digest and explicitly retains
  `vmIsolation: not-attested` and `engineReadiness: not-tested`.
- Frames have a 4-byte big-endian size, a strict JSON envelope, an exact boot
  session and direction, hex payload bytes, and HMAC-SHA256. The MAC domain is
  the exact protocol plus NUL, followed by session bytes, direction byte, and
  the exact payload bytes. Payloads are at most 1024 bytes; envelopes at most
  4096. Both peers reject extra/duplicate fields, altered identities and MACs.
- The host reads a bounded closed private stdin pipe, never argv/environment
  credentials. It rejects wildcard/parent/loopback VM addresses and uses one
  ten-second connection/I/O budget. A separate 15-second whole-process watchdog
  bounds blocked private stdin EOF and output delivery; timeout hard-exits 124 without
  touching a possibly blocked diagnostic pipe or running buffered-I/O cleanup
  handlers (`_exit` on Unix, `TerminateProcess` on Windows). This terminates **only the probe**,
  not the VM; its parent **must** still supervise the VM and record unresolved
  termination/recovery rather than treating helper exit as success.
  Private input/key buffers are cleared
  best-effort on ordinary return; watchdog termination bypasses destructors.
  This is not a memory-forensics guarantee.
- The guest accepts one connection from host CID 2 and exits after one probe.
  Accept plus I/O has an absolute 30-second maximum, further bounded by the
  boot credential's expiry. It requires a root-owned, mode-0600, non-linked
  regular boot record at the fixed private `/run/cline-managed-probe/boot.json`.
  The guest pins `/`, `/run` and its private directory using descriptor-relative
  no-follow opens. All parents must be root-owned and not group/world-writable;
  the private directory must be mode 0700. The record must have one hard link
  and unchanged identity/ownership/mode/size/timestamps across its bounded read.
- No target bytes, arbitrary paths, scripts, commands, engine imports, file
  transfers, subprocess launches or network access operations are implemented.
  Imports perform no probe. Errors never echo private input or raw OS errors.

## Lifecycle recovery core (development only)

`host/src/lifecycle.rs` now supplies a strict, bounded, authenticated lifecycle
journal reducer. This is **not** the privileged broker, a persistence backend,
a VM factory, or a certificate that an observation actually occurred.

- Each entry binds the installation/job, exact VM ID, image digest and original
  host-boot identity, sequence, previous MAC and typed event. HMAC uses a separate
  lifecycle domain. Unknown/duplicate fields, unsupported versions, mutations,
  reordering, foreign identities and invalid transitions fail closed.
- Restore requires an **independently retained trusted checkpoint**. A valid
  prefix plus its own earlier checkpoint is not proof of freshness. The future
  broker must protect and transactionally retain the journal and checkpoint;
  reading the checkpoint from the same untrusted bytes defeats rollback checks.
- A returned candidate is immutable with respect to the previous journal. The
  broker must durably commit it **before** the corresponding effect. No host
  operation is implemented or authorized by appending an event.
- Every nonterminal reopen requires explicit recovery, even if the last record
  said stopped or removal requested. Recovery permits only a stop/inspect path,
  not automatic creation, boot, target execution, approval or replay. Removal
  requires a new exact-VM stop observation after a stop intent. A reboot, helper
  exit or missing PID does not synthesize that observation.
- The fixed inert result is revalidated against the active challenge. It cannot
  promote isolation or engine readiness. Recording it does not independently
  prove transport authentication: the actual trusted probe/broker must verify
  the real exchange first, not construct the public fixture response.
- The single-job state machine permits one boot only and retains public boot
  session/challenge identifiers, never boot keys, target bytes or shell commands.
  Cross-job freshness, entropy and key provisioning remain broker requirements.
  The original boot identity is historical binding, not current boot attestation.
- Limits are 128 entries and 64 KiB. Exhaustion/mismatch remains unresolved and
  blocks further transitions; old events/checkpoints are never silently pruned
  to make a job look complete. Durable repair/compaction is not implemented.

The initial exact VM identity must come from a trusted VM factory/ownership
record. This reducer does not implement crash-safe VM creation/discovery or
establish ownership from a supplied GUID. Its event observations must come from
fresh independently checked Hyper-V state, not client assertions. Nothing is
connected to Setup Center or changes the installed application's readiness.

## Development guest-image path

`image/` now contains a separate CI-only diskless ISO builder and fixed guest
bootstrap. See `image/README.md` for exact input locks, parser and module limits,
BIOS/UEFI cold-boot validation and unfinished publication/Hyper-V acceptance.
This is not a distributable four-engine image or an installed Setup Center pack.
The existing mandatory real-Hyper-V/lifecycle/integration gates below remain.

## Mandatory unfinished lifecycle integration

Do **not** expose this developer probe as a ready Setup Center function.

The lifecycle broker still has to:

1. Distribute a reviewed immutable image with Linux Hyper-V VSOCK support.
2. Create and verify an app-owned VM with no network adapter/host shares.
3. Protect owner/VM/image records and provision a fresh per-boot session/key
   privately. The current helper's supplied VM ID does **not** prove ownership.
4. Register only the reviewed Hyper-V service with explicit elevation, without
   weakening host-wide Hyper-V socket policy or touching unrelated services.
5. Enforce parent process deadlines, cancellation, verified VM termination,
   no replay, disposable job state and recovery after helper/app/host failure.
6. Reject readiness until the actual image, transport, lifecycle and cleanup
   pass owned execution on a representative Windows Hyper-V host.
7. Add separate target admission/execution/approval and per-engine runtime
   identities. The inert probe does not grant permission to execute targets.

No persistent replay ledger exists in this probe. Its one-shot process and
fresh boot session/key are necessary assumptions, not a replacement for the
future broker's lifecycle/no-replay enforcement.
An authenticated response proves possession of the boot key and agreement on
the inert protocol, not the guest image's integrity, safe containment, or that a
particular runtime binary executed. Those require separate host lifecycle and
image-validation evidence.

## Development validation

From the repository root:

```sh
python3 -B workers/managed-emulation/probe_protocol_test.py
cargo +1.85.1 test --locked --manifest-path workers/managed-emulation/host/Cargo.toml
cargo +1.85.1 fmt --manifest-path workers/managed-emulation/host/Cargo.toml -- --check
```

Public fixture vectors contain public test credentials only. Python descriptor
fixtures exercise real no-follow/FIFO/hard-link behavior with synthesized root
ownership (unprivileged CI is not root/VM attestation). Journal tests establish
state-machine/authentication behavior, not actual durable recovery. Python socketpair
and native codec/process tests establish protocol behavior, **not** Hyper-V
communication, Windows 10 compatibility, guest isolation or engine readiness.
The dedicated CI workflow builds/tests the native helper on Linux and Windows;
it deliberately does not claim a VM or framework was installed.

Reference:
https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/make-integration-service