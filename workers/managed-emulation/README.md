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
journal reducer. This reducer is **not** the privileged broker, a VM factory,
or a certificate that an observation actually occurred. The development persistence
adapter below stores it without implementing host effects.

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

## Durable recovery storage adapter (development only)

`host/src/store.rs` uses pinned rusqlite 0.40.2 with bundled SQLite. It writes
immutable content-addressed full journal snapshots and a compare-and-swap current
checkpoint into **separate databases in independent caller-protected directories**.
Snapshots commit first, then the trusted anchor commits; both use rollback journals,
`FULL` synchronization and bounded lock waits. State advances only after both commits.
The key is privately supplied in memory and is never persisted in either database.

- Open reads only the exact anchor-selected digest, verifies its bytes and the full
  lifecycle MAC chain, and fences every nonterminal journal for explicit recovery.
  It never scans for the highest sequence or promotes an orphan staged snapshot.
- Stale writers lose the anchor compare-and-swap. Invalid requests, failed or ambiguous
  commits fence the handle; reopening does not replay VM creation, boot or execution.
- New leaf directories and files are exclusively created. Retained state is not
  reused or deleted on failed creation. Symlink/reparse roots/files and linked
  sidecars are rejected; Unix additionally enforces private modes/single links.
- Fixed schemas, application/version IDs, integrity checks, 16 MiB database bounds,
  256 retained snapshots, 128 journal events and 64 KiB snapshots bound this adapter.
  Exhaustion remains unresolved. Repair/compaction is not implemented.
- **Root ACL/owner protection, ancestor protection, secure key provisioning and
  service identity are caller requirements, not supplied by this adapter.** Windows
  roots must be provisioned by the future privileged broker; inherited ACLs and
  hard-link ownership are not independently established here. Separate files do not
  detect a privileged owner rolling back both the anchor and snapshot stores. MACs
  do not replace a separately protected current checkpoint. No anti-rollback hardware
  or physical-power-loss guarantee is claimed.
- Four subprocess tests forcibly kill a real writer before/after each database
  commit, reopen hot journals, and require the old or new exact checkpoint plus
  recovery fencing. These are process-crash tests, not disk-failure, host-reboot,
  Hyper-V lifecycle, engine readiness or installer acceptance.

The adapter is **not connected to Setup Center or a privileged Hyper-V broker**.
Stored event observations remain claims until fresh exact-VM state is independently
verified. A committed stop intent is not a termination receipt.

## Native private boot-media provisioning (development only)

`host/src/boot_media.rs` now generates a fresh 256-bit key, 128-bit session and
256-bit challenge using OS entropy, with a bounded 180-second credential lifetime.
The native writer builds one fixed-size ISO9660 volume in process: only BOOT.JSON;1,
which the guest mounts as boot.json. No Python, Java, xorriso, external installer,
network endpoint, shell or user-provided template is needed by this writer.

- Boot material is not Debug/Clone/Serialize/Deserialize. Secret-bearing temporary
  buffers are zeroized on ordinary drop; this is best effort, not forensic erasure.
- Media is exclusively created as boot.iso under a caller-protected job directory,
  synced before success and rechecked for expiry. Retained/partial files are never
  overwritten, auto-reused or deleted on error. Unix modes are private; reparse/link
  roots are refused. Windows ACL/owner/ancestor protection still requires the broker.
- The same in-memory material writes bounded matching input through a private pipe
  to the native probe, including the host challenge. No keys go into argv/env/logs,
  model context, receipts or the durable lifecycle journal.
- OS entropy and byte/identity/private-mode/reuse/refusal tests run on native Linux
  and Windows. A separate real UEFI guest boot mounts native-generated media and
  must accept its exact record, remain unresolved without a host exchange, then
  power off. Earlier absent/expired/public-format fixture boots remain required.

The CI-only owned-boot-media-fixture binary produces no credentials on stdout or
stderr. Its media is ephemeral, never uploaded. It is NOT an installer, a privileged
service, VM ownership proof, cleanup authorization or a Setup Center capability.
The future broker must durably reserve each boot, protect roots/keys, supervise
operations, enforce no replay, attach only to the verified exact VM and remove media
only after verified detach/termination. No user WSL or host configuration changes.

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

The probe itself is not wired to the development persistence adapter. Its one-shot
process and fresh boot session/key are necessary assumptions, not a replacement
for the future broker's cross-job lifecycle/no-replay enforcement.
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
state-machine/authentication behavior; separate storage tests kill actual processes
at commit boundaries, not actual VMs or physical power. Python socketpair
and native codec/process tests establish protocol behavior, **not** Hyper-V
communication, Windows 10 compatibility, guest isolation or engine readiness.
The dedicated CI workflow builds/tests the native helper on Linux and Windows;
it deliberately does not claim a VM or framework was installed.

Reference:
https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/make-integration-service
## Separate owned-engine guest images (development only)

`engines/` builds separate Qiling, unidbg, rnidbg and Speakeasy runtime bundles
from the existing pinned worker requirements/adapters and checked-in owned
fixtures. Qiling and Speakeasy never share their incompatible Unicorn Python
environments; the existing desktop Unicorn and external-worker routes are unchanged.
The immutable Python and Rust base images are digest pinned. Debian build-tool/JDK
packages are not a fully pinned reproducible distribution: final runtime bytes,
links and fixture content are sealed in each bundle manifest; redistribution and
complete build-tool/source/license review remain required before publication.

Builders install/compile dependencies inside disposable containers, never execute
an emulator or fixture there, and export only a runtime image. Compilers, Maven,
package caches and pip are excluded from the final bundle. Guest tests use an
engine-specific venv, minimal Java 17 runtime for unidbg, the existing reviewed
rnidbg compatibility patch, and fixed shared-library closure. No arbitrary target,
script, hook, stub, APK, classpath, host share or HTTP worker is accepted.

The dedicated four-way CI constructs actual diskless guest images and boots each
under networkless QEMU/TCG with 2 GiB RAM. Before credentials are provisioned,
fixed owned scenarios must execute: Qiling all three existing profiles with
stdout/exit, fresh-state, syscall-refusal and instruction-budget checks; unidbg
ARM32/64 and experimental rnidbg ARM64 JNI return/refusal/budget/missing-export/
fresh-state checks; Speakeasy owned PE entry/GetTickCount/fresh-state and identity
refusal. Runtime bundle integrity is verified both before and after execution.
Counts, architectures and exact scope must match; imports alone never pass.

These are developer acceptance images, NOT installed Setup Center packs. Even a
passed owned scenario retains engineReadiness not-tested and VM isolation
not-attested. No guest runtime ISO is published. Hyper-V ownership/transport,
privileged lifecycle/recovery, reviewed distribution, per-request approval,
transactional setup and installed Windows 10 acceptance remain mandatory.

### Bounded complete engine inventory verification

The image builder checks every exported non-directory engine member against
the sealed inventory, including exact file lengths/digests and symbolic-link
targets. Extra files and malformed entry types fail before image construction.
The guest reads bounded regular files through no-follow/nonblocking descriptors,
checks allocation limits before reads and rejects changed metadata and special
files. Aggregate bytes are refused before the next content read. These checks
remain scoped to development-owned images; they do not implement installation,
VM ownership, broker filesystem protection or arbitrary-target containment.

Fixed owned guest child commands also have live 1-MiB stdout and 16-KiB stderr
limits, at most 4-KiB input, one monotonic 35-second command deadline and fresh
process-group cleanup. The leader is observed without reaping until cleanup,
so its group ID cannot be reused between observation and termination. This
stops owned background descendants even after a successful leader exit; it
is not proof that the host VM has stopped or that arbitrary targets are safe.

## Native Windows protected parent provisioning

`host/src/windows_roots.rs` supplies fixed-location SYSTEM-only root creation and
existing-root validation, not a running service, an installer or VM authority.
The public API accepts no client paths or identities. It rejects impersonation
and ordinary/admin process identities before accessing ProgramData. New roots
are exclusive and explicitly SYSTEM-owned; protected ACLs admit only SYSTEM and
built-in Administrators with full access. Handle-based ACL checks reject null,
inherited/unprotected, duplicate, missing or changed rights/principals. Held
non-reparse ancestor/root handles deny delete sharing and pin directory names.

All roots must be retained for the future operation lifetime and revalidated
before effects. Opening roots does not authenticate an installation, image,
caller or VM: protected ownership/key records and the actual service/factory
remain necessary. Administrators/SYSTEM are trusted; this does not prevent their
intentional state rollback or certify containment. No existing state is adopted
by initial creation, and failures leave partial state for explicit review.

Native Windows tests exercise owned ACLs and real junctions. The separate
`owned-system-acceptance` Cargo feature enables an unshipped CI-only executable.
A Windows CI step runs it as actual SYSTEM through a fresh bounded scheduled
task, checking exclusive public provisioning, revalidation, reopening and pinned
lifetime. Successful fixture cleanup removes only its newly created empty
directories; no recursive cleanup, user-PC installation or VM execution occurs.
The executable is not built by default, included in an installer, or exposed to
models. This scope is not Windows 10 installed Hyper-V acceptance.
