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
  ten-second connection/I/O budget. Its parent **must** supervise the entire
  process, including stdin delivery. Private input/key buffers are cleared
  best-effort; this is not a memory-forensics guarantee.
- The guest accepts one connection from host CID 2 and exits after one probe.
  Accept plus I/O has an absolute 30-second maximum, further bounded by the
  boot credential's expiry. It requires a root-owned, mode-0600, non-linked
  regular boot record at the fixed private `/run/cline-managed-probe/boot.json`.
  The image must protect that record's parent directories too.
- No target bytes, arbitrary paths, scripts, commands, engine imports, file
  transfers, subprocess launches or network access operations are implemented.
  Imports perform no probe. Errors never echo private input or raw OS errors.

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

Public fixture vectors contain public test credentials only. Python socketpair
and native codec/process tests establish protocol behavior, **not** Hyper-V
communication, Windows 10 compatibility, guest isolation or engine readiness.
The dedicated CI workflow builds/tests the native helper on Linux and Windows;
it deliberately does not claim a VM or framework was installed.

Reference:
https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/make-integration-service