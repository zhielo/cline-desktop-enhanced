# Development inert guest image — not the Emulation Framework Pack

This builds an actual owned cold-boot image, not another readiness card. It is
**CI/developer-only** and does not install on the user's PC, expose an app route,
modify Hyper-V/WSL, install any of the four engines, or publish a release/image.
`image-manifest.json` always retains `installable: false`, isolation not attested,
engine readiness not tested and Hyper-V exchange not tested.

## Image and build boundaries

- Official CPython Debian/amd64 runtime is pinned by an immutable platform OCI
  digest, not a floating tag. CI exports a never-started networkless/read-only
  container. Its runtime files and library bytes are copied into the image;
  apt, pip, shells from that runtime and unrelated executables are omitted.
- Debian cloud kernel and static BusyBox inputs have exact HTTPS origin,
  version, byte count and SHA-256 locks. Package maintainer scripts never run.
  Debian data archives are parsed in memory, never extracted into the host.
  No special archive devices, duplicate paths, traversal, escaping links,
  unresolved/cyclic hardlinks or linked CPIO parents are accepted.
- The reviewed cloud kernel must advertise initramfs/GZIP, devtmpfs, Hyper-V,
  Hyper-V storage, VSOCK, Hyper-V VSOCK and ISO9660 support. Only explicit boot/
  VSOCK/storage modules and their transitive dependencies are retained; network
  and host-share modules are not added by dependency discovery.
- Root ownership, timestamps, archive order and gzip timestamps are normalized.
  CPIO has no setuid/setgid or group/world-writable contents. This does **not**
  claim whole-ISO reproducibility: the CI GRUB/xorriso/firmware toolchain is not
  fully locked. Artifact and input hashes identify actual build bytes.
- GRUB boots a diskless, RAM-backed development image through BIOS or UEFI.
  There is no guest login shell, network configuration, user startup script,
  auto-download, target execution or existing-distro reuse. The base image is
  read-only boot media; guest RAM is not a tamper-proof/immutable filesystem.
- PID 1 mounts kernel pseudo-filesystems and private tmpfs, loads the VSOCK core,
  and runs a public inert Python/kernel/codec self-check. The cold-boot marker
  explicitly does not certify Hyper-V communication or engine readiness.
- Without the second per-job CD media, it records missing credentials and powers
  off. No IP, host-share, KVP, manual-shell or native-host fallback exists.
- A future trusted broker/media writer may supply exactly `BOOT.JSON` on the
  second read-only ISO9660 media. The guest copies at most 1024 bytes into an
  exclusive root-private file, checks stability, validates exact protocol/key/
  session/expiry and only then starts the one-shot agent. No such broker/media
  writer is implemented here. Unknown or failed provisioning powers off without
  printing credential content. Expiry/replay/fresh-key enforcement still needs
  the trusted host lifecycle broker; image code cannot attest those properties.

## Validation and publication limits

`test_image.py` covers archive/parser/budget/link/CPIO/pinning/module-pruning and
actual exclusive private-copy behavior without executing downloaded programs.
The dedicated CI workflow builds the real ISO and boots it twice with QEMU/TCG,
no virtual NIC, no host shares and no hardware acceleration: BIOS and UEFI.
It requires the actual guest-kernel/Python check and absent-credential denial.
QEMU is itself an emulator; these checks are **not** Hyper-V acceptance,
isolation attestation, live authenticated host/guest exchange, real lifecycle
recovery, or four-framework installation. No binary ISO is uploaded/published;
only bounded boot logs, receipts and the scoped manifest are retained.

Before shipping: finish corresponding-source/notices/license packaging for all
redistributed runtime components; pin/review the distribution and signing
policy; build the protected native VM factory/media writer/broker; validate
real Windows 10 Hyper-V cold boot, exact VM ownership, fresh provisioning,
termination and recovery; add independently pinned engine environments and
Setup Center transactional Install/Test/Repair/Update/Remove. UEFI boot here
uses CI firmware, not Secure Boot attestation or a host-wide policy change.
