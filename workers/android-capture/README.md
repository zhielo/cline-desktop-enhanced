# Isolated Android capture worker

This is a separate Linux controller for **apps you own or are authorized to assess**, not a desktop-host executor, VM provisioner or a bypass for app/service access controls. The desktop never accepts job-supplied scripts or shell commands.

## Operational prerequisites

- Dedicated disposable controller VM and disposable Android emulator/device, reset to a clean snapshot before every approved job. A compromised target must not reach the desktop, credentials, other devices or LAN.
- Operator-enforced outbound network denial at the controller AND Android environment, including DNS, IPv6, proxy, bridge and ADB paths. Do not infer isolation from the signed manifest.
- Explicit Android device serial `CLINE_ANDROID_DEVICE_SERIAL`, trusted fixed absolute paths `CLINE_ANDROID_ADB` and `CLINE_ANDROID_APKANALYZER` (Android SDK package-name inspection), a compatible Frida server on that disposable Android target.
- Fixed executable hooks `CLINE_ANDROID_ISOLATION_CHECK`, `CLINE_ANDROID_RESET`, `CLINE_ANDROID_CLEANUP`. The check must fail when isolation/target identity is wrong; reset/cleanup must restore the snapshot and remove samples. Hooks receive no job-provided commands. Their successful exit is an operator claim, NOT hardware attestation.
- Valid HTTPS certificate/key `CLINE_ANDROID_TLS_CERT`, `CLINE_ANDROID_TLS_KEY`; private Ed25519 PEM `CLINE_ANDROID_SIGNING_KEY`; protected local `CLINE_ANDROID_WORKER_DATA`; stable `CLINE_ANDROID_WORKER_ID`; random bearer `CLINE_ANDROID_WORKER_TOKEN` at least 32 characters. Keep secrets out of the repository and logs.

On the controller, install `requirements.txt` in a Python virtual environment and run `bun install --frozen-lockfile && bun run build` here. Only the pinned Frida native dependency is trusted to run its install script. The generated `agent.js` is local deployment output, never committed. Verify dependency licenses for your distribution.

Set `CLINE_ANDROID_ISOLATION_ACK=operator-enforced-disposable-android-and-denied-egress` only after configuring those controls. Run the virtual environment's Python `server.py`. Default listener is 127.0.0.1:8443; `CLINE_ANDROID_BIND`/`CLINE_ANDROID_PORT` can select a private interface. Expose it only over the configured TLS and a restricted network/firewall; never disable certificate validation.

The desktop process needs `CLINE_ANALYSIS_SANDBOX_WORKER` (HTTPS URL), `CLINE_ANALYSIS_SANDBOX_PUBLIC_KEY` (matching Ed25519 public PEM), and `CLINE_ANDROID_WORKER_TOKEN`. A credential manager/operator environment must provide these, not chat text. Existing QBDI worker configuration is separate: this server advertises Android capture only.

## Approval and recovery

In the workbench select an investigation, choose Android runtime capture, supply the APK and exact package, choose whether to retain plaintext DEX, and review upload/execution/capture-write permissions. An approved request binds the artifact hash, workspace, nonce, endpoint, worker ID, pinned key and budget. Captures are content-addressed in the approved workspace child; the exact signed receipt is saved alongside them. `.gitignore` reduces accidental commits, not unauthorized access; Windows ACLs/encrypted disks and secure retention are operator responsibilities.

One job runs at a time. A duplicate nonce with matching request returns retained evidence, never a new execution. A conflicting nonce, interrupted job, expired receipt or quota fails closed. Retrieval is GET-only, requires a previously approved task and does not upload the APK again. It does not retroactively erase the desktop task's timeout/interrupted status. Jobs retain results one hour; expired nonce tombstones remain to prevent replay (4096 total jobs before operator archival/replacement). Do not clear tombstones to retry an unknown execution: inspect the target and create a new, explicitly approved job.

## Coverage and validation boundaries

- Fixed Frida instrumentation observes available JNI RegisterNatives bindings (class/name/descriptor, absolute and module-relative address) and bounded standard DEX loaded through supported Java class loaders. Both in-memory and file-based Java loader observations are limited; the target must actually load the code during the window.
- Standard DEX 035–040 integrity checks precede publication. No compact DEX/v041, arbitrary decryption, key extraction, memory sweeps, packer/anti-debug bypass or universal devirtualization is promised.
- JNI descriptor matching across static evidence remains correlation, not runtime class-loader identity proof. Duplicate static matches are ambiguous. Native module paths/relative offsets are observations; this collector does not capture/hash the native disk image or prove loaded-image integrity. Module hashes remain unresolved unless supplied by a separately validated producer.
- Receipt signature proves the configured worker reported those bytes, not trustworthy target execution or isolation. Results stay **partial**, even when capture succeeds. Originals are never patched.
- `server.test.py` is an owned protocol fixture corpus (auth, identity, signature, idempotency, interruption, expiration, failure and bounded Linux subprocess collection). Bundle compilation is not live-device validation.

Before production use, separately record real device/emulator tests: wrong package refusal, reset/check/cleanup failure, actual denied egress, Java/native fixtures with known JNI offsets, file/in-memory loader capture, timeout/disconnect/retrieval, duplicate nonce/no replay, captured hashes and receipt signature, secure plaintext retention/deletion. No such live-device result is claimed by the source CI.

## Physical Android integration (current target)

Use a dedicated authorized physical test device, not a personal phone with sensitive accounts/data. Keep the controller in an isolated Linux VM with deliberate USB passthrough. The signed `targetKind: physical` identifies this adapter; `ephemeralSnapshots` refers to the controller isolation contract, NOT a phone snapshot. The controller VM and network isolation are still operator-provisioned.

Set `CLINE_ANDROID_PHYSICAL_POLICY_ACK=dedicated-authorized-device-with-operator-cleanup` only after reviewing your fixed lifecycle hooks. No rooting, flashing, factory reset, wipe or emulator creation command is generated by this integration. Reset/cleanup hooks must verify a clean baseline without silently destroying phone data. Runtime capture needs an already configured compatible Frida server/rooted test target; unrooted/Gadget deployment is not automated. The collector checks online ADB state, exact configured serial and emulator property, and refuses to replace an already installed package. ADB properties and serial matching are not hardware attestation.

### Native disk capture and loader scope

Native capture is a separate opt-in and requires the signed `android-native-capture` capability. Up to four package-scoped on-device .so files may be read, 2 MiB each within the combined 8 MiB budget. Shell metacharacters, parent traversal, other packages, system libraries and APK!/ZIP module paths are rejected. Bounded subprocess output/deadlines are mandatory. ELF header checks and disk hashes do not attest the loaded memory image or full structural validity. Existing static APK/native analysis remains available for unsupported paths.

JNI observations carry the approved capture session, PID, transient class handle and best-effort loader identity hash/bootstrap label. Hash collisions and transient handles remain possible; this is scoped correlation, never global class identity proof.

### Retention and explicit logical removal

A periodic 60-second maintenance sweep drops finished receipt payloads older than one hour and preserves nonce tombstones. Authenticated `DELETE /v1/jobs/<nonce>` requires the exact JSON object `{"confirmPlaintextRemoval":true}` and refuses running jobs. Its signed `cline-android-retention/v1` receipt claims worker-payload logical removal only, explicitly `physicalErasure: not-proven`; retrieval/replay remains blocked. It does NOT delete desktop captures, phone data, backups, snapshots or RAM copies. SQLite secure_delete is defense in depth, not guaranteed SSD erasure. Protect/encrypt storage and manage local capture retention independently.

### Operator controller setup helper

`setup-controller.py --directory /canonical/new/private/path --tls-cert /absolute/cert.pem --tls-key /absolute/key.pem` validates a no-write setup plan. Supply the previously documented trusted hooks, exact serial/worker ID, isolation acknowledgment and physical-policy acknowledgment in the operator environment. It requires matching existing TLS files and Bun 1.3.14. `--apply` checks operator isolation, creates a private pinned Python environment, builds fixed instrumentation, generates no-overwrite private signing/token files and writes a mode-0600 controller.env. It prints no credential values and does not start a server, app, device or VM. Actual bootstrap installation and device capture are not established by mocked plan tests; deployment still needs operator execution and real-device validation.

### KernelSU / KSUN rooted targets

KernelSU-family root is supported through a read-only `su -c id` preflight; root access is reported only when it returns uid 0. Review the shell's root authorization on your dedicated device. No KernelSU settings/modules, hiding, rooting or boot images are changed. Preflight bounds ADB output/deadlines, checks online authorization, exact serial, emulator property and supported ABI. Frida must connect/enumerate before installation. Root alone is not proof of compatible Frida server operation. The signed device summary hashes the configured serial rather than exposing it and explicitly does not claim hardware attestation. Native reads use fixed root `cat` only after strict package-path validation; no arbitrary root command is accepted.
