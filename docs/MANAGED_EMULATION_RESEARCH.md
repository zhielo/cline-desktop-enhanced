# Managed emulation: research-backed implementation decisions

This is engineering research and a delivery checklist, not installation,
containment, Windows 10 acceptance or framework-readiness evidence. Existing
owned guest tests and the native storage/boot guards remain separate gates.

## Findings from authoritative documentation

| Boundary | Verified upstream behavior | Implementation consequence |
| --- | --- | --- |
| Hyper-V transport | Microsoft documents Windows 10/Linux AF_HYPERV/AF_VSOCK, host service registration requiring administrator rights, and VM-ID plus Service-ID endpoint addressing. Linux ports map to `xxxxxxxx-facb-11e6-bd58-64006a7986d3`. | Use a fixed app service and exact owned VM endpoint; do not add a NIC, TCP/HTTPS worker, wildcard VM or host share as fallback. Service registration is not caller authentication. [1] |
| VM lifecycle | `DefineSystem` can return synchronous success 0 or asynchronous job-started 4096. It creates default devices even when resource settings are supplied. The resulting computer-system reference identifies the created VM. | Poll the exact returned job with a deadline; independently read back the realized VM/resources. Never count 4096 as completion or assume requested settings eliminate default devices. [2] |
| VM identity/settings | WMI identifies Generation 2 as `Microsoft:Hyper-V:SubType:2`; `VirtualSystemIdentifier` corresponds to the computer-system name. Startup/recovery/shutdown and automatic snapshots have explicit policies. | A generated reservation UUID is not evidence the provider created that ID. Prove actual provider identity binding before boot or cleanup; do not identify ownership by friendly name alone. Verify no auto-start/restart/snapshot/save-state and no unexpected devices. [3] |
| Local privileged IPC | Default named-pipe security grants Everyone and anonymous read access. Microsoft recommends a logon SID to exclude other sessions. | Use an explicit restrictive descriptor, exact local logon/process binding, bounded requests, anti-replay, separate approval and no generic shell/command/path operation. Do not rely on a pipe name or current username. [4] |
| Pipe namespace/network | `FILE_FLAG_FIRST_PIPE_INSTANCE` refuses an existing first instance; `PIPE_REJECT_REMOTE_CLIENTS` rejects remote clients. | Refuse pipe squatting; prohibit remote admission and bound instance/buffer counts. These flags do not themselves authorize a local caller. [5] |
| Qiling | Upstream is cross-architecture/cross-platform and uses Unicorn. Official setup warns Windows DLLs/registry are not bundled because of distribution restrictions. | Preserve desktop Unicorn, keep engine closures separate and advertise only implemented/tested profiles. Do not ship Microsoft rootfs assets or imply all upstream OS/architectures work in this app. Current app profile remains static Linux ELF x86-64/ARM32/ARM64. [6][7] |
| unidbg | Upstream supports ARM32/ARM64 JNI invocation, JavaVM/JNIEnv and multiple backends. Upstream explicitly describes educational/risk limitations. | Bundle a private pinned JRE/JAR/native closure, not a user Java/Maven install; retain exact backend/profile checks. Do not substitute floating master/SNAPSHOT for the pinned 0.9.9 closure. [8] |
| rnidbg | Upstream is an ARM64 Rust emulator; its build instructions require Rust 1.79+ and libfmt/Boost for dynarmic. | Keep the app's pinned reviewed Unicorn-based runner and compatibility patch; no dynarmic build requirements on the user's PC. Label the supported ARM64 profile experimental, not full Android or ARM32 parity. [9] |
| Speakeasy | Upstream models Windows APIs/runtime rather than supplying an actual Windows OS. The current upstream LICENSE.txt is MIT; dependency licenses still differ. | Bundle the pinned 1.5.11 environment privately and keep its Unicorn closure separate. Modeled output is not native Windows behavior. Review exact redistributed archives, native dependencies and notices; do not infer an entire closure's license from the root project. [10] |

## Security-model limits

The cited Hyper-V socket overview documents endpoint addressing/registration;
it does **not** document a per-process allowlist for ordinary VMMS-managed VMs.
Do not invent registry ACL values or transplant HCS-only settings into VMMS and
claim kernel enforcement. Application authentication, protected per-boot keys,
exact VM ownership and actual supported-host refusal tests remain mandatory.
HMAC authenticates possession of the provisioned key, not that an emulator's
modeled output is truthful. Production target runners must not inherit the
trusted guest supervisor's credentials or root-private key access.

No existing Ubuntu/WSL distribution should be repurposed or modified. All VM,
service, registry and disk changes must be app-owned, transactional and explicitly
consented inside Setup Center. UAC for an app-managed machine-level component is
different from requiring the user to install Python, Java or a remote worker.

## Delivery order and proof required

1. **Repair current evidence first.** Current-head real unidbg guest run
   `40782227286`, job `123146500649`, failed `JNI refusal/budget boundary`.
   The retained guest log does not identify the architecture/case/exit. Do not
   guess the cause, rerun until green, enlarge budgets or call the pack ready.
   Preserve this failure and add bounded exact-scenario diagnostics. Also reject
   unrelated OOM/signal/JVM failures as proof of missing-export refusal.
2. **Authenticate and scope the service.** Protected binary/configuration,
   narrow typed local IPC, exact caller identity, request budgets/deadlines,
   explicit operation approval and no arbitrary command execution.
3. **Implement exact-owned Hyper-V lifecycle.** Protected image/VM binding,
   Generation 2 diskless guest, read-back device/resource policy, native private
   boot media, authenticated exchange, cancellation, verified stop/removal and
   crash/reboot recovery with no replay. Missing evidence must retain state.
4. **Publish a reviewed installable pack.** Pin build inputs and actual resulting
   image bytes, package corresponding source/notices/licenses, establish trusted
   catalog/update identity and stage/verify atomically. Existing development
   manifests must stay noninstallable until this gate is met.
5. **Deliver one complete Setup Center flow.** Separate Emulation Framework Pack
   with Install/Test/Repair/Update/Remove and Install all participation. Private
   runtime dependencies and app-managed service/VM setup; no endpoint/key/JRE/
   Python/manual WSL shell setup. Show prerequisites, progress, cancellation,
   retained failures, freshness and profile-specific evidence accurately.
6. **Connect execution and capability discovery.** Shared exact installed/tested
   identities, local session/mode checks, per-request approval and typed engine
   selection. Registered tool names and a completed fixture are not authorization.
7. **Accept the installed product on Windows 10 Pro/Hyper-V.** Real cold boot,
   all advertised profiles, host/guest refusal boundaries, lifecycle/recovery,
   cleanup, update rollback, memory/startup budget and all existing release gates.
   QEMU/CI native storage tests do not replace this acceptance.

Merge only after the promised functional pack and these independent gates pass.
A successful legacy Windows installer build does not establish the managed pack.

## Primary sources

1. https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/make-integration-service
2. https://learn.microsoft.com/en-us/windows/win32/hyperv_v2/definesystem-msvm-virtualsystemmanagementservice
3. https://learn.microsoft.com/en-us/windows/win32/hyperv_v2/msvm-virtualsystemsettingdata
4. https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
5. https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew
6. https://docs.qiling.io/
7. https://docs.qiling.io/en/latest/install
8. https://github.com/zhkl0228/unidbg
9. https://github.com/fuqiuluo/rnidbg
10. https://github.com/mandiant/speakeasy (LICENSE.txt; review pinned release separately)
