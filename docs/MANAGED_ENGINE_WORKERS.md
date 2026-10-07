# Managed selected-function engine workers

## Opt-in workflow

In Analysis workbench choose Decompile and an installed Ghidra or licensed IDA/Hex-Rays engine. Use Targeted decompiler options JSON:

```json
{"function_selector":{"address":"0x1000"},"managed_worker":true,"confirm_managed_worker":true}
```

Replace the address with an exact entry address from this binary, or use one exact `symbol` instead. Prepare the immutable plan and review/acknowledge the separate `managed-persistent-engine-process` and `private-analysis-project-write` requirements. Opening or refreshing the workbench never launches a worker. The existing tool-call approval boundary still applies to agent tool invocations; the SDK additionally requires explicit acknowledgement in the structured request.

A later separately approved selected-function request with the same owning session, canonical target path/hash, engine command/config fingerprints, output root and CPU option can reuse the same native process and imported private project. Function selector is deliberately not part of the worker identity: selectors remain independently bound to random request IDs. Different inputs/owners/configuration never silently reuse a worker. The response reports the worker ID, PID and reuse flag.

## Lifecycle and limits

- At most two managed engine processes per owning SDK process; no silent capacity eviction or license acquisition/bypass. Installed engines and compatible plugins must already be available. IDA licensing errors are failures, not a reason to bypass licensing or fall back to another engine.
- One request at a time per worker; concurrent requests fail rather than queue or replay. Two cooperating processes also coordinate through the existing cross-process project lease, held until owned child exit is observed. A worker occupies its parent output-project lease; it imports into a fresh private child project instead of modifying an existing GUI database.
- 90-second idle timeout and 15-minute lifetime. Startup obeys the request deadline (up to the tool's configured bound); selected requests obey at most 60 seconds. Fixed engine adapters have their own finite idle/lifetime limits as well.
- Timeouts, protocol errors and cancellation terminate the owned process group on POSIX or request Windows process-tree termination. PID-based termination is never issued after the owned root exit has already been observed (to avoid acting on a reused PID). If child termination is not confirmed, the lease is retained and reuse is blocked. This is supervision/coordination, not an OS sandbox, an external-GUI writer lock or proof that arbitrary descendants are confined.
- Fixed read-only Java/Python adapters accept only base64-encoded exact function selectors. No supplied scripts, expression evaluation, debugger attachment, target execution, annotation mutation or database type edit is supported.
- Native engines may execute their installed loader/plugins while parsing a malicious binary. Use trusted installations and a separately provisioned isolation environment for hostile artifacts; private folders and resource/time budgets are not containment.
- A byte-verified input snapshot is imported; engine/config identity is checked immediately before new worker launch. Pseudocode is limited to 100,000 characters; mailbox responses to 1 MiB. Both child output pipes are drained, retaining a bounded redacted diagnostic tail on failure. Private projects are retained as analysis cache data, not automatically published or deleted.
- Windows batch-engine paths/arguments containing cmd.exe expansion or control characters (`&`, `|`, `<`, `>`, `^`, `%`, `!`, quote or newline) fail before process launch rather than rely on unsafe quoting. Ordinary spaced paths remain supported. This restriction applies to the batch launcher, not IDA executable arguments.
- Protocol responses require the owning nonce and exact request ID. Mailbox files are bounded regular non-link descendants of a canonical private directory and opened with handle/size identity checks. These are local integrity/coordination checks, not signatures or protection against privileged host tampering.
- Incomplete work is never automatically restarted or replayed. A subsequent explicitly approved user request may start fresh after confirmed worker exit; this is not recovery of the previous request. No process identity is reclaimed after owner loss.

## Validation and remaining work

Mandatory owned Node-process fixtures exercise live process reuse, coordination lifetime, capacity, cancellation, deadline, nonce/request mismatch, ambiguity/error, oversized output and unexpected exit. They are protocol/lifecycle tests, not IDA or Ghidra execution. Fixed adapter source-contract tests do not prove compatibility with every engine version. Real installed Ghidra and licensed IDA/Hex-Rays sessions remain operator validation requirements; inventory or a successful Windows installer build does not establish those capabilities.

Transactional annotation/prototype editing is not implemented in these workers. Do not describe this phase as applying every recommendation. That work needs engine-specific commit/rollback semantics and verified compatibility; particularly, IDA edits must not be called transactional without a tested rollback mechanism. Physical KSUN-device validation also remains outstanding.
