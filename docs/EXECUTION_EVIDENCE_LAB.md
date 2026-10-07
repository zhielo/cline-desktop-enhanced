# Integrated execution and evidence lab

## Execution

The local **Execution lab** tab prepares an immutable multi-stage JSON task, then requires individual acknowledgements and one expiring approval token. Every task has a unique operation UUID. Dependencies execute only after success; concurrency is capped at two. Shell stages serialize workspace writes against other stages managed by this service. Analysis output/project and debugger identities are resource keys. This is not a distributed/global resource scheduler.

Receipts are durable, revisioned, hash-checked SQLite records. Reusing a UUID with different content is rejected. Refresh/reconcile do not execute anything. Owner loss means **uncertain**, not success or permission to replay. Terminal exit must be observed; cancellation without confirmed termination remains uncertain. Retained backend results, journal events and optional private logs are bounded. Process output hashes cover collected redacted output, not an uncaptured original stream. Dropped bytes, incomplete drain and truncated logs/results remain visible. Timings describe observed stages, not a proven performance improvement.

Only reviewed host runtimes are accepted; scripts/commands can still mutate files, access the network or launch descendants. `trusted_host_work` is a declaration, **not a security boundary**. Unknown samples require the existing signed isolated worker, not a host-shell shortcut. Do not put credentials in task JSON or argv; common credential flags/assignments are rejected, but arbitrary embedded secrets cannot be recognized reliably. Stdin is not journaled; the launched program may echo it. Output redaction is defense in depth, not proof of absence of secrets.

Native Windows resource limits are opt-in: `native_job:true`, `memory_mib` 128–4096, `max_processes` 1–32. The fixed supervisor creates a child suspended, assigns it to a Job Object, then resumes it. Failure is fatal—no silent fallback. The wrapper itself is outside the job. This is resource/process containment, not filesystem/network sandboxing. Interactive native-job wrappers are blocked until validated; use the existing PTY/ConPTY terminal or noninteractive jobs. Linux hard memory/process limits require an isolated worker; logical timeout/output limits are not cgroups. Resize/stdin/cancellation reuse process-session controls.

Example stages support `backend: shell|static|debugger`, dependency IDs and explicit timeouts. Static stages permit fixed built-in operations, not arbitrary scripts. Target and comparison hashes, debugger PID start-token, and shell executable hash are bound before approval and revalidated. Revalidation cannot eliminate every filesystem/process race; it does not freeze the host OS.

## IDA/Ghidra and debugging

Existing persistent IDB/Ghidra reuse now has cross-process filesystem leases, executable/config/custom-script content fingerprints, and existing artifact/version/options checks. A crashed owner's lease is not stolen automatically. Inspect the recorded PID/owner and prove it is no longer active before manually removing a stale lease. External GUI writers do not participate; do not open the same project for writing concurrently.

Debugger launch is execution-control, not inspect-only. Launch/continue/step require explicit confirmation. Attach requests require a kernel process start-token, revalidated immediately before invocation. A token is not an OS-held process handle and cannot eliminate a final PID race. LLDB numeric addresses use start-address disassembly rather than a symbol-name option.

This integration does **not** implement permanent licensed IDA/Ghidra workers, automatic in-place project annotations or type edits. Existing approved headless adapters and exact function selection remain the supported path. Executable/config fingerprints do not cover every plugin/library in an installation. Do not claim engine compatibility from discovery alone: owned-fixture readiness is required.

## Evidence-first analysis and patch review

The planner inspects file magic and proposes bounded inventory/embedded-artifact/exact-selection stages; it never executes a task. A ZIP signature does not prove a valid APK. No guessed JNI registration, decryption key, stripped function boundary or overload. Supply exact verified selectors before deep analysis.

Android report import reads a bounded workspace file and attributes tombstone/ANR/thread evidence only with explicit package markers. Reported PCs, symbols/build IDs, lock waits and process-death lines are untrusted imported observations. They are not authenticated device capture, proven deadlocks, runtime JNI mappings or verified symbolication. No automatic root, debugger continue, installation or device mutation. The existing APK incident and signed-worker workflows remain the routes for separately approved live capture.

Patch review hashes original/candidate artifacts and records bounded changed-byte ranges, reproduction and regression criteria without changing/installing either file. Semantic correctness, successful reproduction and rollback are not inferred from a diff. Use the existing APK incident workflow for signature verification, explicit install/reproduction review and a separately approved rollback; code rollback does not undo data/schema migrations.

## Validation boundaries

New receipt, graph, cancellation, privacy, stale-UI, lease, report-scoping and patch-review fixtures run in mandatory regression gates. Windows-only fixtures exercise actual suspended Job Object launches, argv quoting and process-count enforcement, and run on the Windows installer runner; they are skipped on Linux rather than falsely marked verified. No physical KSUN device, proprietary IDA/Hex-Rays installation or full Ghidra compatibility corpus was available locally. Real-device ANR/tombstone capture, transactional project type editing, a persistent licensed-worker pool and target-specific runtime JNI evidence remain readiness-gated future work, not implemented or verified capabilities.
