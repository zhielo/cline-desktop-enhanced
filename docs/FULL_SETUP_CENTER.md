# Full capability setup

The Windows installer contains an integrity-checked core pack, full pack, separate angr pack and official Android connectivity tools. Use **Settings → Setup Center → Read bundled platform-tools notices → Install all supported components**. Review the confirmation, wait for the actual owned fixtures, then choose **Apply setup to idle backend** when no jobs are active. It refuses busy/unknown activity and never forces running jobs. No user Python, pip, command scripts or environment setup is needed.

## What full readiness proves

LIEF, Capstone, Z3, Triton (triton-library), QBinDiff, Androguard, Miasm, Unicorn, angr, QBDI and cryptography each execute a fixed owned test. A version inventory is not readiness. Records are bound to the selected runtime and embedded worker code, and displayed as last tested—not universal target support. Angr uses a separate private interpreter because its solver dependency conflicts with the main pack. Engine imports happen on explicit tests/tool calls, not on opening settings.

Unicorn emulates bounded x86-64 bytes in private mapped memory, with instruction/time/range limits and blocked SYSCALL. Angr performs bounded static VEX lifting, not arbitrary target execution or unbounded search. The local QBDI test instruments only a fixed owned return-42 function; tracing target-native code remains behind the approved signed isolated-worker flow.

## External prerequisites

Choose an authorized installed IDA folder and save it, then explicitly authorize the fixed owned x86-64 decompilation acceptance. This cannot install a commercial license or prove every processor's Hex-Rays support. Choose the exact Android serial/type, save and run read-only connectivity acceptance after authorizing USB debugging on your device. Root/Frida/capture permissions remain separate. Supply only the isolated worker's HTTPS root URL and Ed25519 PUBLIC key; capability probing rechecks signatures and job submission rechecks identity. The desktop does not provision outer VM isolation, phone root or automatic-update signing keys.

## Repair and rollback

Repair uses verified installed resources offline and immutable digest-versioned private directories. Rollback selects core without deleting full packs, session history or project data; restart a pre-existing shared Hub separately. No running job is killed. This is runtime-pack rollback, not installer/database migration rollback. Old private versions consume disk until a separately reviewed cleanup policy is implemented.

## Acceptance

Windows packaging must execute every shipped engine fixture and pass the installed UI journey: full-pack activation, all eleven actual engine receipts, persisted selection after restart, saved-session reconnect after exact fixture Hub termination and core rollback. Linux source tests do not establish final Windows installer success. Performance captures candidate startup samples only; no measured speedup claim or machine-wide OS quota is made.
