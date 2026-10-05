# V5 offline Rizin pack checkpoint — not app-integrated

This source checkpoint preserves the standalone Python CLI and its 18 boundary tests. It does not change the app's native adapter, SDK actions, workbench, source-validation workflow or Windows installer. The last fully verified integrated implementation remains 6bede76d31062faef907d27ea526ec9ca721e7bb.

## Actually observed locally

- All 18 Python tests passed on Linux before the sandbox stopped: archive traversal/links/case collisions/expansion, private paths, explicit approvals, immutable state, cooperative foreign-lock preservation and rollback retention.
- The reviewed Linux Rizin 0.9.1 archive was copied, size- and SHA-checked, manually extracted into a canonical private root and activated after an actual version probe plus static four-byte fixture check returning [1,2,3,4]. The fixture was never executed.
- A subsequent CLI status call verified receipt, full installed-file inventory and hashes successfully. Import-time health is not a fresh execution probe, sandbox attestation or semantic proof.
- The actual Windows shared64 archive was downloaded, independently hashed and layout-inspected, not executed. Native Windows support remains unverified.

The successful import used archive SHA 9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf and local receipt SHA bdbab0a0ec40c6d1723671ac7a3c3e9e8483bf4a23cda8e11457bd26e24d6500. These observations are not committed CI evidence for this new checkpoint.

## Explicit host setup only

Use a trusted local Python interpreter, a canonical absolute private root and the exact provider archive listed by `python scripts/manage-re-toolpacks.py catalog`. The CLI has no networking. Import requires both `--confirm-install` and `--confirm-reviewed-tool-execution`. Status fully rehashes files; rollback requires `--confirm-install` and retains revisions. Only one version per platform is cataloged: initial rollback deactivates the pack rather than pretending to downgrade to an unlisted version. Foreign/stale locks are never automatically removed.

The CLI expects the exact upstream tagged license texts at docs/vendor/rizin-0.9.1/COPYING and COPYING.LESSER. Both hashes are pinned. License resource preservation is a checkpoint requirement, not blanket redistribution clearance. The archives themselves lacked COPYING/LICENSE-named entries. Per-component notices control. Engine binaries and Python are not installer-bundled.

## Limits and follow-up

- This CLI revision follows the actually tested importer. Its status helper may create an empty owner-private root when none exists; it is not presented as a read-only app action.
- POSIX owner/mode checks are implemented; Windows ACL setup is the operator's responsibility. Cooperative locks and hashes do not protect against privileged or non-cooperating host tampering. There is no VM containment claim.
- Interrupted publication can leave an inactive revision requiring operator review. No GC, repair UI, install cancellation UI or automatic reactivation is claimed.
- Full SDK managed resolution/status, workbench registration, complete catalog/receipt validation hardening, source-preservation contracts, source-only CI import/health/recovery and Windows execution remain pending.
- Local SDK integration drafts were deliberately not committed after validation could not run. A lint failure was corrected, but an over-broad local text replacement introduced a Python syntax error in the newer draft. This checkpoint restores the earlier tested importer, not that broken draft. No assertions or CI gates were weakened.
- The execution sandbox returned sandbox_stopped before integrated tests could start. No new Windows installer, PR, merge or release was started.

V5 remains incomplete. Isolated tracing, Android/JNI recovery, advanced deobfuscation and the synchronized investigation UI remain outside this checkpoint.
