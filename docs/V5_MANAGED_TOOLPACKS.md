# Offline managed Rizin packs

Explicit offline host installation accepts only reviewed Rizin 0.9.1 Linux-x64 or Windows-x64 archives. No automatic app download, arbitrary script or target execution. Use a trusted local Python interpreter and canonical absolute private root. Windows runtime/ACL validation remains pending; the Windows ZIP was only checksum/layout-inspected.

```sh
python scripts/manage-re-toolpacks.py catalog
python scripts/manage-re-toolpacks.py import --root /canonical/private/packs --pack-id rizin-0.9.1-linux-x64 --archive /absolute/rizin.tar.xz --confirm-install --confirm-reviewed-tool-execution
python scripts/manage-re-toolpacks.py status --root /canonical/private/packs
python scripts/manage-re-toolpacks.py rollback --root /canonical/private/packs --confirm-install
```

Set CLINE_RE_TOOLPACK_ROOT for managed native Rizin and crosscheck resolution. An explicitly configured external CLINE_RE_RIZIN takes precedence. Invalid managed state fails closed; no PATH fallback. managed_toolpacks is a read-only workbench inspection, never an installer or current execution probe. Full inventory/file hashing has a 1 GiB/30-second cooperative budget and adds I/O; import-time health is labeled as such. Python and binaries remain separate, not installer-bundled.

Initial rollback deactivates and retains the immutable revision. Only one version per platform is cataloged; no multi-version downgrade or repair/reactivation UI is claimed. Foreign/stale locks require operator review. Interrupted publication may leave an inactive revision. Local hashes/cooperative locks do not authenticate against privileged or non-cooperating tampering. Windows ACLs remain operator-owned. CLI status may create an empty private root; the SDK inspection does not.

Verbatim upstream GPL/LGPL texts are hash checked and retained; per-component terms govern redistribution. Local 18 Python and 14 SDK tests plus actual reviewed Linux import/health passed. Complete committed source/real-engine CI is required before declaring the integrated milestone verified. Other packs, isolated tracing, Android/JNI, advanced deobfuscation and investigation UI remain pending.
