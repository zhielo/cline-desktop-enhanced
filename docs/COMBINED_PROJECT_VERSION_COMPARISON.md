# Combined project version comparison

Use `compare_versions` with an explicit `version_comparison` object to combine the existing complete bounded project-file inventory with the existing explicit JS/TS API signature engine. This is read-only partial evidence, not an approval, build, vulnerability verdict or behavioral equivalence test.

```json
{
  "operation": "compare_versions",
  "target": "/authorized/versions/before",
  "compare_target": "/authorized/versions/after",
  "version_comparison": {"kind": "project", "max_results": 100},
  "timeout_ms": 120000
}
```

The two roots must be distinct real sibling directories under the same authorized parent. No synthetic manifest file is written: the existing inventory-request schema confines both roots. All regular-file bytes and names including dotfiles participate in inventory SHA256 fingerprints. Links, hard-linked files, aliases, special files, overlapping roots, nonportable names, mutation and exceeded hard budgets fail closed. Four complete inventory passes bracket source comparison. This detects ordinary mutations, not hostile-filesystem races or an atomic snapshot.

One report includes:
- Exact before/after inventory hashes, file counts and total changed-file count.
- Added/removed/changed relative paths with before/after SHA256 hashes. Path-based categories group source, manifest, resources/assets, Android code, native/binary and other changes; labels do not authenticate file formats.
- Explicit JS/TS API syntax additions, removals and signature changes with source paths, lines and hashes. Project API keys always use relative paths, even when one side contains only one source file; adding an unrelated file must not manufacture removals.
- Source artifact fingerprints, detail truncation flags, budgets, exclusions and limitations. No generated prose substitutes for code evidence.

Inventory limits reuse the existing project reviewer: 4096 entries per root, depth 16, 16 MiB/file and 64 MiB combined bytes per pass. More than 256 changed files blocks the combined report before API processing; narrow the roots rather than treating a truncated allowlist as approval. `max_results` is 1–200. Returned change and source-artifact details each have a 48 KiB budget. API rows cap at 50 and its detail envelope at 128 KiB; larger API detail is omitted with a fingerprint. The combined report is capped at 256 KiB. Total changed-file/category counts are never inferred from the truncated displayed detail.

API analysis separately scans at most 128 UTF-8 JS/TS files, 1 MiB/file, 8 MiB/root and depth 8, excluding node_modules, .git, dist, build and .cline. Those exclusions do not exclude files from the byte inventory. Empty source sets are supported, including removal of the last exported API. Explicit declaration syntax is not inferred type compatibility, resolved reexports, complete accessibility, ABI stability or a breaking-change determination. Function-body-only changes do not alter a declared callable signature.

No resource-table/manifest semantic interpretation, DEX/native instruction comparison, rename inference, signing, installation, runtime execution, downloads or writes occur. Empty directories, metadata, ACLs and alternate streams remain outside the inventory. Unchanged hashes are byte evidence, not provenance or runtime compatibility.

The desktop template presents project mode before exact-request approval. Remove `version_comparison` to use unchanged legacy APK ZIP-entry metadata or fixed-offset file-byte comparison. Project mode rejects unrelated options and advanced overrides. Runtime/Hybrid approval is never enabled by Static Analysis.

This extends one remaining partial recommendation; it does not declare the original 55-command program complete. Tests and installed Windows acceptance cover combined categories/API, unchanged originals, total counts and display caps.
