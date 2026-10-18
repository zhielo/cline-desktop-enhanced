# Content-based artifact identification

`identify_artifact` is now a fixed read-only workflow, not an alias for `inspect`. Existing `inspect` stays unchanged for legacy structural triage. The workflow reuses the supervised fixed Python artifact-discovery worker; it never executes targets, extracts target members to disk, downloads engines, or grants approvals. The managed Python interpreter must already be available. Private worker and immutable investigation-index files remain existing host bookkeeping.

```json
{
  "operation": "identify_artifact",
  "target": "/absolute/authorized/misleading.exe",
  "artifact_discovery": { "max_depth": 3, "max_artifacts": 200 },
  "max_results": 200,
  "timeout_ms": 120000
}
```

Budgets appear in the fresh desktop command template and exact approved request. Depth accepts 0–4 and artifacts 1–500; defaults are 3 and 200. Unknown properties, invalid budgets and advanced-action overrides are rejected. Outer timeouts/cancellation and worker output supervision remain in force. The command returns the stage receipt, including its original input fingerprint, rather than combining separately read target snapshots.

## Evidence and limitations

- ZIP/gzip/zlib traversal and standard DEX carving use existing strict bounded parsers. Every retained artifact includes its hash, size, parent, logical label, origin and carved offset where applicable. Member labels are untrusted; extensions never establish format.
- `evidence.identification` uses `cline-artifact-identification/v1`. Per-artifact `identification` lists signature candidates and reports `bounded-validated`, `candidate`, `ambiguous`, or `unknown`. Bounded validation means only the listed parser checks, never complete semantic or executable validity.
- Shared CAFEBABE bytes retain both JVM-class and Mach-O-fat candidates. An MZ/ELF/DEX prefix plus ZIP directory candidate retains competing signatures and can traverse ZIP members without validating the other format. This is not a universal polyglot detector or proof that multiple formats execute.
- PE (MZ only), JVM, Mach-O and Wasm detection is signature-only. ELF remains a signature candidate in this workflow; use the separate native tools for structural evidence. Unsupported formats, partial/rejected content, ambiguity and exhausted budgets never produce completed identification. Empty/unknown bytes are partial, not a guessed type. Even a completed bounded DEX/ZIP scan does not prove all hidden formats were discovered.
- Fixed ceilings: 64 MiB input, 16 MiB expanded child, 128 MiB aggregate scanned bytes, 100:1 expansion, 10000 ZIP entries, 50000 parsed DEX methods and a 900000-byte worker response ceiling. ZIP names, duplicates, encrypted/symlink members, CRC failures and trailing/concatenated compression remain rejected/partial. Oversized response failure is not a successful truncated report.
- Raw `advanced_analysis/artifact_discovery` retains legacy behavior unless `advanced_options.discovery.identify_formats` is explicitly true. This optional reporting mode does not enable native parsers, target execution or writes.

## Verification

The shared owned ZIP fixture includes gzip-compressed DEX under a misleading `.exe` member, an ambiguous signature and inert unknown script bytes. Python, public SDK and installed Windows checks verify nesting, partial classifications, input hashes, depth refusal and unchanged inputs. Separate tests cover MZ-prefixed ZIP conflict, empty/unknown/signature-only inputs, invalid budgets, parser rejection, no fallback on blocked/failed/cancelled stages, and template visibility without execution. Existing Android and native regression corpora remain required.

This advances one original recommendation within explicit bounds. It does not complete the entire recommendation list.
