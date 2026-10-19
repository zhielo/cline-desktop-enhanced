# Android callback and resource evidence

These are bounded static commands, not target execution, Android verification, or whole-program proofs. Both return `partial` even when all requested bounded work succeeds.

## Manifest-to-DEX callback candidates

```json
{"operation":"find_android_entrypoints","target":"/owned/app.apk","advanced_options":{"entrypoints":{"max_depth":8,"max_components":64,"max_dex_files":32}}}
```

`map_attack_surface` on an APK uses the same worker. The command reads the manifest, standard root `classes.dex`/`classesN.dex` files and supported exact lifecycle signatures. It preserves declared and declaring classes, DEX hashes and method origins; follows bounded superclass chains; and reports duplicate classes, unsupported manifest names, missing ancestors and excluded DEX files without inventing resolution. Disabled/exported/permission declarations are raw evidence, not effective platform policy.

Maximums: inheritance depth 16, components 128, DEX files 32, 50,000 accepted methods/classes, 200 candidate details. Default depth/components/DEX limits are 8/64/32. Missing binary-XML parsing support blocks manifest analysis rather than substituting a filename guess. No callback dispatch, framework compatibility, reflection, dynamically registered listeners, fragment/Compose reachability or runtime behavior is proven.

## Resource and member differences

```json
{"operation":"diff_android_resources","target":"/owned/before.apk","compare_target":"/owned/after.apk","max_results":100}
```

The command hashes actual bytes of every covered regular ZIP member, not ZIP CRC alone. It separates manifest, resources, assets, DEX, native and other changes. Supported XML gets namespace-expanded structural fingerprints preserving text, tails and child order while ignoring attribute order and comments. Equal parsed structure does not mean equal Android resource configuration, compiled table semantics or application behavior. Unsupported XML retains byte evidence and an explicit unavailable structural result.

Ordinary single-disk non-ZIP64 ZIP framing is preflighted before archive allocation. Refuse duplicate/case-alias paths, traversal, special files, encryption and excessive expansion. Per archive input: 64 MiB; members: 10,000; expanded member: 16 MiB; paired aggregate expanded bytes: 128 MiB; expansion ratio: 100:1; parsed XML: 1 MiB, 20,000 nodes and depth 64. Unsupported archive forms fail closed; nothing is extracted or executed. Detail truncation retains bounded full counts and fingerprints. Originals are never overwritten.

## Bulk notebooks

Fixed actions `android_entrypoints` and `android_resources` are available in confined analysis notebooks. Resource cells require `compareTarget`; entrypoint budgets are valid only for entrypoint cells. Existing path confinement, paired input fingerprints, fresh approvals, cancellation and checkpoint invalidation apply. A partial cell does not become completed or silently unblock dependent stages. Independent approved reads may still run.

Owned Python, public executor, UI template and installed-app acceptance tests cover provenance, ambiguity, budgets, unchanged inputs and non-execution boundaries. This expansion does not turn the original 55-command roadmap into a claim of universal implementation.
