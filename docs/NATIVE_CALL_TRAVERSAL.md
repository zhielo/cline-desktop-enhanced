# Bounded native call traversal

`trace_native_calls` uses the existing fixed LIEF/Capstone ELF adapter. It does not execute a target, invoke a model-generated shell, attach a debugger, download an engine, write the input or enable Runtime mode. Use the normal independent Inspect approval and configured Python/tool-pack readiness. Missing engines are blocked, never treated as successful execution.

```json
{
  "operation": "trace_native_calls",
  "target": "/absolute/owned.so",
  "function_selector": { "symbol": "owned_root" },
  "advanced_options": {
    "native_calls": {
      "max_depth": 2,
      "max_functions": 16,
      "max_edges": 128,
      "max_total_bytes": 32768
    }
  },
  "timeout_ms": 120000
}
```

An exact hexadecimal entry address may replace the symbol. Root selection must identify one symbol before traversal. The advanced workspace template exposes these budgets before preparation; changing them creates a different approval-bound request.

## Traversal and provenance

One bounded input read (64 MiB maximum), one LIEF parse and one immutable buffer underpin all nodes. Breadth-first traversal follows **decoded direct-call candidates only**, to unique exact defined ELF function entries. It records cycles/shared callees without decoding them twice. Named aliases at one entry remain ambiguous. Symbol ranges must be nonzero, uniquely file-mapped and executable; no guessed extent. Only little-endian ELF ARM/Thumb/ARM64/x86/x86_64 is supported by the adapter. Other formats/architectures are not silently interpreted.

`stages[0].result.result.evidence.callGraph` contains the `cline-native-call-graph/v1` receipt: input-associated node IDs, exact addresses, architecture, symbol size, depth, per-node decode status, requested/decoded bytes, byte fingerprints, call-site edges, target resolution/status, budgets and usage. The existing stage wrapper retains input SHA-256 and tool versions; the selected root retains bounded instruction evidence. Descendant nodes contain summaries rather than duplicating all disassembly. Addresses describe ELF link-time virtual space, **not** ASLR/runtime placement.

Defaults: depth 2 (root depth 0), 16 functions including root, 128 edges, 32 KiB requested instruction bytes total. Hard limits: depth 4, 32 functions, 256 edges, 64 KiB total. `advanced_options.function.max_bytes` remains the existing per-function limit (default 4096, maximum 65536); when supplied its symbol/address selector must also be valid. Each decode retains the existing 1000-instruction and bounded relationship limits. Metadata display rows can be truncated independently of the up-to-50000-entry symbol lookup index. The normal supervised worker output cap (1 MiB), timeout, process-tree cancellation and retained diagnostics still apply; output overflow fails rather than silently dropping evidence.

Depth, node, edge and byte limits plus partial/blocked ranges and per-function relationship truncation are recorded explicitly. Unknown/import/PLT targets, missing symbols, indirect calls (even static constant-register candidates), and ambiguous entries are not followed. ARM64 and other supported non-x64 indirect calls are retained as unresolved candidates. No automatic retries or fallback to target execution occur.

## Interpretation

Every traversal remains **partial** and `observedExecution: false`, even when its finite frontier is exhausted. Linear symbol-range disassembly is not a CFG, whole-program call graph or proof a call is reachable. Conditional reachability, tail calls, stripped functions, dynamically registered targets, cross-image imports and actual execution remain outside this contract. No claim of full recommendation coverage follows from this feature.

## Owned checks

The shared synthetic ELF fixture contains `owned_root -> owned_child -> owned_leaf -> owned_root`; it is parsed, never run. Real LIEF/Capstone tests cover multi-hop traversal, cycles, limits, invalid extents, aliases, unknown targets and indirect calls. Stdlib tests independently exercise budgets and scheduling. Installed Windows acceptance repeats the three-node chain and depth-zero stop through exact approval and the packaged SDK after full tool-pack setup; original bytes must remain unchanged. The release gate requires all 46 installed stages, including final owned-process cleanup.
