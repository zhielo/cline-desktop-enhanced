# Integrated semantic source analysis

## Status and scope

This is a partial source-level migration from `morluto/rea` at commit `d0067ba34a39ea47dd7e11bb2e6169bc0938cc3f`, not the completed whole-application REA migration. It directly integrates file-local semantic analysis, graph construction, fingerprints and saved semantic queries. No `rea-agents` dependency, REA CLI, MCP server, REA installation, or separate REA runtime is used in production.

Existing Cline native, managed, runtime and device capabilities remain unchanged. Cross-module application graph linking, bundle recovery, native high-p-code value tracing, complete managed workflows, runtime reconciliation, reconstruction obligations and remaining specialist-provider migrations are not implemented by this patch. No full REA parity or superiority claim is made.

## Use

Enable Analysis for the exact local session/workspace. In Analysis Workspace, explicitly select **Include file-local semantic graph**, clear the comparison target, and inspect static sources. Selection does not run analysis. Existing analysis remains the default.

The same path is available to the model:

```json
{"operation":"javascript_analysis","target":".","javascript_options":{"semanticGraph":true}}
```

Read the returned receipt using `analysis_evidence`. Supported views are `semantic-summary`, `semantic-nodes`, `semantic-relations`, `semantic-unknowns`, `semantic-fingerprints`, `semantic-contexts`, and `semantic-trace`. Existing evidence views still work. Evidence remains readable after switching Analysis Off.

```json
{"operation":"analysis_evidence","evidence_query":{"receiptId":"<owning receipt UUID>","view":"semantic-nodes","filter":"value","limit":20}}
```

A saved trace requires an upstream-compatible seed and direction; select the output section separately:

```json
{"operation":"analysis_evidence","evidence_query":{"receiptId":"<owning receipt UUID>","view":"semantic-trace","trace":{"seed":{"kind":"semantic-node","node_id":"<node ID from retained evidence>"},"direction":"backward-provenance"},"traceSection":"relations","limit":20}}
```

Directions are backward-provenance, forward-influence, callers and ownership. Trace findings remain static inference. No target execution, producer attestation or semantic-equivalence certification is implied.

## Integrity and budgets

- Existing source inventory budgets remain: 128 files, 1 MiB per source, 8 MiB aggregate source bytes, bounded ASAR inventory. Therefore broad artifact/source-selection parity is not established.
- Upstream graph capacities remain explicit: 100,000 semantic nodes total and 20,000 per file by default, with corresponding unknown limits. Truncation is retained, not silently dropped to fit the legacy fact array.
- A private worker transfer avoids the 4 MiB stdout envelope. The parent validates the graph and its summary, and persists graph plus receipt in one SQLite transaction.
- Graph transfer/storage is limited to 128 MiB per graph, 512 MiB aggregate retained graph data. Capacity failure never evicts evidence automatically. Existing receipt admission and ownership limits apply.
- The graph root identifies the admitted source path/hash manifest, not the original application container bytes.
- New canonical graph hashing is separate from legacy receipt hashing. Historical evidence is not rehashed.
- Semantic analysis has a five-minute deadline. Worker isolation is not an OS sandbox or a fixed-RSS guarantee; no new kernel memory enforcement is claimed.
- Page output is bounded by record count and byte budget. Oversized individual records retain a display-omitted marker. Saved queries currently load/hash-validate the bounded whole graph before returning a page; they are not streaming queries.
- Combined semantic graph/version comparison is rejected. Analyze targets independently; no application-version equivalence claim is provided.

## Source provenance

`semantic-engine/upstream/PROVENANCE.json` records original file hashes, pinned revision, test selection and local compatibility adaptations. Upstream MIT attribution is included. Adaptations remove unused imports or prefix unused parameter names to satisfy host compiler rules; a URL base is passed as its identical href for downstream string-only URL.parse declarations, and a guarded loop uses a type-only non-null assertion for older downstream TypeScript versions. The analysis algorithms and function arity are preserved.

Run `node scripts/verify-semantic-port.mjs` to detect undocumented drift. Do not run global source-rewriting formatters over the attributed snapshot without updating documented adaptations and rerunning differential tests.

## Validation

- `bun run build:sdk`
- In `sdk/packages/core`: `bun x vitest run src/analysis --config vitest.config.ts --maxWorkers=1`
- `bun scripts/test-semantic-worker.ts`
- `bun scripts/verify-custom-fork.ts`
- Desktop tests include `first-party-analysis.test.tsx` and `sidecar/first-party-analysis.test.ts`.

The parity test requires `CLINE_SEMANTIC_REFERENCE_ROOT` pointing to a separate checkout of the exact pinned reference. Its dependencies must resolve to identical analysis versions. The reference is development-only; do not install or launch REA in production. Without this variable, the parity test is explicitly skipped, not passed. The reusable source-validation workflow always supplies the pinned reference and runs on Linux and Windows before the installer job.

The owned corpus covers local calls/closures, properties, promises, events, timers, child-process syntax, configuration/requests, Electron syntax, shadowing, dynamic keys, malformed input and nonexecution. Exact graph digests are compared; original source hashes are also checked. This establishes equality only for those file-local fixtures, not all JavaScript programs or all REA features.

Installed Windows acceptance, licensed-engine compatibility, whole-application parity and superiority remain separate release obligations. This patch must remain draft until its required CI and release obligations are reviewed.
