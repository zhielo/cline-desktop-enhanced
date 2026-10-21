# Integrated semantic source analysis

## Status and scope

This is a partial source-level migration from `morluto/rea` at commit `d0067ba34a39ea47dd7e11bb2e6169bc0938cc3f`, not the completed whole-application REA migration. It directly integrates file-local semantic analysis, application graph projection over admitted source files, graph construction, fingerprints and saved semantic/application queries. No `rea-agents` dependency, REA CLI, MCP server, REA installation, or separate REA runtime is used in production.

Existing Cline native, managed, runtime and device capabilities remain unchanged. Complete application acquisition/source selection, bundle source recovery, native high-p-code value tracing, complete managed workflows, runtime reconciliation, reconstruction obligations and remaining specialist-provider migrations are not implemented by this patch. No full REA parity or superiority claim is made.

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

## Bundled investigation skills

The app ships six instruction-only guides as the portable Agent Plugin **cline-investigation**. They appear in Customize → Skills and the local slash-command catalog:

| Command | Scope |
| --- | --- |
| `/investigate-artifact` | Confirm exact artifact identity, authorization, scope and supported analysis route. |
| `/analyze-electron` | Inspect admitted JS/TS/application and Electron-boundary evidence; separate static inference from observation. |
| `/compare-applications` | Compare distinct saved application receipts, selected exports and partial source/bundle references without rerunning a target. |
| `/investigate-native` | Use supported configured native engines and bounded selectors; preserve unresolved calls, engine/license limitations and partial coverage. |
| `/investigate-android` | Coordinate supported static Android/DEX/resource/native evidence; treat device execution as a separate approval boundary. |
| `/review-candidate` | Review preview-bound candidates, exact source/output hashes and separate validation/export steps; never overwrite originals automatically. |

The normal skills tool loads the guides on demand. Their qualified IDs are `cline-investigation:<command-name>`. Bare slash tokens retain the existing deterministic collision rules; a conflicting user skill can own a token. The qualified ID remains available to the skills tool. Selecting a guide does not enable Analysis, approve a tool, acquire a license, install an engine or run a target.

Use Customize → Plugins → Agent Plugins to disable or re-enable **cline-investigation** as one package. Its shipped skill files are not individually editable/toggleable/uninstallable through the existing controls. The setting persists, and the catalog refreshes; rebuild/restart an already running session to refresh its runtime skills. Hot-reconfiguration of an active model turn is not promised. SSH/cloud sessions do not receive local installation paths.

The app verifies the fixed compiled resource manifest before discovery. Missing/damaged resources are explicitly unavailable; normal chat remains usable. No REA installation, backend, MCP tool or new engine implementation accompanies these guides. Instruction loading and catalog acceptance are not a live-model outcome, full engine migration or REA parity test.

## Optional application graph

Select **Include application graph and Electron boundaries** or explicitly pass both flags:

```json
{"operation":"javascript_analysis","target":"app","javascript_options":{"semanticGraph":true,"applicationGraph":true}}
```

The worker uses the original module/bundle/Electron graph algorithms over admitted bytes. JSON and HTML admission is extended only for this option. Native `.node` files contribute static metadata, not native decompilation. Application identities commit a sorted virtual path/hash/size manifest; they do not certify complete original container acquisition. Semantic nodes remain file-local but bind to application nodes (`cline-semantic/2`). Graph coverage is partial even for small fixtures; configured truncation and omitted counts are retained.

Read `application-summary`, `application-nodes`, or `application-edges`. The desktop also offers explicit **Saved application feature tracing and comparisons** controls, including while Analysis is Off:

```json
{"operation":"analysis_evidence","evidence_query":{"receiptId":"<owning receipt UUID>","view":"application-trace","applicationTrace":{"seed":{"kind":"channel","value":"owned:add"},"direction":"both"},"applicationSection":"edges","limit":20}}
```

- `application-comparison`: a distinct `compareReceiptId`; same-content distinct receipts are valid, but incomplete graphs cannot prove globally unchanged behavior or absence.
- `application-exports`: distinct `compareReceiptId` and exact `exportSelectors.left/right` containing `modulePath` and `exportName`.
- `application-source-bundle`: `compareReceiptId`; the left source manifest is only a partial historical reference, without complete repository/import/VCS evidence.
- `applicationSection` selects retained arrays for bounded display. A section absent from that workflow fails explicitly. No provider, target, reconstruction or automatic approval is launched by these queries.

Both graphs and receipt finalize in one transaction after parent-side schema/hash/binding checks. The private combined transfer stays below 128 MiB; retained graph storage shares the 512 MiB ledger limit. No automatic eviction is added.

## Complete contract inventory, not a parity claim

`docs/rea-migration/capabilities.json` records all 212 public contracts from the pinned upstream registry. The companion dependency index covers static literal imports, including types, not provider script/runtime dependencies. Each contract retains its effect audit, description, source location, lexical upstream test mentions and explicit source-migration status. Seven contracts have partial source-port routes; the others are deliberately not certified by this audit, even where Cline has an independent overlapping tool.

Regenerate/check using Bun with `CLINE_SEMANTIC_REFERENCE_ROOT` set to the exact pinned development checkout:

```bash
bun scripts/rea-capability-inventory.mjs --check
```

The script never installs REA and is not part of the production runtime. The two-platform source validation workflow checks the committed inventory.

## Integrity and budgets

- Existing source inventory budgets remain: 128 files, 1 MiB per source, 8 MiB aggregate source bytes, bounded ASAR inventory. Therefore broad artifact/source-selection parity is not established.
- Upstream graph capacities remain explicit: 100,000 semantic nodes total and 20,000 per file by default, with corresponding unknown limits. Truncation is retained, not silently dropped to fit the legacy fact array.
- A private worker transfer avoids the 4 MiB stdout envelope. The parent validates the graph and its summary, and persists graph plus receipt in one SQLite transaction.
- Graph transfer/storage is limited to 128 MiB per graph, 512 MiB aggregate retained graph data. Capacity failure never evicts evidence automatically. Existing receipt admission and ownership limits apply.
- The graph root identifies the admitted source path/hash manifest, not the original application container bytes.
- New canonical graph hashing is separate from legacy receipt hashing. Historical evidence is not rehashed.
- Semantic analysis has a five-minute deadline. Worker isolation is not an OS sandbox or a fixed-RSS guarantee; no new kernel memory enforcement is claimed.
- Page output is bounded by record count and byte budget. Oversized individual records retain a display-omitted marker. Saved queries currently load/hash-validate the bounded whole graph before returning a page; they are not streaming queries.
- `compareTarget` together with semantic analysis is rejected. Analyze separately, then use saved application comparisons; no semantic or behavioral equivalence claim is provided.

## Source provenance

`semantic-engine/upstream/PROVENANCE.json` records original file hashes, pinned revision, test selection and local compatibility adaptations. Upstream MIT attribution is included. Adaptations remove unused imports or prefix unused parameter names to satisfy host compiler rules; a URL base is passed as its identical href for downstream string-only URL.parse declarations, and a guarded loop uses a type-only non-null assertion for older downstream TypeScript versions. The analysis algorithms and function arity are preserved.

Run `node scripts/verify-semantic-port.mjs` to detect undocumented drift. Do not run global source-rewriting formatters over the attributed snapshot without updating documented adaptations and rerunning differential tests.

## Validation

- `bun run build:sdk`
- In `sdk/packages/core`: `bun x vitest run src/analysis --config vitest.config.ts --maxWorkers=1`
- `bun scripts/test-semantic-worker.ts`
- `bun scripts/verify-custom-fork.ts`
- Desktop tests include `first-party-analysis.test.tsx` and `sidecar/first-party-analysis.test.ts`.

The parity test requires `CLINE_SEMANTIC_REFERENCE_ROOT` pointing to a separate checkout of the exact pinned reference. Its dependencies must resolve to identical analysis versions. The reference is development-only; do not install or launch REA in production. Without this variable, the parity test is explicitly skipped, not passed. The finite release policy requires both semantic parity checks and pins both the installer and semantic validation recipes. The reusable source-validation workflow always supplies the pinned reference and runs on Linux and Windows before the installer job.

The owned corpus covers local calls/closures, properties, promises, events, timers, child-process syntax, configuration/requests, Electron syntax, shadowing, dynamic keys, malformed input and nonexecution. Exact graph digests are compared; original source hashes are also checked. The additional application parity corpus compares original application and semantic graph digests for the same admitted inventory plus saved feature/version/export algorithm outputs. Applicable upstream graph/source-map/module/version/uncertainty tests run unchanged. This establishes equality only for those fixtures and projection inputs, not full upstream acquisition, all JavaScript programs or all REA features.

Installed Windows acceptance, licensed-engine compatibility, whole-application parity and superiority remain separate release obligations. This patch must remain draft until its required CI and release obligations are reviewed.

## Direct Electron fuse inspection

Select one explicit regular executable in the session workspace and use `javascript_analysis` with `javascript_options: {electronFuses: true}`. Do not combine graphs or a comparison target. The existing analysis mode/permission/session gates apply. Desktop App analysis exposes **Inspect executable Electron fuses only**; it never starts the selected executable or alters fuse bytes. No REA installation is required.

Read the returned receipt through `analysis_evidence` with `view: "electron-fuses"`, optionally `fuseSection: "slices"`, `"sentinels"` or `"runtime_implications"`, plus normal offset/limit/filter. Saved queries remain available Off. Oversized slice displays are omitted explicitly; the individual-sentinels view exposes bounded raw wires without truncating retained evidence. Runtime implications are derivations, not observed target execution or Inspector readiness.

The pinned source reader supports PE, ELF, thin/universal Mach-O, architecture facts and all fuse sentinel occurrences. It preserves missing/ambiguous/truncated/unknown states and ELF ASAR-enforcement uncertainty. Limits: 1 GiB input, 256 KiB scan windows, 32 sentinels per slice, existing 60-second owned-worker deadline and 4 MiB response cap. File selection is workspace-confined; automatic `.app` bundle resolution and fuse writing are not ported. The migration inventory therefore records this as a partial-source-port, not full provider parity.
