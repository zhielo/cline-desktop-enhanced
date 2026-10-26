# Desktop maturity remediation tracker

Baseline: `1bd931317e12adf995dfeec1dedc4c018571b2ed`. This is a scoped foundation patch, not a claim that all audit findings are closed or that the desktop has product parity with Codex, Claude Desktop or Notion.

## Acceptance policy

- Preserve existing features, Full Access and permission checks. Hidden/disabled features are not removed.
- Keep unsigned private artifact-only distribution; do not enable automatic releases or updates.
- Merge only after exact-head CI and required Windows installed-artifact acceptance pass. Local Linux tests are not Windows installer evidence.
- Instructions, catalog entries and source inventory do not qualify live models, engines, security isolation or target behavior.
- Unknown and not tested remain distinct from unsupported, failed and verified.

## All audit items

| ID | Finding | Patch status | Scope / remaining work |
| --- | --- | --- | --- |
| M01 | Provider credentials are persisted as readable JSON | Open — not implemented in this patch | Use Windows Credential Manager/DPAPI-backed protected storage, macOS Keychain and Linux Secret Service. Store opaque references in settings. Add recoverable one-way legacy migration, redacted exports and explicit vault-unavailable errors. |
| M02 | Atomic replacement does not prevent concurrent settings lost updates | Implemented, targeted validation | Kernel-released cross-process mutex for save/voice/delete transactions; atomic exclusive temp + fsync; stale full-file writes reject. Follow-up adds locked per-provider transforms for settings patches, OAuth refresh/sign-in and telemetry. Refresh/sign-in commit guards reject changed credential/origin context; asynchronous edits preserve fresh omitted fields. Overlapping explicit field edits remain last-committed intent; model-registry transactions and UI revision/conflict UX remain open. |
| M03 | Corrupt provider settings silently become an empty configuration | Implemented, targeted validation | Missing files initialize normally; corrupt, incompatible or unreadable input fails visibly and is preserved. No automatic reset. |
| M04 | Timezone next-run calculation can monopolize the event loop | Implemented, targeted validation | Calendar-date candidate search replaces multi-year minute-format scans. Modern IANA DST/fractional-offset/skipped-day fixtures pass; not a universal historical-timezone proof. |
| M05 | File picker excludes essential dot-directory configuration | Implemented, targeted validation | Approved project configuration directories are discoverable; internal and unknown hidden directories remain excluded. |
| M06 | File discovery is synchronous and its output cap is not a traversal budget | Implemented, targeted validation | Async streaming discovery has independent entry/directory/result/time budgets, owned cancellation and incomplete-result UI. Already-pending filesystem I/O is not forcibly interrupted. |
| M07 | Restricted tool profiles are not arbitrary-process OS isolation | Open — not implemented in this patch | Expose separate policy and containment states. Add a real OS sandbox tier with workspace mounts, network policy, secret policy and no unsandboxed fallback. Preserve Full Access as an explicit trusted mode. |
| M08 | General-purpose skill coverage is narrower than the product ambition | Partial | Four instruction-only source/debug/release/research workflows added; ten total. Integrity/parser/registration/disablement tests remain. This adds no Office engine, provider or OS isolation. |
| M09 | Model-quality evidence does not cover the full product | Open — not implemented in this patch | Keep deterministic CI, and separately run opt-in paid model evaluations across coding, vision, long context, tool selection, document work and adversarial evidence. Attribute every score to exact model/provider/settings/build. |
| M10 | Feature availability needs a unified source of truth | Partial | Searchable 41-family inventory and shared Agenda/UI availability switch. Source support is explicitly distinct from live readiness. Setup Center remains the live engine authority; no combined model/auth/engine readiness certificate yet. |
| M11 | Native document workspace parity is incomplete | Open — not implemented in this patch | Add safe paged preview and typed artifact workflows. Validate spreadsheet recalculation, document layout, slide rendering and provenance instead of relying on “a file was created.” |
| M12 | General-purpose knowledge work is split across multiple systems | Open — not implemented in this patch | Create an explicit project knowledge service/index with citations, source revision, consent, forget/export, stale-source notices and permission checks; integrate existing storage instead of duplicating truth. |
| M13 | Authenticated browser work requires explicit human handoff | Open — not implemented in this patch | Add a host-owned private-input/auth handoff and clear signed-in/account scope UI; bind sensitive approval to exact origin/action/arguments, not only a label heuristic. Do not import cookies or expose credentials to the model. |
| M14 | Automatic desktop update and full migration rollback are not implemented | Open — not implemented in this patch | Keep manual private installation now; a later explicitly authorized private updater needs owner signing, staged activation, backup/schema migration and rollback acceptance. Do not silently enable upstream updates or publish releases. |
| M15 | Runtime-pack retention can grow disk usage indefinitely | Open — not implemented in this patch | Add reference-aware inventory, disk budget and explicit cleanup preview; protect selected/current/rollback/active-job runtimes and shared Hub references. |
| M16 | Source boundaries concentrate too much integration responsibility | Partial | File discovery extracted from the command dispatcher. Other dispatcher/session monoliths are not refactored. |
| M17 | Long transcript rendering retains the full row graph | Open — not implemented in this patch | Measure first; consider bounded pagination and measured variable-height virtualization preserving selection, find, keyboard and assistive technology behavior. Do not replace it with guessed heights blindly. |
| M18 | Resource profiles do not establish an overall speed or quota guarantee | Open — not implemented in this patch | Add reproducible cold/warm startup, tool/first-token/command latency, database and multi-agent memory benchmarks. Optimize only measured hotspots; add cross-process admission if needed. |
| M19 | Advanced-analysis labels must preserve supported-subset boundaries | Open — not implemented in this patch | Use engine-/format-/language-specific support manifests and expose unresolved/approximate/verified status in every result. Generate docs from current capabilities; add unsupported negative cases before broadening scope. |
| M20 | Reliability needs whole-journey evidence beyond fixture counts | Partial | Added cross-process, corruption, DST, bounded discovery, cancellation and capability-navigation regressions. Full journey/provider/soak qualification remains open. |

## Risk-to-test map

| Risk | Regression evidence in source | Still required |
| --- | --- | --- |
| Concurrent settings writers and killed holder | `provider-settings-durability.test.ts`: two real owned OS processes, stale replacement, exception/reentrancy, owned-holder termination | Windows execution of new same-provider process regressions; explicit overlapping-edit conflict UX and full OAuth journeys |
| Corrupt or incompatible settings | durability + manager tests preserve original bytes; existing atomic rename-failure tests retained | Installed recovery UX, volume-full and permission-denied platform matrix |
| Timezone scheduling cost/correctness | scheduler tests: DST gap/fold, Lord Howe half-hour, Apia skipped date, leap day and impossible-date format-call bound | Installed multi-schedule load and long-running restart soak |
| Large/no-match workspace search | streaming discovery tests: entry/directory/result limits, config inclusion, cancellation, missing root, outside symlink; DiffView partial/cancel regression | Remote file search remains unsupported; filesystem replacement races and network filesystem latency are not containment guarantees |
| Skill packaging and organization | integrity manifest, strict loader, command registration, disabled/restarted plugin and selfcheck tests; capability navigation tests | Exact Windows installer resource acceptance and live-model workflow evaluation |

## Limits deliberately retained

Provider credentials remain JSON at rest pending a reviewed native-vault implementation and migration. No claim of encryption is made. Tool permission profiles are not a general OS sandbox. Office editing, persistent project knowledge, private browser input, signed updating, reference-aware pack collection, full transcript virtualization and controlled whole-app benchmarks remain open. Do not close these items by adding a prompt, a label or a passing compilation.

File fsync before rename improves write flushing; parent-directory crash durability and storage hardware guarantees vary by platform. The mutex database stores locking state only, never provider settings or credentials. A process holding the SQLite transaction may cause a bounded busy error; errors must not trigger silent resets.


## Follow-up: same-provider mutation races

- `updateProviderSettings` reads, transforms, validates and commits a single provider under the existing cross-process lock. A declined transform does not rewrite settings; provider identity cannot change. No network I/O belongs inside this synchronous transaction.
- Settings service patches merge against current fields. Model discovery remains outside the lock; omitted settings survive concurrent changes, and an edit cannot recreate settings removed while discovery was pending.
- OAuth refresh checks credential/account/API-key/endpoint/OCA-mode context inside the commit transaction, not before a separate save. Concurrent sign-out, account switch and endpoint changes discard obsolete refresh results; unrelated preferences/metadata survive. Sign-in rejects changed auth context and preserves unrelated settings.
- Telemetry metadata writes preserve fresh credential fields and decline missing providers. This does not yet bind delayed account API responses to an account-generation token.
- Regressions include two real same-provider writer processes, exact refresh commit-boundary interleavings, delayed sign-in and delayed model discovery. Four refresh regressions were independently confirmed to fail against the previous runtime implementation before restoring the patch.
- Remaining boundaries: no native credential vault; no per-field UI revision tokens or persisted sign-out generation/tombstones; no atomic settings-plus-`models.json` transaction. Explicit overlapping edits and observationally identical auth changes require a stronger intent/version contract. These are not closed by this follow-up.
