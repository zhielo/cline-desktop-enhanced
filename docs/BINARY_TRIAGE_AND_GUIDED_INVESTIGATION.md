# Evidence-driven coding and investigation

The desktop preserves normal coding, selected providers, durable tasks, worktrees,
parallel agents, integrations and existing advanced analysis surfaces. The Analysis
workbench adds **Start here**: target → question → static inspection → selected
follow-up → evidence review → explicit JSON export. With no owning session, the
previous Analyze default is retained. A guide does not change permission or mode.

## Four user journeys

- Build/fix: normal chat, Changes, Files, Terminal and managed worktree review.
- Understand an application: App analysis for JS/TS/Electron/ASAR; native triage
  for supported PE/ELF. Candidate relationships never prove execution.
- Investigate APK/native issues: existing APK incidents, IDA/Ghidra/JADX and
  independently approved device/runtime operations. Extracted native libraries
  are native targets; capa/FLOSS are not universal APK/DEX engines.
- Review/publish: evidence reports distinguish observed input, derived findings,
  rule matches, unknowns and limitations. External publication remains separately
  approved through existing integrations; export is not publication.

## Binary Triage Pack

Windows x64 installers package pinned radare2 6.2.4, capa 9.4.0 and FLOSS 3.1.1.
The verified core/full Python runtimes include r2pipe 2.0.0 and yara-python 4.5.4.
Archives and upstream license files use reviewed SHA-256 pins in
`scripts/binary-triage-tools.lock.json`. Native upstream source is available at
those projects' corresponding tags; radare2 redistribution must preserve its
LGPL obligations. Included upstream licenses are not a claim of complete
transitive license review of standalone executables.

Installed use never invokes pip, downloads rules or updates engines. Repair is
reinstalling the trusted installer; existing core/full runtime repair and rollback
remain unchanged. FLOSS is optional to use, packaged for offline availability;
only **static** extraction is exposed. Decoding/emulation and live tracing are
not added. Standalone tools avoid merging capa/FLOSS dependency graphs into core.

The GUI-controlled adapter exposes fixed `inspect_binary`, `list_functions`,
`get_function_disassembly`, `find_references`, `scan_yara`,
`identify_capabilities`, `extract_strings` operations. It does **not** add a new
unrestricted model tool or arbitrary r2/Python/shell console. Normal model tools
and profiles are unchanged; model-driven triage dispatch is not implemented.

## Readiness and security

Setup Center and the guide share one readiness component: needs setup, installed
but untested, ready, unsupported, integrity failed. Opening/refreshing only reads
and hashes resources; it never launches tools. Explicit testing uses the fixed
owned PE fixture packaged from `scripts/fixtures/binary-triage-owned.rs`. Readiness
is process-local and bound to the pack manifest and interpreter executable; a
backend restart requires explicit retesting. It does not certify arbitrary
architecture/target compatibility or protect against privileged local tampering.

Execution requires a trusted local desktop connection, an attached idle Full
Access session, enabled Analysis and explicit confirmation. Workspace confinement
and hash-verified private snapshots are mandatory. Limits are 64 MiB input,
90 seconds per operation, 1 MiB worker stdout, 256 KiB discarded stderr and two
active jobs per sidecar (one per owning session). These are not an OS sandbox,
machine-wide resource enforcement or guaranteed peak-RSS limits. Engine internals
may allocate before an output limit is detected. Unknown-target execution remains
restricted to separately configured isolated workers.

The child uses a minimal environment, no inherited provider credentials, Python
isolated mode, radare2 no-rc/sandbox options, fixed commands, no debugger/write
operations and no user scripts/plugins or remote endpoints. A supervised process
is terminated as a tree on timeout/cancel; missing close confirmation retains
capacity/snapshot and explicitly reports termination-unconfirmed. Host loss never
replays work. Unresolved persisted jobs block new triage in that session; automatic
lease recovery is intentionally not supplied. Operators must inspect prior host
processes; do not delete receipts or assume a missing window proves termination.

Private durable session-scoped receipts retain input/rules/pack/interpreter and
result hashes, operation/question, timestamps and status. Terminal receipts are
immutable; rejected/failed work never becomes a successful result. Export includes
observations, findings, unanswered questions and limitations. Redaction is best
effort; review before sharing. A YARA match is not a malware verdict, no match does
not mean safe, and capa findings on packed targets can be incomplete.

## Acceptance and merge

Required consolidated gates include contract, integrity, immutable-ledger and
no-automatic-execution UI regressions. Windows packaging executes all four tools
against owned fixtures, then installed WebView acceptance repeats the readiness
journey using installed resources. Existing engine/device/license/recovery and
unsigned artifact-only gates are preserved. No arbitrary-target, real-device,
licensed-engine, whole-app speedup or superiority claim follows from fixtures.

GitHub administrator action remains necessary: require the installer, Windows
regression and isolated-execution checks, require the current integration state,
and prohibit unreviewed bypass. The available GitHub integration cannot change
repository rulesets. Never merge before the current revision's Windows installer
and all required checks succeed.

## Dependency visibility
The installer artifact includes a CycloneDX source inventory of Bun/Cargo locks, direct pinned Windows Python requirements, and pinned triage archives. This is not an exhaustive binary SBOM: transitive Python and embedded PyInstaller components still require separate distribution/license review.
