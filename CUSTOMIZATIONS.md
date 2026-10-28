# Cline Enhanced custom fork

This file is the durable customization ledger for this repository. The source on `main` is the source of truth: every installer must be built from a committed revision, and custom behavior must never exist only as an uncommitted patch or generated build output.

## Installed RPC evidence bookkeeping

- Every acceptance RPC records endpoint discovery and command submission as one bounded operation rather than counting native endpoint lookup as an additional action. Discovery still occurs on every call, including restarts; discovery/submission failures remain recorded, and submitted commands are never retried. The 768-action cap, 95-second per-action deadline, all 70 installed stages and cleanup requirements remain unchanged. Regression coverage exercises 400 calls, fresh endpoint lookup and both failure paths. The exact installed recipe fingerprint follows this change; no gate is bypassed.

## Qiling static multi-architecture profile v2

- Extend the fixed Linux static ELF profile to little-endian ARM32 and ARM64 while retaining x86-64, Unicorn and all existing Android/Speakeasy routes. SDK/schema/plan/catalog/UI and worker profiles are bound to the same reviewed architecture map and exact updated profile digest. Unsupported engines/architectures, dynamic ELF, dependencies and external rootfs remain blocked; no engine fallback.
- Qiling verifies its detected architecture and installs only the selected Linux ABI's write/exit/exit_group syscall numbers. Unknown syscalls stop before the original dispatcher. Stdout/stderr, instruction, parent deadline and evidence limits remain unchanged.
- Runtime sealing requires every advertised architecture fixture. Startup rejects missing, empty, extra or unsealed fixture maps and requires the real bounded stdout hash and exit-7 assertions for all Qiling architectures. Signed desktop capability validation also rejects incomplete/duplicate architecture lists. Old profile/runtime fingerprints must be deliberately resealed/restarted; no stale approval is reused.
- Clang/LLD acceptance builds separate owned static Linux ELF images, distinct from JNI shared libraries. Real worker tests verify matching output/exit, denied syscalls, mismatched expectations, instruction limits, fresh state, signed receipts, no replay and process-group cancellation for each architecture. The existing installed planning/Static-denial/unconfigured-worker-denial stage covers all six supported engine/architecture pairs and checks that the returned plan preserves both choices. Its exact recipe fingerprint changes without removing prior stages. Local owned fixture execution does not attest VM isolation or installed Windows engine provisioning.

## Setup output-boundary and framework visibility repairs

- Ghidra and IDA Setup Center owned test projects use unique private canonical OS temporary directories, which the existing reverse-engineering output policy already permits. Durable receipts remain under the data directory. No external-output acknowledgement, global allowlist expansion, license preflight or target execution is introduced. Real executor extraction tests exercise the shared output guard without mocking it; engine acceptance tests assert the route uses the new directories.
- Setup Center renders the backend's existing registered capability catalog and separate Qiling, unidbg, rnidbg and Speakeasy cards. Configuration-only states reuse the transport validators and never return endpoints, keys, tokens or raw parser errors. Merely opening the page performs no worker probe, test, install or execution. Registered routes do not establish current-model exposure or engine readiness.
- Install all continues to mean bundled local engine packs only. These four isolated workers are not bundled or app-managed, Qiling v2 adds explicitly tested static x86-64/ARM32/ARM64 Linux ELF entry profiles, not general rootfs or upstream architecture parity. Managed install/test/use, dynamic/rootfs Qiling support, interrupted-job recovery and session-specific model-exposure evidence remain outstanding; see `docs/SETUP_MATURITY_REMAINING.md`. This repair must not be represented as completion of the maturity roadmap.
- New regression files join the existing consolidated desktop customization gate; all prior gate names, checks, timeouts and installed Windows stages remain intact. The validator fingerprint follows the added tests only; the installer-workflow fingerprint follows one added production Setup Center Ghidra acceptance step in its existing pinned Linux/Windows Ghidra job. It requires a durable data directory outside OS temp to reproduce the former failure; no existing step is removed.

## Deep audit lifecycle hardening (2026-10-25)

- Local session deletion validates opaque IDs, requires an existing session and deletes only its canonical owned directory and derived regular log file. Stored message paths never authorize recursive parent cleanup; linked directories/junctions are refused. Unknown session IDs do not trigger artifact deletion. Legacy external artifacts remain untouched rather than being guessed as owned.
- The shared core persistence backend uses the same ownership rule: it derives message artifact identities rather than deleting persisted `messagesPath` parents, rejects unsafe deletion IDs and refuses canonical path/junction aliases.
- Session discovery is read-only, including reserved upload staging and unindexed artifacts. It performs no garbage collection.
- Attachment materialization copies completed uploads provisionally, rolls back partial outputs and preserves original upload IDs on failure; staging is consumed only after all outputs succeed. Attachment-bearing steering remains visibly queued for the regular multimodal turn because the existing steering callback is text-only. Text-only steering remains unchanged.
- Pending prompts represent distinct submissions even with identical text. Only an explicit submission identity can deduplicate a replay; editing/promoting a queued prompt uses its prompt ID, not its text.
- Task-state replacement never unlinks the previous valid state after a failed rename. Replacement errors remain failures and do not claim a saved state.
- ClinePass unknown capability facts are explicit and survive all catalog-to-gateway producers. Exact known model identities may supply bundled facts; no dated-name guessing or blanket vision enabling is introduced. Image input with unresolved facts fails visibly instead of being silently removed. Current user media reserves budget ahead of historical media while existing limits stay enforced.
- External evidence packages redact nested quoted JSON sensitive keys and quoted source/YAML assignments before sharing. Preview/approval and best-effort limitations remain; this is not a perfect secret-scanning guarantee.
- Engineering review includes NUL-delimited tracked and untracked nonignored paths, bounded new-text line counts, rename parsing and explicit unknown CI status. Unknown checks do not authorize a merge.
- Release policy v2 requires the live two-parent current-base/head synthetic merge identity and checks base/merge identity again at final collection. A direct-head build or stale-base receipt cannot certify integration. The merge tree may legitimately differ from the head tree and is reported as the tested tree.
- Regression tests accompany these invariants. Source/unit results do not substitute for installed Windows or live-provider acceptance. No merge, release publication or automatic update is added.

## AI-callable Binary Triage Pack

- `reverse_engineer` → `advanced_analysis` → `binary_triage` runs the existing seven fixed operations through a dedicated `binaryTriage` desktop/Hub capability. Other reverse-engineering executors are unchanged; no headless, generic RPC or shell fallback is added.
- AI execution binds approval to owning session/workspace, operation/question/address, target hash, pack/rule identity and interpreter hash. It requires local attached Full Access, Static/Hybrid mode, matching selected-engine fixture readiness and independent trusted-surface review. Manual workbench retains idle-session rules.
- Task abort and scope/profile/mode changes cancel supervised children. Unconfirmed termination remains unresolved and blocks replay. Saved evidence is scoped and paged, non-executing and readable Off.
- Setup/catalog/tool instructions distinguish supported route, inventory/fixture status and per-request authorization. YARA uses minimal neutral marker/header rules, not a threat signature library; FLOSS remains PE static-only. Joern Windows support is not changed.
- Windows installed acceptance uses a deterministic loopback provider through actual model dispatch, Hub capability transport, human-review transport and real engines. All seven operations and receipts are required by the release policy. This is not a live commercial-provider or arbitrary-target guarantee.

## Optional specialist reverse-engineering profiles

- Added fixed Joern single-file queries and bounded raw-AMD64 angr models, separate owned-fixture Setup Center receipts, input/request/runtime identity and fail-closed OS memory enforcement. Existing eleven-engine readiness is unchanged. Joern uses the reviewed Linux distribution; Windows Joern remains blocked.
- Speakeasy uses a separately provisioned authenticated, signed isolated worker and the existing approved runtime workbench, not a model static tool or desktop-native target launch. The blanket Qiling deferral is superseded by the optional static x86-64/ARM32/ARM64 empty-rootfs profiles in `docs/ADDITIVE_EMULATION.md`; general rootfs and broader architecture support remain unimplemented.
- Frida's read-only process/protocol probe moved into `capture_support.instrumentation_preflight` and runs before target installation. Preservation markers follow that implementation and retain process enumeration/system-parameter checks. Sandbox redirect rejection remains enforced; its marker follows formatting only.
- New owned real-engine CI supplements, rather than replaces, existing Windows build/release gates. The finite release recipe fingerprint follows the consolidated validator addition; all prior gate names and assertions remain intact. The four specialist job names and their workflow fingerprint are added to the finite release policy. Local fixtures do not certify installed Windows, live Android or operator VM/network deployment. See `docs/RE_SPECIALIST_ENGINES.md` for exact scopes and prerequisites.

## Native Node CI supervision with exact pinned Bun children

- The consolidated CI supervisor runs under native Node 22+, independent of the Bun children that execute the unchanged gates. This addresses a repeatedly observed Windows stall at installer configuration in which Bun-hosted supervisor heartbeats also stopped; it is a targeted mitigation, not proof of an established Bun root cause or a passing Windows result.
- Before any gate, bounded isolated probes verify the exact supported Bun version, canonical regular-file executable and a second invocation of that exact path. Every default Bun job uses that executable; explicitly Node/Python jobs retain their own runtime. Wrong/malformed/changed identities fail closed. Probe failures omit child error output.
- No gate is removed, skipped or retried; 20-minute per-gate and 35-minute outer workflow deadlines, owned child-tree termination, failure receipts and exact commit/run/attempt reuse remain unchanged. Package orchestration still uses the existing workflow commands; only the supervisor runtime changes. Its finite release recipe hash is updated. New Windows validation is mandatory before claiming the mitigation works.

## Runtime-neutral installed receipt profile identity

- The unchanged `cline-js-static/7` constant lives in the dependency-free analysis `profile.ts` module. Analysis contracts import and re-export that same constant; parser schemas and receipt validation remain unchanged. Native Node strip-types acceptance imports/reads the profile-only module rather than transitively loading Bun-resolved source parsers. No Node loader, extension-resolution workaround or parser validation bypass is added.
- Native harness acceptance still verifies the trusted checkout's exact profile declaration and rejects stale, empty or unknown profiles. A schema regression binds the production contract export and literal validation to the same profile and checks that malformed fuse evidence is still rejected. Native harness source-string assertions use the formatted call text; counts, quit deadlines, capture instrumentation and restart checks are retained. Source-reference ordering additionally requires both markers to exist. The acceptance hash is repinned; no runtime profile version, existing assertion, cleanup check or deadline is relaxed.

## Electron reader cross-runtime compatibility and acceptance formatting

- The VS Code source compatibility check uses older Node declarations that omit the BigInt positional-read overload supported by Node 24 and Bun 1.3. A call-local type-only intersection preserves the exact original method receiver and BigInt offset without number coercion. Emitted JavaScript is byte-identical to the original reader. Original cancellation/coverage fixtures and new real-descriptor/cursor/large-offset regressions remain blocking; provenance records the adaptation explicitly.
- The installed acceptance driver is formatted with the existing extension Biome configuration. Its emitted runtime AST is unchanged (ignoring parentheses/formatting), assertions and deadlines are not relaxed, and the finite policy pins its new bytes. The exact filterable-view-before-filter preservation marker is updated to the formatted source, not removed. The complete extension quality/package checks must pass before publication. The dependency-free quick-preflight skill and Windows-hardening assertions also use the formatted call text, retaining every disabled-state, approval, isolation, immutable-preview and saved-workflow check; startup ordering now explicitly requires both source locations to exist, preventing a missing-marker index of -1 from passing.

## Direct Electron fuse source port

- `javascript_analysis` accepts explicit `javascript_options.electronFuses: true` for one confined regular PE/ELF/Mach-O executable, including universal Mach-O slices. It uses the pinned original streaming reader, format/architecture decoders, wire-state names, implication rules and descriptor cleanup—not a REA install, backend, MCP server or executable plugin. Existing source analysis remains the default. Fuse mode cannot combine graphs or comparison.
- The existing session mode, local ownership, permission and fixed child-process controls still apply. The reader caps one input at 1 GiB, searches in 256 KiB windows and rejects more than 32 sentinels per slice; the existing 60-second worker deadline and 4 MiB response cap remain unchanged. This is streaming file admission, not a fixed-RSS or kernel-sandbox guarantee.
- Parent admission requires the requested fuse result to be present (and absent otherwise), a partial status, one matching hash/byte-count artifact projection, exact read-byte counters and no synthetic JS facts/edges. Full validated wire reports persist under the receipt hash. Session-owned `electron-fuses` evidence stays readable while Off, with bounded slices, individual sentinels and runtime-implication pages. Missing, multiple, removed, unknown-version, unknown-byte and truncated states remain explicit; Linux embedded-ASAR enforcement stays unknown.
- Desktop controls provide explicit fuse-only selection, disable incompatible options and reset on session/environment changes. The evidence view exposes artifact identity, limitations, raw wires and derived implications. No fuse is written and no target is launched. No automatic macOS .app resolution, Inspector readiness, application security or complete REA parity is claimed.
- Exact-source PE/ELF/thin/universal Mach-O fixture parity and worker/receipt/schema/UI regressions block CI. An additional installed Windows stage requires explicit UI invocation, exact original-byte preservation and hash/size binding, raw wires plus derived evidence while Off. This stage remains pending until a fresh current-head installer run succeeds.

## Bundled investigation skills (instruction-only)

- Six original workflow guides ship inside the app as the pinned portable Agent Plugin `cline-investigation`: artifact routing, Electron/application evidence, saved application comparisons, native investigation, Android investigation and candidate review. This is not a REA install, CLI, MCP server or executable plugin. The guides invoke only actual advertised Cline tools, preserve receipts/hashes/unknowns, and never grant approval, install engines or certify behavior.
- Source resources live in `src-tauri/investigation-skills`, included by both Tauri resource recipes. The compiled manifest pins every member's byte count and SHA256. Missing, changed, appended, extra, linked or redirected members fail closed with an explicit unavailable catalog; a broken installed resource never falls back to development sources. The dev fallback requires an actual source module on disk. There are no IPC/environment resource-root overrides or writes to user-global skill folders. These integrity checks are not a kernel sandbox against a concurrently hostile filesystem.
- Local new/rebuilt/forked/restored sessions receive verified portable `agentPluginPaths`. Nonlocal runtime bindings never receive desktop resource paths. Local catalogs and slash expansion use the existing portable loader and skills executor. Existing deterministic command-collision semantics remain unchanged. Catalog records retain Agent Plugin ownership so the existing UI disables per-skill mutation/uninstall; the existing plugin-level disable setting controls the whole pack and persists across restart.
- Skill availability is instruction metadata, not engine readiness or proof of a live model turn. Restart/rebuild an existing runtime session after changing its plugin setting; immediate hot-reconfiguration of a running model is not claimed. The fixed sidecar selfcheck reads all six instructions before profile/Hub/listener startup and performs no provider call or target execution.
- A dedicated blocking core gate exercises integrity, real catalog/control wiring and local-only projection. Two additional installed Windows stages require compiled instruction loading, six namespaced catalog entries, disable/re-enable behavior and disabled-state persistence after native restart. These stages require new-head CI evidence; the earlier successful installer does not contain this skill pack. The full REA migration remains partial.

## Installed application evidence view sequencing

- The installed WebView journey selects the filterable application-nodes view before filling its evidence filter. The preceding verification view intentionally has no filter. This repairs a captured locator timeout without changing app behavior, adding force clicks/retries, increasing deadlines, skipping assertions or bypassing the installed release gate.
- A UI regression checks that verification has no filter, switching views exposes it, and saved application evidence is queried while Off without starting inspection. The ordered installed interaction is preserved and the finite release policy pins the updated acceptance script.

## Windows SDK fixture interpreter initialization

- Before Windows SDK tests, a separate bounded CI-only check starts the existing interpreter in isolated `-I -B` mode, initializes fixture-used standard-library modules, validates its reported absolute executable/version identity, and binds subsequent tests to that exact canonical executable through `CLINE_RE_PYTHON`. Startup phase markers distinguish interpreter entry from standard-library readiness on failure; raw environment or stderr content is not printed.
- This does not install Python, load fixtures or target code, retry tests, change the 18-second Android fixture child deadlines, skip cases, or claim improved production cold-start performance. Initialization has its own 60-second bound and fails the job if unsuccessful. Package scheduling remains unchanged: the failed core suite was not overlapping other SDK packages.

## Migration CI diagnostics and narrowly scoped secret-scan exception

- The pinned public REA revision is exempted only from the Sourcegraph token rule, on its exact `revision` JSON line in the two generated migration inventories. Other fields, revisions, files and actual token patterns remain scanned. One exact historical fingerprint records the same public revision in the first scanner-scope fixture; current fixtures read the revision from inventory instead of embedding it. Nine synthetic scope regressions run before both Windows secret scans; default rules and full-history scanning remain enabled.
- Application evidence fixtures use the worker's async canonicalizer on their temporary workspace before calling low-level helpers; synchronous JS realpath can retain Windows 8.3 TEMP aliases. The worker containment/link checks remain unchanged.
- Semantic CI always publishes bounded JUnit failure/error annotations, retains the complete report artifact, and fails diagnostic parsing on missing/malformed/unsafe reports. Unicode diagnostics explicitly use UTF-8, including on Windows console code pages. Python is standard-library CI tooling only, not an app prerequisite. The original Vitest exit status still blocks release; tests are not retried or skipped to mask failures.

## Integrated application graph and saved application workflows (partial REA migration)

- Explicit `javascript_options.applicationGraph: true` additionally requires `semanticGraph: true`; both default off. The installed desktop checkbox binds those choices visibly, never silently enables Analysis mode or approves execution. The owned worker directly imports the pinned source algorithms; no REA install, CLI, server or separate runtime is introduced.
- Desktop development/WebView typechecks target ES2020 to match existing Bun and modern WebView2 runtimes and allow BigInt in type-inclusive upstream dependencies; static analysis implementation remains sidecar-only. Strict checking and test inclusion remain enabled.
- Admitted JS/TS, package/JSON, HTML, source-map and native-addon metadata feed an application graph with module, bundle and Electron boundary relationships. File-local semantic nodes bind to the graph under `cline-semantic/2`; `cline-application/1` identifies the application projection. Legacy `cline-semantic/1` behavior remains available. This is a virtual sorted path/SHA256/byte-count manifest, not complete container identity, whole-program execution or a cross-module taint solver. Coverage stays partial and original truncation/omission accounting is preserved.
- Application and semantic graphs transfer together under the existing private 128 MiB combined transfer cap and finalize atomically with the receipt. Each graph remains capped at 128 MiB; the shared ledger is capped at 512 MiB without eviction. Stored manifest hashes, canonical graph hashes, application IDs and semantic bindings must agree. Paths are confined relative POSIX identities; changed bytes, duplicate NFC paths and traversal are rejected.
- `analysis_evidence` adds application-summary/nodes/edges and explicit saved application-trace/comparison/exports/source-bundle workflows. Comparisons authenticate both receipts to the owning session and derive separate Evidence identities from receipt ID plus result hash, including identical-content distinct receipts. Version/export comparison rejects the same receipt on both sides. Source-to-bundle reference input is admitted source metadata only, not a complete VCS/import inventory. No provider is opened; queries remain readable Off and never certify behavior. Partial inputs prevent unchanged/absence guarantees.
- The installed Windows journey explicitly enables the new checkbox, inspects an owned Electron fixture, reads a saved trace Off and checks a filesystem sentinel proving that fixture code was not run. The finite policy requires this new stage. This is a pending release check until CI actually succeeds; it does not establish arbitrary-target parity.
- `docs/rea-migration/capabilities.json` inventories every public contract in the pinned upstream registry with audited upstream effects, source references, static type-inclusive dependencies, lexical test mentions and explicit migration status. `scripts/rea-capability-inventory.mjs --check` detects drift in Linux/Windows CI; names and lexical test references are not parity proof. Native, managed, runtime reconciliation, reconstruction and specialist migrations remain unfinished.

## Integrated semantic source port (partial REA migration)

The finite release verifier requires both Linux and Windows semantic-parity checks and hash-pins the standalone semantic validation recipe as well as its installer dependency. Missing, skipped, failed, or altered semantic release evidence is rejected.

- `javascript_analysis` optionally accepts `javascript_options.semanticGraph: true`; the desktop Analysis Workspace offers an explicit file-local semantic graph checkbox. No REA package, CLI, MCP server or separate runtime is installed or launched. The existing owned analysis worker runs directly imported source algorithms.
- Source revision `d0067ba34a39ea47dd7e11bb2e6169bc0938cc3f`, MIT notice, exact file hashes, compatibility-only adaptations and applicable upstream fixtures are recorded under `sdk/packages/core/src/analysis/semantic-engine/upstream/PROVENANCE.json`. `scripts/verify-semantic-port.mjs` prevents undocumented source drift.
- Large semantic output transfers privately outside stdout, then persists atomically with its receipt. New canonical hashes do not replace legacy receipt hashes. Graphs are session/receipt-bound, capped at 128 MiB each and 512 MiB total, with no automatic evidence deletion. Existing source admission limits remain, so full artifact/source-selection parity is not claimed.
- Saved semantic-summary/nodes/relations/unknowns/fingerprints/contexts and bounded semantic-trace sections are available through `analysis_evidence`, including in Off. Results retain static-inference limitations. Queries currently validate/load the bounded whole graph before returning a bounded page; this is not a streaming-query or fixed-RSS guarantee.
- Semantic analysis has a five-minute worker deadline; process separation is not a kernel memory sandbox. Semantic version comparisons are rejected rather than silently using a reduced implementation. Existing source inspection remains the default.
- A blocking Linux/Windows source-parity workflow compares owned file-local fixtures with a separately checked-out pinned source reference, never a production dependency. An owned worker smoke verifies persistence and tracing. This does not establish complete application acquisition, source recovery, native, managed, runtime/reconstruction, external-engine or installed-Windows parity. See `docs/INTEGRATED_SEMANTIC_SOURCE.md`.

## Six-defect desktop audit repair

- Automatic task validation requires the current command/write/network capability profile and explicit auto-approval, a successful exact matching plan-tool completion, a local session, and a canonical workspace working directory. Plan/read-only/restricted profiles are not widened by auto-approval; reviewed tool calls remain the fallback. These are capability gates, not an OS sandbox.
- Stop/Abort/configuration changes/environment disposal cancel and drain owned validation processes. Replaced plans cannot reuse a stale completion or turn a late zero exit into passed evidence.
- Explicit IDA desktop requests default to a 75-minute overall approval envelope for the existing one-hour auto-analysis phase; other engines and explicit shorter budgets keep their limits. Fake-clock tests retain exact deadline enforcement.
- Reports supersede old headline failures only with newer same-plan/step/scope host checks; history and unrelated failures remain. Chat media uses a canonical-schema adapter across Zod majors.
- Full WebView typing (including fixtures) and strict Next.js builds are required. CI and the pinned finite release policy include the new frontend/audit gates; no acceptance checks are skipped. See `docs/desktop/audit-repair-contracts.md` for limitations and regression references.

## Bounded advanced candidates, graph tracing and reviewed batches

- Advanced AI commands now expose `preview_binary_patch` / `patch_binary`, `preview_ast_transform` / `apply_ast_transform`, managed and JVM constant preview/apply pairs, `decompile_dotnet_method`, `read_jvm_method`, `trace_cross_language`, `trace_data_flow`, and independent `preview_candidate_batch` / `apply_candidate_batch` operations. Selection only prepares a request; the owning trusted idle session, mode, permission profile and separate one-use human execution approval remain mandatory. New writes are classified Modify, including batch writes.
- Every candidate requires the current source SHA256 and a new explicit output. Apply also requires a matching preview SHA256 binding source, destination, output and recipe. Inputs are bounded regular files (16 MiB; JS/TS source 1 MiB), symlink ancestors and existing outputs are rejected. Private temporary files publish using an atomic no-clobber hard link, never an overwrite fallback. Publication receipts retain cleanup warnings if a candidate was published but temporary-link cleanup failed. These checks are not an OS sandbox against concurrent hostile filesystem mutation.
- Binary recipes replace exact equal-width bytes only. AST recipes replace one exact primitive JS/TS literal at a UTF-16 offset and reparse syntax; no arbitrary expressions, calls or whole-program transforms. Managed recipes replace a selected fixed-width `ldc.i4` constant; selected Int32 constant-return bodies can reconstruct a minimal body, otherwise bounded IL remains explicitly partial. JVM recipes inspect a selected class method and transform only static `()I` iconst/ireturn bodies with no exception/nested Code attributes. No PE checksum, relocation, strong-name, class verifier, semantic-equivalence or runtime correctness guarantee is implied.
- Trace commands traverse saved first-party static reports or existing artifact evidence graphs, preserving source locations, hashes, confidence and coverage. Depth/node/edge and 96 KiB selected-payload budgets apply; oversized seed/coverage is rejected. Data-flow mode uses only declared data-flow edges. Candidate JNI/IPC paths remain candidates, not observed execution or universal inter-language/taint resolution.
- Batch manifests contain up to eight independent fixed candidate stages, with relative paths confined beneath the manifest directory. All sources, outputs and recipes are preflighted before writes; the batch preview SHA256 also binds the manifest bytes. Duplicate destinations, dependent outputs, arbitrary shell/sign/install stages and automatic replay are rejected. Each file is atomic, not the whole batch; failure/cancellation stops and returns completed output receipts plus skipped stages. Inspect partial candidates before a separately approved new manifest.
- `capture_network_metadata` is an alias of the existing owned built-in browser metadata capture workflow, not a system-wide packet capture engine. It shares strict model input, independent fresh human start consent, Hybrid static-evidence preflight, session checks and cleanup-only stop behavior. The static command picker directs users to the existing Investigation runtime controls.
- The owned APK observation-owner and cancellation regressions wait for an explicit observation-boundary handshake, not an assumed 500 ms startup. Their finally paths cancel when needed, release and drain the owned operation before SQLite/root teardown; assertions still require an incomplete receipt, no fix claim and no replay. No production cancellation policy or CI gate is relaxed.
- Consolidated validation adds blocking candidate/tracing regression suites; installed Windows WebView acceptance additionally performs a separately approved binary/AST batch preview/apply and verifies both originals and exact candidates. Synthetic managed/JVM fixtures prove bounded parser transformations, not actual CLR/JVM target execution.
- Still unavailable: universal cross-language resolution, whole-program taint solving, general native executable rewriting, complete .NET decompilation, arbitrary AST refactoring, unrestricted batch replay, non-browser packet capture, and an automatically approved patch→assemble→rebuild→sign→install→verify pipeline. Existing Android assembly/build/sign/device commands remain separate approved workflows; this batch does not claim that entire roadmap is complete.

## First-party Analysis Workspace (no REA dependency)

- Existing local sessions gain a session-specific Analysis Off/Static/Runtime control. Off is the default; mode changes require a trusted desktop connection and idle chat. The control gates the new static parser, not existing tools, and never overrides permission profiles or approves runtime actions.
- `reverse_engineer` gains `javascript_analysis` and paginated `analysis_evidence` operations. Static inspection requires an enabled exact owning session/workspace. Evidence can still be read in Off. No target module is imported, evaluated, transpiled or executed. Runtime selection adds no JavaScript Inspector implementation.
- TypeScript 5.9.3 is pinned and bundled into a fixed parser-child branch in the existing compiled sidecar. No REA process, separate Node install, Python pack or target-provided script is required. Worker environment excludes credentials; target .env/bunfig are not used as child host configuration.
- Inventory supports confined directories, JS/TS/JSX/TSX, package metadata and bounded ASAR payloads. Links/unpacked ASAR sources, malformed/oversized files and excluded directories produce explicit partial coverage. Static findings include literal module/native-addon references, function/call syntax, unshadowed Electron IPC/preload candidates and literal global-fetch candidates. Profile `cline-js-static/2` additionally performs bounded lexical symbol resolution, immutable scalar/template/concatenation reduction and simple pure-return argument substitution, with configuration→request and local-call support edges. Mutable/imported/side-effecting/recursive values remain unresolved. Basic Source Map v3 declarations and embedded source hashes are read as untrusted labels, never fetched or executed. This is not full program data flow or universal deobfuscation.
- The private SQLite ledger atomically reserves at most two shared workers, retains up to 250 receipts without automatic deletion, binds mode to canonical workspace, and preserves immutable terminal receipts, evidence hashes, parser profiles, source hashes/locations and observed/derived distinctions. Hash integrity is not producer attestation or behavioral correctness. Abrupt host loss retains running reservations; no PID-only recovery, automatic replay or unsafe restart repair is added.
- Parser budgets: 128 source files, 4096 inventory entries, depth 8, 1 MiB per source, 8 MiB total source bytes, 32 MiB ASAR input, 200000 visited AST nodes, 8000 findings/edges, 4 MiB result and 60-second deadline. These are admission/output budgets, not an OS sandbox or guaranteed total-RSS ceiling; AST construction precedes traversal counting.
- Analysis Workspace has bounded Artifacts/Findings/Graph/Comparison/Timeline/Verification views and optional relative-path byte plus finding comparison. Added/removed findings retain exact hashed source evidence; identical version-relative modules do not become changes solely due to folder names. Comparisons are paginated and available in Off. Candidate graph relationships do not prove execution, unique routing or semantic equivalence. Native/device/project-edit/runtime workflows remain in their existing explicitly approved workbench tabs.
- Setup Center separates bundled parser presence, explicit owned-fixture results, target support, existing native provider tests and unavailable JavaScript runtime capture. Parser license/notices ship inside the sidecar and can be read from Setup Center.
- Consolidated validation includes parser/admission/worker safety tests and UI regression tests. Windows installer acceptance additionally runs the installed sidecar parser selfcheck and WebView mode/IPC/evidence journey before verified installer upload. New implementation is not a benchmark proving REA superiority, full .NET integration, native function dossiers, comprehensive semantic recovery or general runtime reconstruction.

## Integrated analysis runtime and Windows merge hardening

- Python workers retain bounded streaming-redacted stderr, exact host job/interpreter/PID/exit/signal metadata and distinct failure categories. Failed/blocked receipts are private and bounded; nonzero exit never counts as success. Unconfirmed termination is explicit and defers script cleanup.
- Settings → Analysis environment performs explicit, coalesced owned-fixture readiness and package inventory using the backend interpreter. No installs or target execution occur on refresh; IDA/Hex-Rays/device readiness remains separately unverified.
- `scripts/setup-analysis-environment.ps1` requires explicit `-Apply`, pinned dependencies and isolated imports before setting the user's absolute interpreter. Python CI environments are not bundled into the installer. Keystone is not required by Capstone disassembly or IDA.
- Normal supervised IDA runs publish exact PID receipts and fixed decompiler script phases; the read-only job view never uses CPU totals or missing output as progress proof. Unconfirmed termination/drain retains the cross-process project lease; no automatic stealing or PID-only recovery is added.
- Every main PR gets an unsigned installer check; fix branches are included. Regression filters are removed and consolidated checks replace failure-masking multiline PowerShell commands. Hosted CI additionally runs optional Python fixture corpora.
- Verified installer upload now requires installed sidecar smoke AND an installed WebView2 acceptance journey with isolated workspace/profile, idle session, local setting, readiness, navigation and restart. No live model turn, physical-device or licensed IDA test is claimed.
- Private installer signing secrets and release publication are removed from this workflow, aligning it with artifact-only policy. The supported Bun version is centralized in root packageManager/engines.bun; custom Windows, installer tests and SDK CI read it through scripts/read-bun-version.mjs (currently 1.3.14). Hosted runner versions remain pinned in workflows.
- Licensed selected-function acceptance is an explicit local script on an authorized IDA/Hex-Rays machine; it is not run by hosted CI and must supply a reviewed receipt when changing adapters. See `docs/ANALYSIS_RUNTIME_HARDENING.md` for setup, evidence and required GitHub administrator settings.

## Fixed Windows project output location

- Windows canonical directory spelling is accepted only when bigint filesystem directory and parent identities match; existing junction/link and distinct-identity redirection tests remain mandatory. Build #174 exposed the former spelling-only false positive; no failing suite was skipped.

- New local Windows session prompts supply `C:\Cline-Outputs` as the generated-output default. Stable sanitized project names plus a workspace-path hash separate same-named projects; `deliverables`, `reports` and `logs` are explicit destinations. Source edits and existing build/private-evidence/native-project storage remain unchanged.
- The session header shows the exact destination with Copy path and Open outputs. Reading/refresh does not create folders. The explicit button creates direct children only, rejects existing links/junctions, and surfaces permission failures without AppData fallback.
- Local Windows only: SSH/cloud hosts are never routed to the desktop C drive. This is agent guidance plus folder controls, not interception of arbitrary shell/file operations or an OS sandbox; explicit existing tool output paths remain in effect. Existing sessions keep their persisted prompt until a new/rebuilt session is started.
- Automated folder/RPC/UI regressions are mandatory. No automatic file migration or deletion. See `docs/PROJECT_OUTPUT_LOCATION.md`.

## Session navigation status restoration

- Local/SSH hydration preserves explicit runtime status. Assistant narration and completed tool rows never infer completion; running sessions remain busy until authoritative runtime reconciliation.
- Status revisions and turn epochs prevent delayed history/attach snapshots or errors from overwriting newer live events. Returning to a pane does not replay, stop or submit a task.
- Mandatory regressions cover pane remounts, live terminal events racing attachment, and queued follow-ups racing stale completed attachment. See `docs/SESSION_NAVIGATION_STATUS.md`.

## Windows validation hang safeguards

- The Windows installer workflow serializes consolidated gates and caps Windows CI Vitest pools at two workers without removing suites or changing assertions. An independent 35-minute Actions step deadline bounds validator hangs; the existing 20-minute per-check deadlines remain enforced.
- Named 30-second heartbeats and append-and-close `progress.jsonl` records expose active checks and preserve intermediate start/finish evidence before a final summary exists. A lost hosted runner can still prevent artifact upload; these safeguards do not claim a diagnosed application defect or a successful installer.

## Reviewed native-project edit candidates

- Fixed Ghidra/IDA adapters preview exact function state and create private name/comment/prototype candidates under separate Modify/state/project/pointer approvals. Original target bytes and GUI databases are never replaced. Every candidate is saved and independently reopened at the exact entry before publication.
- Ghidra wraps edits in a native transaction; IDA rollback is isolated unpublished-candidate discard, not a native undo claim. Byte-bound immutable candidate manifests and a separately approved exact-head pointer rollback preserve prior candidate data without replay or in-place patching.
- Bounded metadata/receipts/project inventory reject link/junction escape, stale state/head, partial native save, read-back mismatch, cancelled work and tampered bytes. Read-only profiles block this workflow. Source/API checks and owned protocol fixtures are not actual installed-engine or physical-device validation.
- See `docs/NATIVE_PROJECT_CANDIDATES.md`. Global type-library/struct migrations, automatic GUI replacement, licensed-engine compatibility and KSUN-device validation remain outside the verified scope.

## Managed selected-function native engine workers

- Explicitly opted-in Ghidra/IDA exact decompilation can reuse a bounded native process and private imported project. Two workers per owning SDK process, serialized requests, finite idle/lifetime/deadlines, fixed data-only adapters and held cross-process leases prevent silent concurrent project reuse or automatic replay.
- Reuse binds owning session, canonical target/hash, command/config/script identity, output root and CPU settings; new imports use a byte-verified snapshot. No arbitrary scripts, debugger actions, target execution, license bypass or annotation/type writes are accepted. Pseudocode, mailbox bytes and child diagnostic tails remain bounded.
- Windows batch engine launches reject cmd.exe expansion/control characters before spawn; ordinary spaced paths remain supported.
- Analysis workbench requires separate persistent-process/private-project acknowledgements. Opening/refresh never launches workers. Owned process lifecycle tests are mandatory on Linux and Windows; fixed script contracts are not real IDA/Ghidra validation.
- Guarded function name/comment/prototype candidate editing is implemented above; actual native compatibility and physical KSUN-device validation remain outstanding. See `docs/MANAGED_ENGINE_WORKERS.md` for limits and operational validation.

## Selected device diagnostics and signed live JNI evidence

- A separate `collect_apk_debug` incident binds the workspace APK, installed base-APK hash, explicit device serial and 1–6 approved text tombstone/ANR paths. It does not install, launch, stop, clear logs or instrument an app. Root is off by default and requires an additional exact-plan acknowledgement; KernelSU policy is never changed or bypassed.
- Report reads reject symlinks/traversal/protobufs, check device/file metadata before and after, cap capture bytes and retain exact-package sections only. Historical age, immutable runtime identity and absence of crashes are not inferred. Bounded private hash-checked report files remain outside the source workspace; the journal stores metadata and a bounded summary, with explicit hash-bound viewing.
- The existing signed RegisterNatives collector is reused. Queries reverify the pinned Ed25519 signature, approved capture request, nonce, original APK identity and captured module hashes. Exact class/name/descriptor, optional PID and loader identity preserve ambiguous observations rather than guessing an overload or address mapping.
- Module-relative offsets are not automatically ELF virtual addresses. A unique existing-symbol candidate requires an explicit coordinate acknowledgement and remains an operator-reviewed disk candidate, not loaded-memory equivalence; query/refresh never attaches, resumes or replays a capture.
- Diagnostic report viewing canonicalizes the trusted cache anchor before constructing UUID/hash paths, avoiding Windows drive/ancestor/short-name spelling false positives. Cache/incident links, report links, byte-budget violations and hash/handle identity changes remain rejected; junction and tamper regressions are mandatory.
- Physical KSUN/Frida/ADB validation remains unavailable here. Managed read-only selected-function worker adapters are implemented in the subsequent worker phase above; real installed-engine compatibility remains unverified. Guarded function name/comment/prototype candidate adapters are implemented above; they do not automatically modify GUI databases. See `docs/DEVICE_DEBUG_JNI_EVIDENCE.md`.

## Integrated execution and evidence lab

- Local one-shot, resource-aware task DAGs use durable hash-checked receipts; refresh/owner loss never replays work. Bounded timings, output hashes, drop/incomplete-drain/truncation evidence, stdin/resize and confirmed cancellation reuse the existing process manager.
- Windows resource-limit fixtures handle synchronous throws and asynchronous spawn denials, and require an identical two-process positive control before asserting one-process enforcement; no check is skipped.
- Opt-in Windows suspended-launch Job Objects enforce process count and memory; unsupported/interactive configurations fail explicitly, with no sandbox or Linux-hard-limit claim.
- Debugger launch now requires execution-control confirmation; attaches bind/recheck process start-tokens. IDA/Ghidra project reuse uses cross-process leases and executable/config/script fingerprints; stale leases are not silently stolen.
- Evidence-first plans, package-scoped imported ANR/tombstone/death reports and hash-bound patch review are available in Execution lab. Import/review never installs, resumes, roots or executes a target.
- Managed read-only native workers are implemented above but require installed-engine validation; guarded candidate edits are implemented above; native-engine compatibility and real-device validation remain outstanding. Signed JNI registration queries and selected device-report reads are implemented in the subsequent evidence integration below; disk-to-runtime equivalence is not inferred. See `docs/EXECUTION_EVIDENCE_LAB.md` for contracts and limits.

## Integrated APK incident workflow

- APK incidents use exact workspace APK/package/selected-device identities, one-shot device approvals and durable SQLite stages; reading status never launches or replays work.
- Bounded base-APK identity capture, process-name/PID-scoped log observations and baseline-aware Java/native/ANR crash classification support manual reproduction. Root/Frida, split contents, OS-kill attribution and complete tombstones remain unverified.
- Candidate validation uses a private hash-checked snapshot, real signature verification, separately acknowledged install/execution, post-install identity and explicit operator regression notes. A separate rollback plan verifies recorded installation identities; no automatic uninstall, retry, force-downgrade or data rollback.
- Exact-build mapping candidates and GNU-build-ID/ABI/hash/file-backed native symbol ranges remain honest about provenance, stripped symbols and unresolved overloads.
- Readiness reuses discovery and explicitly approved owned-fixture execution; inventory alone is never engine validation. Artifact evidence offers hash-bound, bounded ZIP member viewing without extraction/execution.
- See `docs/APK_INCIDENT_WORKFLOW.md` for operational limits and fixture-versus-real-device validation.

## Post-integration audit hardening

- File-bound analysis approvals use an in-flight claim and revalidate token, cancellation and expiry after hashing. Concurrent requests cannot reuse approval or resurrect cancelled work.
- Ledger capacity reclaims terminal entries only; pending/approved/running tasks and in-flight claims remain controllable. At capacity new plans fail explicitly instead of silently evicting work.
- Android capture output is preflighted before POST or GET: dedicated workspace child, no symlink directories, and an exact regular ignore-all `.gitignore`. Publication rechecks the same policy; partial staging files are removed on write/sync failure as well as link failure. Ignore rules are not a substitute for encryption, host sandboxing, or protection against force-add/tracked files.
- Android upload obeys the minimum of the signed worker byte budget and the desktop's 16 MiB cap.
- Collector/result validation errors persist a bounded signed terminal failure, without private diagnostics or captured bytes; repeated nonce retrieval never re-executes the sample.
- Terminal UTF-8 truncation uses byte-boundary slicing rather than materializing character arrays/concatenating individual code points; head/tail limits and exact omitted-byte accounting are retained.
- Regression coverage is in the existing approval, Android capture, worker and process-session suites. See `docs/POST_INTEGRATION_AUDIT.md` for scope and limitations.

## Quality gate reliability

- Full workspace typechecks run sequentially with the same `-F '*'` scope to avoid simultaneously loading every TypeScript graph. No workspace, strict check or failed diagnostic is suppressed.
- SDK smoke checks use separate Node/Bun projects, both mandatory, so portable-engine tests have Bun declarations without leaking Bun fetch augmentation into Node-only tests. Long-history OAuth fixtures explicitly constrain user/assistant input roles instead of widening them to tool-role messages.
- SDK CI uses the same pinned Bun 1.3.14 and frozen lockfile as the Windows installer. Downstream lint and test gates remain blocking.
- Functions custom controls use instance-unique React IDs and explicit label/control associations; duplicate view instances are covered by a DOM regression test.

## Build policy

- Produce an **unsigned Windows x64 NSIS `setup.exe`** for private use and testing.
- Do not publish a GitHub Release from the custom installer workflow.
- Record the exact Git commit in `BUILD-INFO.txt` and retain the installer as a workflow artifact.
- Include this ledger in every installer artifact.
- Run `scripts/verify-custom-fork.ts` before every custom Windows build. If a customization is intentionally renamed or replaced, update both the implementation and the verifier in the same commit.

## Preserved customizations

### Combined Android/native investigation integration

- One integration PR includes long-session recovery, capability-authenticated transport, bounded Android discovery, exact DEX bytecode and native function analysis, static JNI export-name correlation, saved-index graphs, and targeted decompiler adapters.
- `analysis_readiness` executes owned DEX/ELF fixtures with the actual installed Androguard/LIEF/Capstone engines. Missing engines stay blocked; installed-version inventory alone is not an execution claim.
- `android_method_code` uses an exact class/name/descriptor. `native_function` selects a unique file-backed executable symbol by exact name or hexadecimal entry address; it returns bounded linear disassembly, not a recovered CFG or runtime proof.
- `investigation_graph` reads validated immutable indexes. Loader pool references and JNI export-name matches remain candidate edges, never observed registration or execution.
- Ghidra/IDA exact-function adapters and JADX single-class cache identities remain approval-gated. Adapter templates and mock routing tests do not substitute for installed engine/license validation.
- Windows builds delete only cached NSIS bundle outputs, compare installed/fresh sidecar hashes, and assert the transport-auth protocol plus baked-in source commit. Installer smoke still requires strict unauthorized denials; no 404-as-success fallback.
- Licensed engines, provisioned isolated runtime workers, unknown-key recovery, full devirtualization and universal deobfuscation are not shipped capabilities. See `docs/COMBINED_ANDROID_TOOLING.md` for requirements and coverage.


### Long-session edit and recovery reliability

- Hub session creation and checkpoint restoration use a bounded ten-minute
  lifecycle deadline instead of the thirty-second metadata deadline. The
  desktop lifecycle waiter has a thirty-second response grace period.
- Desktop command deadlines are selected centrally by action, covering direct
  history-attachment callers as well as chat hooks. Explicit caller deadlines
  still take precedence, ordinary control/status calls remain bounded, and
  model-turn sends remain unbounded until their runtime completion or disconnect.
- Message-edit forks reconcile ambiguous lifecycle timeouts using the existing
  stable operation ID before one bounded retry. Provider authentication failures
  and arbitrary send failures are not classified as retryable edits.
- A failed re-attachment preserves visible messages for the same session without
  mixing another thread's transcript into it.
- Mandatory installer validation includes desktop transport/recovery tests, Hub
  lifecycle-deadline tests, and long-history ClinePass OAuth continuation coverage.
  OAuth recovery retains completed tool evidence rather than replaying the user
  turn. These tests do not claim that revoked credentials can be repaired without
  signing in again.

See `docs/LONG_SESSION_RECOVERY.md`.

### Engineering Control Center

- A dedicated **Engineering** sidebar workspace is separate from normal Cline chat, Notion Functions, and the chat Analysis workbench. Opening it never changes the selected provider, permission profile, active session, or tool auto-approval behavior.
- Its durable control plane stores project profiles, policies, mission DAGs, audit events, and privacy-safe model outcomes in a device-local SQLite database using WAL and foreign-key enforcement.
- Project discovery is local, bounded, and ignores dependency/build directories. It detects languages, package managers, build/test scripts, CI providers, Git state, and known sensitive root files without sending source content to any model or Notion.
- Repository-writing mission roles require isolated worktrees. Mission dependencies are validated for missing references, duplicate IDs, self-dependencies, and cycles before persistence. Planning a mission never executes commands, creates a worktree, or merges code.
- Execution policy evaluation defaults to denied networking, bounded runtime/process counts, and explicit approval. Untrusted scripts and package installation escalate to a sandbox; unknown binaries and debugger work escalate to an isolated VM.
- Git review scoring is transparent and considers change size, sensitive files, dependencies, APIs, migrations, checks, and tests. Model routing ranks only supplied candidates by capabilities, context, observed success, tool reliability, latency, and cost; the user may still lock a provider/model.
- Dependency-ready mission tasks can be claimed by bounded agent IDs. Only the claiming agent can transition a running task, and writer completion requires managed-worktree evidence.
- Managed writer worktrees use dedicated `cline/engineering/*` branches rooted under the Cline data directory. Metadata binds mission, task, agent, repository, base revision, path, and branch. Cleanup refuses to discard dirty or committed work without explicit confirmation.
- **Prepare next agent drafts** creates separate normal-Cline drafts for ready work; it does not submit prompts automatically, replace the user's model, bypass the permission profile, merge, push, or contact Notion.
- The local Git review engine validates the comparison revision and produces deterministic file, line, category, sensitive-path, and bounded symbol evidence. Risk reasons stay visible and are not represented as an AI security review.
- These are orchestration and enforcement foundations. They do not claim that the desktop provisions Windows Sandbox, Hyper-V, or a remote VM by itself; dynamic untrusted execution remains blocked until an attested worker is configured.

Primary files:

- `apps/examples/desktop-app/sidecar/engineering-control-plane.ts`
- `apps/examples/desktop-app/sidecar/engineering-git-review.ts`
- `apps/examples/desktop-app/sidecar/engineering-worktree-manager.ts`
- `apps/examples/desktop-app/webview/components/views/engineering/engineering-workspace.tsx`
- `docs/ENGINEERING_CONTROL_CENTER.md`

### Separate Notion-assisted Functions

- A dedicated **Functions** sidebar page is separate from normal Cline chat and from Customize. It does not replace the selected provider or automatically route ordinary prompts to Notion.
- Every function opens a new, editable chat draft powered by the user's current Cline model. The existing thread remains preserved and unchanged.
- Official Notion MCP OAuth status and connection are available in the feature. Notion workspace tools are requested only by explicitly selected templates and remain subject to the existing MCP and permission boundaries.
- Read templates are non-mutating. Write-oriented page, report, and action-plan templates require the model to show the destination and proposed content before making changes.
- The only setup requirement is a Notion account authorized through OAuth. No dedicated database, automation, integration token, or Custom Agent configuration is required, and no private Notion AI model API is claimed.
- Function sessions use the host-enforced `notion-functions` profile: only tools from the exact official `Notion` Streamable HTTP registration at `https://mcp.notion.com/mcp` plus user-coordination tools are available. Agent-plugin servers and similarly named or substituted endpoints are excluded. Normal sessions keep their existing profile, provider, and capabilities.
- Function sessions disable tool auto-approval, display a persistent Notion Function banner, and preserve proposed writes in the chat transcript for explicit review.
- The hub stores optional default destinations, reusable custom templates, and a bounded local launch audit in browser-local storage. Recent functions can be run again; actual tool calls remain visible in their separate session transcripts.
- A device-local context basket pins existing Notion page names or URLs to function drafts. Manual Notion Agent handoff publishes an approved project-analysis page and returns a copyable Agent instruction; review import reads the resulting page back into a read-only Cline planning session without pretending to invoke the private Agent API.
- Device-local Project Intelligence profiles bind a repository to approved Notion sources, a destination, project instructions, a context TTL, a write policy, a redaction policy, and a hard operation cap without storing Notion credentials or page content.
- The Project Intelligence dashboard launches evidence-backed repository analysis, schema-aware workspace discovery, and official-connection health checks. Claims must cite repository, commit/PR, build, Cline-session, or Notion evidence.
- A visual approval center lets users queue, select, dry-run, and explicitly approve create, update, archive, or relation operations. Every target and database schema is revalidated before execution; operations run sequentially and stop safely on partial failure.
- Manual synchronization recipes cover builds, Cline engineering logs, GitHub work, releases, and technical-debt backlogs. No background synchronization is started.
- Local audits can be exported without prompts or Notion content. Official GitHub Actions now use Node 24 generations, and unrelated reverse-engineering timing tests no longer block the focused Notion installer gate.
- The compiled terminal smoke fixture waits for its explicit input payload and ignores incidental ConPTY control traffic, preventing a resize event from ending an otherwise healthy Windows build.
- The separate **Notion Agent Bridge** packages an explicitly selected local repository into a bounded text-only context package. It respects Git ignore rules, confines paths to the workspace, excludes credential/binary files, redacts likely secrets, hashes evidence, and uploads nothing until the user reviews the complete package and approves the exact Notion operation.
- The separate **Notion Agent review-to-patch pipeline** accepts only reviewable unified Git diffs, verifies approved evidence hashes and citations, performs a local `git apply --check`, requires explicit application approval, writes only to an isolated `notion-agent/*` branch, and provides hash-guarded rollback. It never commits, pushes, merges, or runs Agent-supplied commands automatically.
- Bridge modes support exact published-Custom-Agent discovery and session launch, automatic manual-handoff fallback, same-session follow-ups, temporary-page retention, persistent incremental project memory, and narrowly scoped cleanup. Agent identity is never guessed, and unavailable session capabilities stop safely.
- Approved snapshot hashes are stored locally to show added, changed, unchanged, and removed evidence on later packages. The bridge never schedules background synchronization and never turns Notion into the provider for ordinary Cline chat.
- Explicit first-turn requests that combine a local project with a Notion Agent are routed before session creation into the host-enforced `project-notion-bridge` profile. This profile exposes read-only local inspection, static reverse engineering, and tools from only the exact official Notion MCP registration. It fails session startup when Notion is unavailable, keeps native confirmations enabled, forbids token searches and shell-based upload imitations, and never changes unrelated Cline chats.
- Large projects use an evidence-grounded review loop: a complete typed manifest with stable IDs is followed by bounded sanitized batches sent to exactly one Agent session. Binary files remain metadata-only, and Agent conclusions must cite evidence IDs.
- Quick, Deep, and Forensic review depths control package limits without changing the read-only security boundary. The Agent may request precise additional evidence for at most four rounds; Cline records fulfilled, denied, and unavailable requests before producing a separate consensus report.
- Long-running Agent work uses resumable status polling and a host-owned five-minute MCP request floor. A 60-second transport timeout is not treated as proof that delivery failed, and no manual MCP timeout configuration is required.
- Persistent project memory is optional and uses one visible Notion page containing the sanitized manifest, batch index, checkpoint, consensus, and source session URL. It requires only the connected Notion account, not a pre-created database.
- A combined request submitted to an already-running incompatible session is stopped before further work and its prompt is preserved. Tool boundaries are never silently widened in place.

Primary files:

- `apps/examples/desktop-app/webview/components/views/settings/functions-view.tsx`
- `apps/examples/desktop-app/webview/components/views/settings/sections.ts`
- `apps/examples/desktop-app/webview/components/agent-sidebar.tsx`
- `apps/examples/desktop-app/webview/app/page.tsx`
- `apps/examples/desktop-app/webview/lib/notion-agent-routing.ts`
- `apps/examples/desktop-app/webview/lib/desktop-app-state.ts`
- `sdk/packages/core/src/extensions/tools/permission-profile.ts`
- `sdk/packages/core/src/runtime/orchestration/runtime-builder.ts`

### AI task execution UI

- Polished sticky AI task report with progress, repair, verification, and execution states.
- Typed task lifecycle events persisted in chat metadata.
- Stable step IDs map tool evidence and durations to their exact plan steps.
- Structured step kinds take priority; text-label heuristics remain only as compatibility fallback behavior.
- One active step is enforced, failed or malformed plan updates are ignored, and an older turn's plan is not reused for a new request.
- Copyable task reports for issue reports and debugging.

Primary files:

- `apps/examples/desktop-app/sidecar/context.ts`
- `apps/examples/desktop-app/sidecar/chat-session.ts`
- `apps/examples/desktop-app/webview/lib/chat-schema.ts`
- `apps/examples/desktop-app/webview/lib/task-report.ts`
- `apps/examples/desktop-app/webview/components/views/chat/task-report-panel.tsx`

### Codex-style chat, artifacts, and permissions

- The composer permissions control is interactive in every local chat. It can switch the next run between Read only, Workspace, Workspace + network, and Full access, persists the selected default, and restores the previous value if saving fails.
- Assistant output recognizes code and non-code artifact paths. Code references can include `:line:column` and open at that exact editor location; generated APK/APKS, archives, documents, spreadsheets, presentations, images, installers, and other non-code files open through the operating system's registered handler.
- Right-clicking an inline artifact, workspace file, or completion-summary artifact opens a native context menu with Preview, Open with default app, Show in folder, and Copy path. Left-clicking readable text, image, and PDF artifacts opens the in-app preview without navigating to the internal file route. Show in folder waits for a verified shell launch and uses Explorer's canonical single-argument `/select,"<file>"` syntax to select the exact file on Windows; Finder reveal and Linux containing-directory behavior remain supported.
- The review surface has Last turn, Unstaged, and Staged scopes; per-file and bulk stage/unstage actions; confirmation-gated revert actions; searchable workspace files; direct editor opening; and an Open terminal here shortcut.
- A single artifact path in a fenced Markdown block renders as an actionable artifact card instead of a passive copy-only code block.
- Finished sessions combine declared task artifacts, artifact paths found in assistant output, and changed Git files into one completion summary. Artifact rows open the exact file, while changed-code rows retain direct editor and review-pane actions.
- Remote artifacts remain blocked from local opening until an explicit remote download/preview boundary exists.
- Inline Markdown artifact actions inherit the originating transcript's workspace and environment through a scoped React provider. Preview, system/editor opening and folder reveal use the same context; unchanged memoized Markdown still updates its workspace binding. Copy path remains clipboard-only. See `docs/ARTIFACT_WORKSPACE_CONTEXT.md`.

Primary files:

- `apps/examples/desktop-app/webview/lib/artifact-paths.ts`
- `apps/examples/desktop-app/webview/components/ui/markdown.tsx`
- `apps/examples/desktop-app/webview/components/views/chat/chat-input-bar.tsx`
- `apps/examples/desktop-app/webview/components/views/chat/session-completion-card.tsx`
- `apps/examples/desktop-app/sidecar/commands.ts`

### Permanent Custom AI Instructions

- Visible editor under **Settings → General → Custom AI instructions**.
- Stored in the desktop settings file and retained across app restarts.
- Added to every new local AI session before project and session rules.
- Maximum length: 50,000 characters.

Primary files:

- `apps/examples/desktop-app/sidecar/desktop-settings.ts`
- `apps/examples/desktop-app/sidecar/commands.ts`
- `apps/examples/desktop-app/sidecar/chat-session.ts`
- `apps/examples/desktop-app/webview/components/views/settings/settings-view.tsx`

### Windows reliability

- Cline account sign-in follows the current official desktop WorkOS device-code flow: obtain device authorization, publish the confirmation code and exact verification URL to the webview before browser handoff, open the default browser, poll for completion, and register the resulting tokens with the Cline API. No local callback server is required. Windows URL launching uses `rundll32 url.dll,FileProtocolHandler`, and every sign-in surface retains selectable Open and Copy fallbacks if the OS handoff fails.
- Canonical Windows paths are used for temporary Git worktrees; short-path aliases, slash direction, and case differences do not break cleanup or tests.
- Worktree deletion resolves the repository root, removes the worktree, removes a canonical-path fallback when Git alias matching fails, prunes stale metadata, and independently deletes `refs/heads/cline/<id>`.
- Managed task worktrees persist their identity, source revision/repository, base branch, generated branch, and retention decision. The chat exposes Apply to Local, Create Branch, Open PR, Keep, and explicitly confirmed Discard actions after checking both checkouts for dirty or conflicting state.
- Parallel writing teammates can request an `isolated-writer` workspace. Core creates a handoff-compatible managed Git worktree, routes that teammate's built-in tools and workspace prompt to it, persists ownership across restart recovery, records changed files on async runs, and flags cross-agent path overlaps before handoff. Settled overlap evidence is persisted on the writer child session; the desktop roster blocks handoff visibly, lists conflicting paths, and opens that writer's worktree/session for review and resolution.
- Apply to Local accepts committed work only and aborts a conflicting cherry-pick; Keep prevents session deletion from cleaning the worktree; cleanup remains idempotent and never deletes renamed/user-created branches.
- Sidecar stores are closed during tests and logging fixtures work across platforms.
- Desktop, example VS Code, and repository-root Vitest configurations are native ESM in `vitest.config.mts`; the legacy CommonJS-loaded `.ts` configs must not be restored.
- React image-attachment tests explicitly enable the React `act(...)` environment.
- Desktop Vitest installs a deterministic `ResizeObserver` test polyfill using a config-relative setup path, so both app-local and repository-root test invocations load it reliably. Expected error-path fixtures stay out of CI stderr unless verbose test logging is explicitly enabled, and asynchronous workspace-control effects are wrapped in React `act(...)` rather than suppressed.
- The custom installer requires type safety, the full desktop sidecar regression suite, task reports, focused customization tests, and installer configuration to pass before NSIS packaging begins; it then validates installation, startup, and unsigned binaries.
- Installed-sidecar smoke validation executes the installed `code-sidecar.exe` against an isolated Hub, waits for its ready contract, and checks `/health`; it does not depend on a racy one-time Windows process-name/path snapshot while the sidecar transitions into its detached daemon.
- The installed sidecar readiness gate and the detached Hub daemon both use the same 30-second cold-start window as the desktop host, preventing healthy first launches on slower Windows runners from failing an earlier internal timeout. Once an installer has been collected successfully, the workflow records the smoke outcome and uploads the private test artifact even when a later smoke assertion fails, while retaining the failed job conclusion.

Primary files:

- `apps/examples/desktop-app/sidecar/commands.ts`
- `apps/examples/desktop-app/sidecar/commands-git-worktree.test.ts`
- `apps/examples/desktop-app/webview/components/views/chat/worktree-handoff-bar.tsx`
- `docs/WORKTREE_HANDOFF.md`
- `vitest.config.mts`
- `sdk/tsconfig.json`
- `apps/examples/desktop-app/vitest.config.mts`
- `apps/examples/desktop-app/package.json`
- `apps/examples/vscode/vitest.config.mts`
- `apps/examples/vscode/package.json`
- `apps/examples/desktop-app/webview/lib/image-attachments.test.ts`
- `apps/examples/desktop-app/sidecar/oauth-login.ts`
- `apps/examples/desktop-app/sidecar/oauth-login.test.ts`
- `apps/examples/desktop-app/webview/hooks/use-oauth-user-code.ts`
- `apps/examples/desktop-app/webview/components/oauth-authorization-prompt.tsx`
- `apps/examples/desktop-app/webview/components/views/onboarding/onboarding-view.test.tsx`
- `.github/workflows/build-custom-windows-installer.yml`

### Desktop execution and analysis workbench

- The chat header opens a unified Workspace with Changes, Files, Terminal, and Analysis tabs.
- Integrated terminals reuse `ProcessSessionManager` rather than spawning an unrelated shell path. Starting one requires an explicit host Full Access confirmation; output stays bounded and secret-redacted, and active processes retain stable IDs and conservative recovery.
- The Analysis tab exposes a static-operation allowlist for IDA/Ghidra/JADX workflows, live tool/version discovery, evidence output, verified GUI handoff, and separately confirmed one-shot GDB/LLDB/CDB actions. Arbitrary analysis scripts and unconfirmed execution-control operations are blocked.
- A device-local Analysis Orchestrator prepares immutable task envelopes before execution, enforces workspace path confinement, permission requirements and resource budgets, and issues one-time tokens bound to the exact operation and target. Completed tasks retain only bounded metadata, output paths, and SHA-256 evidence hashes.
- Analysis approvals bind the complete canonical request, including engine, PID, address, target identity, options, execution flags, and timeout. Tokens expire, compare in constant time, and are removed before execution.
- The task ledger is durable, private, bounded, and restart-aware. Evidence uses canonical JSON hashes and can be exported as a reviewable bundle. Filesystem confinement resolves real paths and future parents so symlinks and Windows reparse points cannot bypass workspace boundaries.
- Dynamic execution requires an HTTPS isolated worker with an Ed25519-signed, unexpired capability manifest verified against a pinned public key. The host remains incapable of running dynamic samples.
- The workbench separates Tasks, Analyze, Debug, Terminal, Approvals, Evidence, and Diagnostics. Fast discovery is cached; deep health checks explicitly probe versions, IDA Hex-Rays/idalib, Ghidra/PyGhidra, JADX, Android build tools, and supplemental utilities.
- Interactive process sessions negotiate PTY or Windows ConPTY and fall back to bounded, secret-redacted pipes when the runtime lacks terminal support. Dynamic analysis remains disabled on the host and requires a separately provisioned isolated worker or disposable VM.
- These controls remain capability boundaries, not native Windows containment. Unknown executables require an externally provisioned disposable VM; see `docs/EXECUTION_WORKBENCH.md`.

### Command execution performance

- Command execution favors structured direct argv calls when shell syntax is unnecessary, immediately emits the first output chunk, records duration, time-to-first-output, and output-volume telemetry without command text, and sends the command preview only once instead of repeating it on every progress event. The implemented behavior contract is recorded in `docs/CODEX_LIKE_COMMAND_EXECUTION.md`.
- The SDK exposes a host-scoped `process_session` tool backed by `ProcessSessionManager`, with direct argv start, stable process IDs, owner isolation, cursor-based reads, writable stdin, terminal resize, portable process-tree signals, explicit close, bounded head/tail output, global/per-owner limits, and completed-session expiry. Pipe execution remains the default; `interactive: true` attaches Bun's native Unix PTY or Windows ConPTY boundary and records terminal dimensions. Act and Full Access modes enable it; Plan mode disables it so it cannot bypass the read-only command guard. Existing `run_commands` behavior remains unchanged.
- Active process sessions persist only owner, PID, kernel start token, working directory, and terminal metadata. After an unexpected host restart, exact start-token revalidation restores conservative status/signal control without fabricating lost stdin, terminal, or output handles. PID-only recovery and identity mismatches fail closed.
- The unsigned Windows installer uses Bun 1.3.14 for native ConPTY while the repository's default Bun 1.3.13 remains sufficient for Unix PTY support. The installer workflow compiles and executes a real ConPTY input/resize smoke test before packaging, covering the embedded runtime used by the installed sidecar.
- Every installer artifact includes SPDX 2.3 SBOM metadata; protected tagged releases also receive GitHub build-provenance attestations. Feature and main branch builds share one reusable workflow trigger.
- Agent-started SDK processes withhold credential-bearing inherited and override environment variables unless the host explicitly grants an exact name. Known and pattern-detected secrets are redacted before streamed output, final results, errors, detached logs, or process-session buffers retain them. The policy and its remaining security boundary are documented in `docs/PROCESS_ENVIRONMENT_SECURITY.md`.
- Codex-grade process sessions, durable task state, worktree handoff, additive permission profiles, parallel orchestration, telemetry-gated PowerShell optimization, and optional scoped computer use must follow the phased contract in `docs/CODEX_PARITY_ROADMAP.md` and GitHub issue #20.
- Windows `run_commands` records a local, privacy-safe rolling baseline containing only execution mode, duration, time-to-first-output, output volume, success, and timestamp. It stores no command, arguments, cwd, environment, output, or identity. The prewarmed PowerShell worker remains disabled until at least 20 direct and 50 shell samples show both a 150 ms startup disadvantage and a 60% shell-startup share; a diagnostic command reports `collecting`, `not_recommended`, or `eligible` without enabling optimization.

Primary files:

- `sdk/packages/core/src/extensions/tools/schemas.ts`
- `sdk/packages/core/src/extensions/tools/definitions.ts`
- `sdk/packages/core/src/extensions/tools/executors/bash.ts`
- `sdk/packages/core/src/extensions/tools/executors/process-session-manager.ts`
- `sdk/packages/core/scripts/process-session-terminal-smoke.ts`
- `sdk/packages/core/src/extensions/tools/runtime.ts`
- `sdk/packages/core/src/extensions/tools/executors/process-environment-policy.ts`
- `docs/CODEX_LIKE_COMMAND_EXECUTION.md`
- `docs/PROCESS_ENVIRONMENT_SECURITY.md`
- `docs/CODEX_PARITY_ROADMAP.md`

### Additive permission profiles

- General settings expose host-enforced `read-only`, `workspace`,
  `workspace-network`, and `full-access` profiles for new local sessions, with
  a complete capability matrix that explicitly shows web/network and browser
  access for Full Access and the read-only browser boundary for Workspace + network.
  `full-access` is the desktop default when no preference has been stored,
  keeping the enforced boundary aligned with the existing Full Access/Yolo
  composer contract; restricted profiles remain explicit choices, and callers
  may still supply custom capability profiles through the SDK.
- Enforcement runs before approval and tool execution and is inherited by
  delegated agents.
- Restricted profiles fail closed for unclassified plugin/MCP tools and keep
  network, external-device/debugger, process-session, command, and file-write
  capabilities independently controllable.
- The preference is persisted in global settings and resolved by the sidecar,
  so a webview client cannot silently weaken it while starting a session.
- Capability profiles are not described as an operating-system sandbox; native
  filesystem and network containment remains separate follow-up work.

Primary files:

- `sdk/packages/core/src/extensions/tools/permission-profile.ts`
- `sdk/packages/core/src/extensions/tools/permission-profile.test.ts`
- `sdk/packages/core/src/runtime/orchestration/runtime-builder.ts`
- `sdk/packages/core/src/services/global-settings.ts`
- `apps/examples/desktop-app/sidecar/chat-session.ts`
- `apps/examples/desktop-app/webview/components/views/settings/settings-view.tsx`
- `docs/PERMISSION_PROFILES.md`

### Durable task execution

- Plan-tool updates are normalized by a host-side durable task state machine rather than trusted as presentation-only data. It enforces stable step identity, one active step, valid task transitions, terminal-state protection, and a repair/verification gate before work can advance past a failed or blocked step.
- Each session stores an atomic, versioned `task-state.json` artifact alongside its session data. Starting or re-attaching a session restores the canonical plan and active step so subsequent tool evidence remains associated after a desktop restart.
- Typed `plan.updated` events expose the canonical task state and transition history plus optional acceptance criteria, validation commands and results, owning agent, worktree, checkpoint run, artifacts, timestamps, repair attempt limits, skip reasons, and rollback metadata.
- In Full Access or explicitly auto-approved sessions, newly completed local steps execute their declared validation commands sequentially with bounded runtime and no retained command output. A failure marks the step failed, records only a sanitized status, and skips later commands until repair.
- Every skipped step requires a non-empty reason. Restoring a workspace checkpoint rewinds task steps associated with that checkpoint or a later run, and records the rollback in the task transition history.
- Sessions without `task-state.json` migrate the newest compatible projected `plan.updated` report once, then use the canonical artifact. Existing projection-only reports remain readable.
- See `docs/DURABLE_TASK_EXECUTION.md`. The unsigned installer workflow and private artifact-only release policy are unchanged.

Primary files:

- `apps/examples/desktop-app/sidecar/task-state-machine.ts`
- `apps/examples/desktop-app/sidecar/task-validation.ts`
- `apps/examples/desktop-app/sidecar/context.ts`
- `apps/examples/desktop-app/sidecar/chat-session.ts`
- `apps/examples/desktop-app/webview/lib/chat-schema.ts`
- `apps/examples/desktop-app/webview/lib/task-report.ts`
- `docs/DURABLE_TASK_EXECUTION.md`
- `docs/CODEX_PARITY_ROADMAP.md`

### Parallel-agent desktop controls

- Persisted subagent and team-task children appear in the parent session's agent
  roster with status, assigned task, latest activity, model, and transcript.
- Team-task rows expose host-controlled Stop, Guide, and Retry actions. These
  target one teammate without aborting the lead session.
- Guide uses the existing team mailbox and live steering boundary; Retry queues
  the latest failed, cancelled, or interrupted task with conversation
  continuity.
- Control requests are validated at the sidecar, Hub, root-session, and
  child-agent boundaries. Running synchronous `spawn_agent` and configured-agent
  children register host-owned control handles, expose Stop and Guide without
  aborting the lead, consume one-shot steering messages inside their own loop,
  and remove the handle atomically when the child settles. Retry remains limited
  to durable team runs; completed synchronous tool calls must be spawned again by
  the lead rather than replayed outside the parent tool contract.

Primary files:

- `sdk/packages/core/src/extensions/tools/team/multi-agent.ts`
- `sdk/packages/core/src/runtime/host/local-runtime-host.ts`
- `sdk/packages/core/src/hub/server/hub-server-transport.ts`
- `apps/examples/desktop-app/sidecar/commands.ts`
- `apps/examples/desktop-app/webview/hooks/use-session-agents.ts`
- `apps/examples/desktop-app/webview/components/agent-header.tsx`

### Specialized tools

- Android automation includes device selection, screen metadata, UI hierarchy, validated touch/swipe/key/text actions, foreground-package guards, and before/after screenshot evidence.
- Unrestricted `adb shell` is intentionally available for already-authorized devices and requires `acknowledge_risk: true`; see `docs/ANDROID_DEVICE_AUTOMATION.md`.
- Reverse-engineering and Smali workflows, with cross-platform IDA/Ghidra discovery, executable/version/capability reporting, version-and-option-aware cache reuse, complete output draining, process-tree cancellation, and verified GUI startup.
- Windows reverse-engineering discovery refreshes persisted tool environment variables and performs a bounded two-level search under `Documents`, `Program Files`, and `%LOCALAPPDATA%\Programs`; it does not scan arbitrary drive roots.
- IDA Hex-Rays batch decompilation uses a generated bounded IDAPython script, verifies a non-empty pseudocode artifact, and never passes output paths through the incompatible `-Ohexrays:<path>:ALL` form.
- A separate opt-in `live_debugger` tool provides explicitly acknowledged, bounded, one-shot GDB/LLDB launch and attach workflows with command-safe breakpoint and address validation; see `docs/LIVE_DEBUGGING.md`.
- The forensic reliability boundary keeps reverse-engineering string filters literal by default, rejects unsafe or oversized opt-in regular expressions, requires acknowledgement for output outside managed cache/temporary roots, resolves future outputs through real parents to block symlink or reparse-point escapes, and records SHA-256 evidence for bounded generated artifacts. Live-debugger execution control requires a second confirmation, while Android package changes and log deletion have separate confirmations and Android text output uses the shared secret redactor. See `docs/FORENSIC_TOOL_RELIABILITY.md`.
- Advanced forensic reports combine executable/archive structure, bounded categorized indicators, findings, and hashed JSON or print-ready HTML output. Each completed stage is persisted by artifact hash so interrupted reports resume without repeating finished inspection, string, or APK-security stages. APK reports add `apksigner` scheme/certificate evidence and bounded `aapt2` permission/exported-component signals when those tools are installed.
- `live_debugger inspect_dump` validates Windows `MDMP` metadata without launching the target and optionally uses CDB for bounded `!analyze -v` and stack evidence with a validated, redacted symbol path and local cache. See `docs/ADVANCED_FORENSIC_ANALYSIS.md`.
- APK comparison improvements.
- Codex-compatible tool calls and binary attachment handling.

Primary files:

- `sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts`
- `sdk/packages/core/src/extensions/tools/executors/supervised-process.ts`
- `sdk/packages/core/src/extensions/tools/executors/live-debugger.ts`
- `docs/LIVE_DEBUGGING.md`
- `docs/FORENSIC_TOOL_RELIABILITY.md`
- `docs/ADVANCED_FORENSIC_ANALYSIS.md`

### Scoped Windows computer use

- Desktop settings provide an explicit opt-in and exact absolute `.exe` allowlist. The host refuses every control-session start until enabled, and restricted permission profiles block the tool.
- `computer_use` supports owner-agent-scoped start/list/observe/click/type/key/scroll/wait/stop operations for one foreground allowlisted Windows application. Child agents cannot start control; owners may issue and revoke leases bounded by exact agent ID, expiry, and action count.
- Windows UI Automation selectors are preferred over coordinate fallback. Every action revalidates the foreground executable; password controls, protected Windows security processes, arbitrary key combinations, and clipboard typing are denied.
- Actions remain pinned to the original process ID, coordinate targets must stay inside the foreground window, and state-changing actions can require a bounded selector to appear or disappear before success is reported.
- Sessions are bounded to 200 actions and 15 minutes. Screenshot evidence is stored under the private Cline data directory, capped at 10 images per session, and deleted on stop or takeover.
- Local computer-use diagnostics persist aggregate counts and durations only; they exclude executable paths, titles, selectors, typed text, screenshots, and identities.
- Windows installer testing force-terminates timed-out process trees instead of waiting forever, then runs a deterministic WinForms fixture through real UI Automation when the Windows host exposes an interactive accessibility tree. Noninteractive hosted runners retain the foreground-scope assertion and report the action portion as a capability skip, without changing the workflow or publishing a release.
- The desktop displays a persistent Computer control active banner with a host-owned Stop and take over action.
- Structured tools, MCP, browser protocols, and the specialized Android/reverse-engineering tools remain preferred.

Primary files:

- `sdk/packages/core/src/extensions/tools/schemas.ts`
- `sdk/packages/core/src/extensions/tools/definitions.ts`
- `sdk/packages/core/src/extensions/tools/permission-profile.ts`
- `apps/examples/desktop-app/sidecar/computer-use-manager.ts`
- `apps/examples/desktop-app/sidecar/computer-use-metrics.ts`
- `apps/examples/desktop-app/scripts/computer-use-windows.test.ts`
- `apps/examples/desktop-app/sidecar/desktop-settings.ts`
- `apps/examples/desktop-app/webview/app/page.tsx`
- `apps/examples/desktop-app/webview/components/views/settings/settings-view.tsx`
- `docs/SCOPED_COMPUTER_USE.md`

### Structured repository and diagnostics

- The desktop exposes a native in-app GitHub connection through the signed-in Cline account and the built-in Composio GitHub connector. Connect GitHub starts the browser OAuth flow without requiring GitHub CLI; connected repositories, issues, pull requests, reviews, and related GitHub tools are loaded into new agent sessions, while local repository mutations remain permission-gated.

- The desktop exposes a typed `repository` tool for bounded Git status, diff,
  log, branch, commit, fetch, fast-forward pull, non-force push, and GitHub CLI
  status operations. Local writes and remote operations require separate
  explicit confirmations; refs, remotes, and relative paths are validated.
- Read only permits repository inspection, Workspace permits local changes, and
  network-enabled profiles permit confirmed remote operations. Plan mode does
  not expose the tool, so it cannot bypass the read-only command guard.
- Settings includes a Diagnostics center for sanitized Hub/app/permission and
  session-count health, PowerShell evidence state, sanitized report copying,
  and stopping stale browser sessions. Reports exclude prompts, credentials,
  URLs, typed browser content, and workspace/repository paths.
- Native Windows sandboxing is intentionally not part of this package.
- See `docs/STRUCTURED_REPOSITORY_AND_DIAGNOSTICS.md`.

Primary files:

- `apps/examples/desktop-app/sidecar/repository-tool.ts`
- `apps/examples/desktop-app/sidecar/repository-tool.test.ts`
- `sdk/packages/core/src/extensions/tools/schemas.ts`
- `sdk/packages/core/src/extensions/tools/definitions.ts`
- `sdk/packages/core/src/extensions/tools/permission-profile.ts`
- `apps/examples/desktop-app/webview/components/views/settings/settings-view.tsx`
- `docs/STRUCTURED_REPOSITORY_AND_DIAGNOSTICS.md`

### Lightweight built-in browser

- The Windows desktop exposes a structured `browser` tool backed by an
  isolated Tauri WebView window and the installed WebView2 runtime. It does not
  bundle a second Chromium distribution or launch the user's normal Edge
  profile.
- Browser sessions are owner-scoped, bounded to eight windows, expire after 30
  minutes of inactivity, and reject child-agent session creation.
- The browser supports navigation, metadata-only `page_info` diagnostics,
  visible interactive-element inspection, semantic click/type/select/check
  actions, bounded waits, and screenshots.
  Role, accessible name, text, and test ID are preferred over CSS.
- Only HTTP(S) destinations are accepted. Password fields are denied, and
  sensitive-looking submission, purchase, publication, deletion, acceptance,
  and booking controls require explicit consequential-action confirmation.
- Permission profiles classify the browser as a network capability.
  Workspace + network permits navigation and inspection but not state-changing
  actions; Full Access permits interaction.
- APIs, MCP, and `fetch_web_content` remain preferred. Structured browser
  control comes before screenshot interpretation and generic `computer_use`.
- See `docs/BUILT_IN_BROWSER.md`.

Primary files:

- `sdk/packages/core/src/extensions/tools/schemas.ts`
- `sdk/packages/core/src/extensions/tools/definitions.ts`
- `sdk/packages/core/src/extensions/tools/permission-profile.ts`
- `apps/examples/desktop-app/sidecar/browser-manager.ts`
- `apps/examples/desktop-app/webview/lib/built-in-browser.ts`
- `apps/examples/desktop-app/src-tauri/src/built_in_browser.rs`
- `docs/BUILT_IN_BROWSER.md`

### Objective Codex-parity benchmark

- A versioned weighted task corpus covers coding, execution, durable/parallel
  orchestration, Generic Computer Use, restricted-profile escape attempts, and
  background automation.
- Candidate and reference runs must use the same corpus and a documented
  comparable environment before the tool reports a relative percentage.
- Missing scenarios reduce coverage and score rather than being silently
  omitted. Without a reference run, the report deliberately provides readiness
  only and does not fabricate a Codex percentage.
- Results retain only numeric scores, durations, intervention counts, and
  optional aggregate token/cost units—never prompts, output, paths, secrets,
  screenshots, typed text, or identity.

Primary files:

- `evals/parity/corpus.v1.json`
- `evals/parity/codex-parity.ts`
- `evals/parity/codex-parity.test.ts`
- `evals/parity/README.md`

## Advanced analysis release candidate

- The existing approval-gated Analysis workbench supports a fixed embedded Python worker for structural APK/DEX/ELF inventory, DEX indexing, native range disassembly, Z3/Triton expression analysis, QBinDiff BinExport matching and data-only transformation receipts.
- Credentials are filtered, output/time/input budgets enforced, reports are hash-bound and exclusive-create, targets never executed. Optional dependencies are installed separately through a host-owned absolute CLINE_RE_PYTHON path.
- Distribution discovery is not functional verification. QBDI, FlowDroid, Remill and advanced CFG passes, licensed JEB/IDA and research recovery actions remain blocked. The complete recommendation set is not delivered by these contracts.
- No universal decryption, whole-function equivalence, confirmed JNI graph, notebook platform, runtime-worker provisioning or Windows containment is claimed. Windows installer validation remains mandatory.

## Evidence graph and durable static notebooks

- Advanced graph_build and graph_query operations construct artifact/class/method/native-symbol/member graphs from bounded imported evidence, with stable content-derived IDs, provenance hashes, candidate edges and explicit unresolved calls. Imported reports remain untrusted data, not authenticated facts or instructions.
- notebook_validate preflights a strict static-cell DAG and confines canonical inputs to the approved notebook folder. notebook_run checkpoints serial execution in the managed private analysis cache, validates input hashes, blocks dependent failures and resumes unchanged completed cells using engine/configuration/dependency fingerprints.
- No notebook executes scripts, target binaries or runtime actions. No graph infers verified JNI bindings, lifecycle taint or whole-program semantics. Hashes do not authenticate reports against privileged local tampering.

## Bounded Miasm static IR

- Advanced lift_native_ir and deobfuscation_pass use Miasm for bounded one-basic-block IR lifting and expression simplification. Explicit architecture/range, instruction/generated-block caps, original/simplified IR and limited coverage are preserved. No target executes or native patch is applied. This does not implement Remill, IDA microcode passes or full devirtualization.

## Host-gated authenticated decryption

- Advanced decrypt_blob uses cryptography AEAD for AES-256-GCM and ChaCha20-Poly1305 with an existing host-owned raw 256-bit key, explicit nonce/tag/AAD, optional bounded prefix transforms and recovered-content structural analysis.
- CLINE_RE_ALLOW_DECRYPTION=1, an absolute trusted CLINE_RE_PYTHON and absolute CLINE_RE_PRIVATE_KEY_FILE are required. Key material never enters tool parameters, command-line arguments, reports or persisted notebook cells. POSIX ownership/mode and raw key length are checked; Windows ACLs remain a host responsibility.
- Desktop plans require authorized-decryption and sensitive-plaintext-processing acknowledgments with moderate risk. Auth failures retain no recovered plaintext. Successful reports contain provenance/structure only, not binary plaintext exports; temporary parser inputs are privately created and deleted without a secure-erasure claim.
- Decryption is not exposed as a notebook cell. No key guessing, protected-service access, target execution or encryption bypass is implemented.

## Required validation

Before an installer build, preserve and run the checks encoded by `.github/workflows/build-custom-windows-installer.yml`:

1. `bun scripts/verify-custom-fork.ts`
2. SDK build and desktop type-check
3. Desktop sidecar regression suite
4. Windows installer configuration test
5. AI task-report tests
6. Focused customization tests
7. Unsigned NSIS packaging and artifact upload

Do not hide a new regression by weakening assertions or making a required customization check non-blocking. Fix the implementation or update the expected contract only when behavior changes intentionally.

## Rules for future AI assistants

1. Read this file, `/AGENTS.md`, and `/.github/copilot-instructions.md` before changing desktop, sidecar, task-report, tool, or installer behavior.
2. Preserve these features unless the user explicitly asks to replace or remove one.
3. Commit every durable source change to the repository before triggering a build.
4. Never rely on local-only files, an uncommitted diff, generated `dist/` output, or a workflow workspace as the only copy of a customization.
5. Update this ledger and `scripts/verify-custom-fork.ts` in the same commit when adding, replacing, renaming, or intentionally removing custom behavior.
6. Run the relevant focused tests, desktop type-check, repository lint, and custom-fork verifier.
7. Keep the personal installer unsigned and artifact-only; do not create a release unless the user explicitly changes that policy.

## Consolidated blocking validation

- `bun run validate:advanced` verifies preservation and builds SDK prerequisites before running all previously required desktop/core checks with bounded parallelism (default 2; maximum 4). It never counts a blocked prerequisite as passed and collects every required check failure in a machine-readable summary and separate logs.
- Required sidecar, installer configuration, task report, chat UI, customization and focused SDK safety suites remain blocking. The Windows workflow then performs its existing process smoke, NSIS build, installation/startup smoke and verified artifact upload. No release or merge is enabled.
- `bun run validate:advanced --engines` additionally requires a trusted absolute CLINE_RE_PYTHON and runs the real static engine, Miasm and cryptography fixture corpora. Source-only gates report these optional engines as not requested, not validated; the Windows installer now additionally provisions the pinned interpreter and invokes --engines. A passed consolidated source test is not proof of installer or whole-platform completion.

- Validation evidence upload explicitly includes the scoped hidden .cline-validation folder and fails if no report is present; it never uploads other hidden repository files.

- Installed-sidecar smoke uses a bounded 45-second Hub bootstrap deadline, covering the SDK's existing 30-second startup contract plus cold-launch overhead. A regression guard prevents reverting to a premature deadline. Readiness, health, restart and database uniqueness assertions remain blocking; no failed startup is accepted or automatically retried.

## V4 program evidence, authoring and worker transport

- cfg_analyze computes bounded imported CFG reachability, dominators/postdominators, natural loops, SCCs and irreducible regions. trace_slice and trace_taint compute explicit-location dependencies and overwrite-aware input influence from imported traces. These are not runtime tracing, semantic proofs, full unflattening or devirtualization.
- Static notebook and evidence graph document authoring validates strict data-only schemas, DAGs and confined names. Saving requires an explicit write acknowledgment and never silently overwrites a file; hash-guarded updates use cooperative locks. Saving never executes analysis.
- Isolated-runtime submission is bound to an exact approved worker endpoint, Ed25519 key fingerprint, request and artifact hash. Receipts bind a fresh nonce and matching identity; HTTPS redirects, oversized bodies and undeclared QBDI capability fail closed. Worker egress is disabled. This is a client protocol, not a provisioned QBDI worker or hardware isolation proof.
- Bridge hardening is reconciled from its durable patch: stable path-bound evidence IDs, serialized UTF-8 budgets, redaction-before-budgeting, collision-safe Markdown fences, fail-closed Git inventory, shared depth presets and a read-only structured Git allowlist.
- Remaining Remill/JEB/D810, automatic VM provisioning, full native recovery and key recovery are not implemented. No merge or release is authorized by this source update.

- V4 document authoring uses separate save/run approval, a 1 MiB limit and hash-guarded updates. Runtime submission has independent upload/execution acknowledgments, exact worker/artifact binding, strict Ed25519 keys and bounded signed receipts.
- Installer packaging requires six real portable-engine SDK-to-worker tests, not merely package presence. Python and these dependencies are CI-only and not bundled in the installer. No live QBDI backend, licensed adapter, full unflattening or VM provisioning is claimed.

### V4 publication and responsive authoring validation
- New notebook/graph documents are fully staged, synced, and published atomically without overwrite using a same-directory hard link. This requires a hard-link-capable filesystem (normally NTFS on Windows); unsupported filesystems fail closed. This does not claim protection against privileged or non-cooperating actors, Windows reparse races, or stronger ACLs than the workspace provides.
- Both input and pretty-printed saved documents must fit the 1 MiB UTF-8 byte budget. Nine required document-store regressions cover complete publication, no-overwrite, explicit approval, reviewed hash updates, stale content, path confinement, graph integrity, serialized expansion, concurrent publication and foreign-lock preservation.
- Notebook preparation actions wrap with an explicit gap at narrow widths. The authoring tests require that container while preserving separate file-write and exact analysis approvals. All previous source, real Windows engine, terminal, installer and installed-app gates remain mandatory.

## Android static investigation foundation

- `artifact_discovery`, `android_relationships` and `android_method` use a reviewable, fixed stdlib-only Python worker, embedded deterministically in the SDK. They never execute target code. Python must be available; optional engines are not required for these three actions.
- Bounded ZIP/APK, gzip and zlib traversal inspects names independently of extensions and carves embedded standard DEX (035–040) from opaque/native inputs. DEX candidates must pass Adler32/SHA1, header/table/map checks and bounded method/class-data/code-item range checks before structured metadata is emitted. This is not full bytecode verification. Compact DEX, v041, arbitrary encryption and unsupported formats are not silently promoted to valid DEX.
- Source hashes, parent identities, member lineage and byte offsets survive discovery. Method selectors require the exact class descriptor/name/prototype and report ambiguity across artifacts. Loader references are explicitly reference-only; JNI mangled names are derived candidates, not confirmed exports or runtime bindings. ELF discovery is signature-only; structural native evidence remains a separate `native_inventory` operation.
- Successful/partial investigations save immutable, private, content-addressed JSON indexes using atomic no-overwrite publication. `investigation_query` performs bounded literal-text/kind/ID queries with pagination, preserving incomplete coverage and candidate status. Hashes detect corruption, not privileged tampering. Windows ACL/reparse protections remain host responsibilities; hard-link-capable storage is required.
- The SDK fixture corpus, real supervised worker, schema limits, index concurrency/integrity and embed-parity tests are blocking in consolidated validation. Existing recovery, engine, terminal, installer and installed-sidecar gates are retained.
- This is the static foundation, not all advanced recommendations. Full JNI registration correlation, decompiler/function-target adapters, runtime DEX capture, transform proof pipelines, live taint/CFG recovery, sandbox provisioning and general devirtualization are not delivered. See `docs/ANDROID_INVESTIGATION.md` for usage and remaining work.

## Authenticated desktop command transport

- Every `/transport` upgrade requires the per-process sidecar capability, regardless of trusted or absent Origin. The existing `approval_token` query is retained for the native/dev WebSocket bootstrap; authenticated originless integrations may also use a bearer header. Duplicates, conflicting credential sources, missing/empty/oversized tokens fail closed with constant-time equality for equal-length inputs.
- WebSocket handlers separately require authenticated, registered connections before command dispatch or event replay. Interactive tool-prompt approval authority still requires the trusted browser Origin; possessing the capability is a privileged command credential, not a granular integration permission profile.
- `/shutdown` and `/telemetry/error` require bearer authentication plus the existing Origin policy. HTTP query credentials are not accepted. Health and marketplace catalog remain public and contain no capability. Authenticated telemetry input is streamed with a 64 KiB ceiling; diagnostic capability/query/bearer redaction occurs before field limits and telemetry capture.
- Native shutdown remains the existing child-process signal/termination path, not HTTP. Native ready-line token handoff and `dev:headless` ephemeral-token handoff are preserved. Manual split development must explicitly share the sidecar capability with the web endpoint; there is no insecure tokenless fallback on the server.
- Installed-sidecar smoke now denies tokenless transport/shutdown, executes one authenticated diagnostic command and rejects the prior automatically generated capability after restart. Explicit token overrides must be rotated by their operator. Required authentication, recovery, optional-engine, terminal, installer and installed-app checks remain blocking. No TLS, OS sandbox, protection against same-user memory/log access, or comprehensive desktop security audit is claimed.

## Durable advanced investigation and isolated Android capture

- Workspace-scoped SQLite investigations persist checkpoints, questions, artifact/request/result hashes, bounded cross-language summaries and integrity chains independently of chat. Stale writes fail; forks inherit metadata, never executable jobs. Evidence truncation counts are explicit. Signed worker observations remain reports, not hardware attestation or runtime class-loader identity proof.
- The optional fixed Android Frida worker observes supported Java DEX loaders and JNI registrations under explicit upload/execution/capture-write approval. Exact pinned worker identity, nonce and artifact binding are verified before private content-addressed capture and original signed receipt publication. Output is bounded; duplicate/expired/interrupted nonces never automatically replay. GET recovery requires prior approval and leaves original task failure status visible.
- Existing targeted native/decompiler adapters and expression/IR/CFG tools link evidence and model-limited transformation records into investigations without rewriting originals. Whole-method equivalence, automatic key recovery, generic devirtualization, native module hash capture and VM provisioning remain unimplemented. Live Android capture needs operator-provisioned Linux/Android isolation and separate device tests; owned protocol fixtures and bundle compilation are not device validation.
- Consolidated checks require investigation-store, Android client and investigation UI regressions. Windows gates additionally require owned worker protocol fixtures and the pinned Frida bundle build while preserving real portable engines, terminal, unsigned installer and installed-app checks. See docs/ADVANCED_INVESTIGATION_INTEGRATION.md and workers/android-capture/README.md. No merge or release is enabled.

- Terminal process completion keeps the PTY/ConPTY handle open for a bounded 250 ms trailing-output drain after exit notification, without respawning the child. The regression fixture deliberately emits after exit notification and still requires TTY/input/resize evidence. Real Windows terminal smoke remains mandatory; this is not an unlimited EOF-drain guarantee.

## Confirmed CI blocker repair after advanced integration

- Installed restart acceptance verifies the authenticated backend value and waits for the settings textbox to become enabled after asynchronous hydration before comparing its exact value. Missing/wrong persisted values and failed hydration still fail; there is no sleep-only pass or changed production setting behavior.
- Launch diagnostic ancestry checks process creation times at every edge, rejecting recycled parent PIDs. Only bounded candidate metadata for the owned app and relevant WebView/sidecar/console processes is read; only current descendants are retained. No raw command lines or diagnostic-based foreign process control are added.
- The native Windows argv fixture's observed 30,265 ms invocation timeout (internal phase not established) gets a bounded 60-second process guard and structured exit/signal/kill/output diagnostics. Real argv, Job Object assignment and process-limit enforcement assertions remain mandatory; this changes no production resource limit.
- E2E dependency setup invokes the locked local Playwright CLI under Node rather than resolving through npm. Cold installs have a six-minute total guard, five-minute Chromium process limit, 60-second VS Code network-idle limit, named pending/failure diagnostics and Chromium cancellation. Success requires both installs, and the real E2E suite is unchanged.
- The no-session singleton fixture exposes an empty session list to the real search index and uses an owned search database. Startup failures drain their actual cause before exit; the parent waits for stderr pipe close when reporting early failure. Real competing-owner/crash-successor assertions remain unchanged. The previous Windows successor exit still requires confirmation in a fresh Windows run; a warning alone is not treated as a proven root cause.


- A Windows receipt showed the owned private WebView2 profile was used but the requested remote-debugging argument was absent. An explicit `CLINE_INSTALLED_ACCEPTANCE=1` launch now supplies validated loopback-only browser arguments and the absolute private profile through Tauri's native main-window configuration before window creation. The pinned Wry default arguments remain intact. Without the exact opt-in, native configuration is unchanged; invalid fixture options fail startup. No permanent debugging port, arbitrary argument forwarding, IPC/authentication bypass, or substitute webview is added. Five pure Rust launch-option fixtures are required in Windows installer CI; actual installed UI acceptance remains mandatory.

- In-memory SQLite (`:memory:`) performs no filesystem setup. Real file databases create their absolute parent path and propagate failures; no `EEXIST`/permission error is swallowed. Node path-boundary regressions and a repeated native Bun memory-database fixture are blocking, preserving real singleton crash/successor tests.
- Installed WebView acceptance runs its owning TypeScript harness under native Node's type stripping, using shell-free child-process launch with explicit WebView2 environment and visible windows. The CDP port is allocated after isolated Hub startup, immediately before each app launch. Bounded, redacted launch receipts capture startup output, connection failures, and read-only metadata for owned descendants (never raw command lines or foreign-process control). Real Node child fixtures verify environment handoff, failed spawn handling and bounded output. A missing CDP endpoint remains a failure; no simulated/dev webview fallback or production debugger configuration is added.

- Installed WebView acceptance consumes the exact installed app/sidecar paths validated by the preceding hash/startup smoke instead of repeating the quoted registry `InstallLocation` lookup. The UI step requires absolute existing files and its success remains mandatory for verified artifacts.
- Pinned UPX/Gitleaks installation allows at most three attempts with bounded backoff for transient Chocolatey feed failures; exhausted retries still fail. Owned PowerShell fixtures verify immediate success, recovery and exhaustion without network/install actions. Consolidated evidence upload runs only when its validator started; missing evidence after a started validator remains an error.

- The installed Windows build's Python corpus uses the explicit `windows-portable` pin-set profile. Every shipped engine remains execution-tested and blocking; unshipped Triton/QBinDiff receive required missing-engine boundary tests rather than success claims or skips. The default full profile keeps their real execution tests. LIEF uses a hash-verified owned ELF fixture across platforms instead of skipping the Linux executable fixture on Windows.
- Transform helpers resolve their default expansion budget at call time, avoiding stale Python default-argument capture. The public worker reduced-budget regression and exact/over-budget helper tests remain required; production byte ceilings are unchanged and no caller-selected transform budget is exposed.

- PR #105's host execution diagnostics are excluded from the strict Android v1 evidence manifest and its content hash. Identical static evidence still reuses the same immutable index across different jobs; diagnostics remain available on the execution result and in their separate receipt store. Regressions enforce reuse, diagnostic exclusion and rejection of unexpected stored-manifest fields without relaxing schema, integrity or no-overwrite checks.
- The upstream JetBrains integration dispatch runs only in `cline/cline` with its configured App ID, retaining trusted-author/comment authorization and adding HTTP failure detection. Personal desktop forks do not require credentials for `cline/intellij-plugin`. Desktop, SDK, Windows regression and installer acceptance gates remain mandatory. Because the integration uses `pull_request_target`, an existing run evaluates the base branch workflow; this PR's guard takes effect once that workflow reaches the base branch.

- The Python Android worker now closes SQLite connections deterministically after both commit and rollback. SQLite's native connection context manager alone does not close a connection; open handles caused Windows fixture cleanup to fail with WinError 32. New regressions require closed handles and rollback on exceptions; no cleanup failure is suppressed.
- Real Hub shutdown tests probe the exact Bun executable they launch, then require the fixture to report that same runtime version. The obsolete Bun 1.3.13 string assertion is removed, not the exact-version check, authenticated shutdown, forced-exit evidence, discovery cleanup or 5-second exit bound.
- Real Hub shutdown identity tests are now an additional blocking consolidated validation stage. Existing engine, terminal, installer and installed-app gates stay required. New exact-head Windows results remain necessary; Linux fixtures cannot establish Windows installer success.

## Remaining practical runtime safeguards in the same integration

- Native disk capture is opt-in and requires a signed native capability before upload. A fixed bounded reader permits at most four package-scoped .so paths, 2 MiB each within the shared 8 MiB capture budget. Captured disk ELF hashes bind signed JNI module-relative observations; this is not proof of the loaded memory image, structural ELF validity or system-library capture. Both desktop and worker reject plaintext artifact formats without their independent capture consent.
- JNI observations include the approved capture nonce, process, class handle and best-effort bootstrap/class-loader identity hash. Cross-session observations are rejected. Class-loader hashes may collide and handles are transient, so correlation never becomes a global class identity proof.
- Worker receipt payloads expire on a periodic sweep, not only when another request arrives. Explicit authenticated DELETE with boolean confirmation clears non-running worker payloads and returns signed logical-removal evidence while preserving nonce tombstones. SQLite secure_delete is enabled, but snapshots, backups, SSD copies, RAM and desktop capture files are not proven erased.
- setup-controller.py defaults to a no-write plan; --apply validates operator isolation, TLS paths and pinned Bun before installing a private venv, building fixed instrumentation and generating protected credentials without printing secrets or starting a server/sample. It requires an already isolated Linux controller, valid TLS, lifecycle hooks and Android target; it does not provision the outer VM or network policy.
- Owned native-reader, purge/retention, setup-plan and client-consent tests are mandatory in their appropriate source/Windows/engine gates. No real-device test, universal decryption or devirtualization is claimed.

- User-selected physical Android mode checks online state, exact serial and emulator property, then refuses replacement of an existing app. A reviewed dedicated-device cleanup policy is mandatory at worker startup/setup. No rooting, flashing, factory reset, emulator provisioning or phone snapshot is performed. The remote VM snapshot claim concerns the controller, not hardware. Real physical-device validation remains required.

- KernelSU/KSUN physical targets use bounded read-only root (`su -c id`), serial/state, emulator-property and ABI preflight. Frida must connect before installation. Signed device summaries report hashed serial and uid0 observation, not hardware attestation. Native root reads accept only prevalidated package paths; no root-manager setting, module, wipe, flashing or arbitrary command is exposed.

- Physical device SHA256 identity is copied from the signed worker manifest into the approved request and checked again before upload; successful signed device observations must match it. Missing/broken physical identity fails closed. This is serial-based configuration binding, not hardware cryptographic attestation.

- Remaining Windows CI fixture blockers are repaired without skips: supervisor fixtures use a copied native runtime executable with spaces plus owned JS on Windows (POSIX shell retained elsewhere); writer metadata compares the exact canonical filesystem path; capacity fixtures stay alive until explicit manager disposal rather than expiring under slow CI. Corresponding suites are added to mandatory focused SDK validation. Windows reruns remain necessary.

### Integrated install-and-use, optimization and next-day recovery

- The private Windows installer bundles a checksum-pinned isolated CPython runtime with the existing six portable engines, dependency/license inventory, and runtime integrity manifest frozen after fixture subprocesses and bytecode cleanup. Offline repair uses digest-versioned immutable directories to avoid replacing a previously loaded runtime and saves an explicit bundled-runtime preference without modifying user environment variables. Backend and Hub helper/daemon entry points select it automatically; explicit developer interpreter overrides remain supported. No user pip, script, or environment setup is required for installed core analysis.
- Analysis settings provide explicit offline repair, runtime-keyed owned-fixture caching, optimization status and persisted Economy/Balanced/Deep admission controls. Installed-resource integrity failure blocks analysis, not ordinary coding. Licensed engines and physical-device provisioning remain separate.
- Managed-local Hub registration preflight recovers a lost transport before session metadata commands. Recovery does not replay accepted task prompts. Recovery guidance preserves canonical close text so authoritative reconciliation can remove an obsolete transient error. Installed acceptance now restarts its exact isolated Hub and reattaches the saved session.
- Python and managed native workers share bounded per-owning-process resource admission; native leases and capacity are retained until exit is confirmed. This is not machine-wide OS resource enforcement.
- Long transcripts retain DOM/search/accessibility while older rows use native render containment. Session-ending events index one exact session with batched recovery reconciliation retained.
- Model capabilities/context and optional cost ceilings are hard eligibility filters. Static notebook cache identity excludes volatile diagnostics and includes packaged runtime identity. Graph retrieval is byte-budgeted with provenance. Engineering exposes bounded import-impact and non-executing test candidates.
- Performance budget policy and three installed startup samples are delivered without inventing a controlled baseline or claiming measured speed gains. Signed-update metadata checks are delivered with activation/publication disabled; owner signing and tested rollback remain required.
- See `docs/INTEGRATED_ENHANCEMENT_DELIVERY.md` for exact implementation, acceptance and remaining boundaries. Preserve every earlier customization and the unsigned artifact-only workflow.

Bundled repair selection resolves the verified cache to its canonical Windows path so long and 8.3 directory aliases do not change the selected interpreter across restarts.

Bundled runtime manifest IDs accept bounded dotted Python versions (for example cpython-3.13.12-windows-x64-v1) while forbidding path separators/traversal. The installed acceptance records the actual readiness receipt before asserting success, so failed owned fixtures remain diagnosable without bypassing the gate.

Session SQLite schema initialization installs the existing five-second busy handler before the WAL pragma, covering crash-recovery lock admission without deleting/replacing history. Installed acceptance retains the bounded, redacted fixture-owned backend log tail and the backend RPC failure detail; Hub restart and saved-session assertions remain mandatory.

### Integrated full capability Setup Center

- Windows artifacts include separately integrity-manifested core, full and angr private CPython packs. Full includes the portable engines plus triton-library (not the ML Triton distribution), QBinDiff, Unicorn and PyQBDI; angr uses a separate interpreter and pycparser 2.22 to preserve its compatible solver/parser dependencies. Every pack executes fixed owned fixtures during packaging; missing required full engines fail the build rather than silently skip. No system pip, scripts or environment variables are required from installed users.
- Setup Center installs/repairs the immutable full packs offline, records execution-tested capability receipts bound to runtime and worker identities, and permits explicit rollback to core without deleting project/history or prior runtimes. Existing shared Hub jobs are never interrupted; changing interpreter selection requires a separate backend restart. Opening settings performs no engine imports or package installation.
- Eleven local engines require actual owned-fixture execution before full readiness. Unicorn only emulates bounded x86-64 bytes with mapped private memory/instruction/time limits and blocked SYSCALL; angr exposes bounded static VEX lifting, not target execution or unbounded symbolic search. The QBDI fixture executes only fixed project-owned bytes; target-native tracing still requires the existing approved signed isolated worker.
- Official checksum-pinned Android platform-tools 37.0.1 packages only connectivity binaries and notices, not flashing utilities. Setup requires explicit notice acceptance. GUI settings select an authorized IDA installation, exact Android serial/kind and pinned Ed25519 public-key HTTPS worker. Owned licensed acceptance, read-only device connectivity and signed capability probes stay distinct from package health. Licenses, device authorization, outer VM isolation and update-signing keys are not supplied or falsely marked ready.
- Required source tests reject inventory-only/missing/duplicate engine success and unsafe worker credentials, and the installed UI acceptance activates all eleven engines, verifies restart selection, reconnects the saved session, and rolls back to core. No automatic updater publication or machine-wide resource-enforcement claim is added.

- Full Setup Center follow-up binds receipts to the runtime captured before execution and exports the worker identity through the SDK entrypoint. Its GUI mounts lazily. Mutating setup commands require the trusted desktop approval-token connection. **Apply setup to idle backend** explicitly drains and restarts only a confirmed-idle compatible managed Hub; busy/unknown activity refuses even if a force flag is accidentally supplied, and newer/incompatible builds keep their downgrade protection. This supplies a no-script application step without killing running project jobs or replaying prompts.

### Integrated command evidence, readiness and performance upgrade

- Native command argv remains preferred; optional explicit input/output file contracts preflight missing artifacts and reject unchanged pre-existing output after completion. Nonzero exits never publish successful output receipts. Per-command actual execution receipts retain bounded redacted stdout/stderr tails, exit/status, PID/cwd and observed termination confirmation. Custom executor facts are never invented and side-effecting commands are not replayed.
- Shell descriptions retain the exact configured family and now disclose legacy PowerShell native-stderr fail-fast behavior without globally weakening ErrorActionPreference. Edition-specific Windows fixtures and direct argv warning/exit tests are blocking.
- Setup Center distinguishes stale, installed/not-tested and integrity-failed states, retaining last-tested time separately. Runtime file hashing is streaming and bounded; integrity coverage is unchanged. Resource profiles expose queue age and estimated reservations. Trusted GUI cleanup only considers expired process-identity-aware command logs and preserves runtime packs, active work, sessions and project data.
- Engineering model advice adds economy/balanced/deep and eligible manual selection without silent fallback, validates outcome/cost estimates and preserves hard capability/context/budget filters and normal selected providers.
- Controlled owned direct/shell command benchmark evidence runs in consolidated validation; provenance and measurements are validated even without a baseline. No whole-app speedup, machine-wide RAM enforcement, public distribution signing or full installer/database rollback is claimed. See docs/INTEGRATED_RELIABILITY_UPGRADE.md for exact scope and remaining acceptance requirements.
- Installed acceptance uses a uniquely labeled full-pack status and emits bounded redacted failure annotations while retaining all fixture/restart/rollback assertions and the verified artifact upload gate.

Installed acceptance also exercises a fixed 120-row owned offline transcript and records bounded native-app-only working-set and scroll-round-trip observations. Three candidate samples are not a controlled speedup, peak memory, descendant-memory or universal long-session claim.

Installed restart acceptance now waits for the real local native endpoint and one authenticated settings read before counting startup as ready. Endpoint discovery alone may retry the exact native not-ready response at most three times within 90 seconds; commands and prompts are never replayed. Permanent startup failures, nonlocal endpoints and discovery timeout still fail acceptance. Full-pack integrity coverage and the existing outer installed-test deadline remain unchanged.

Consolidated CI emits escaped, bounded public notices for fixed gate starts and five-minute active-gate snapshots, in addition to private append-and-close progress records. Child output, commands and environment are not published. This improves diagnosis if a hosted runner loses communication; it does not assert a root cause, replay work or weaken any timeout/test/upload gate.

The installed crash-recovery journey now invokes the existing authoritative Hub attach/registration recovery before opening its local SQLite discovery connection. Local list_chat_sessions is not a Hub readiness probe. Both the recovered saved-session assertion and discovery identity replacement remain mandatory; no disk error is caught/retried, no database/history is deleted, and no accepted prompt is resubmitted. This sequencing removes the fixture's uncoordinated pre-recovery discovery, without claiming a diagnosed disk-I/O root cause.

### Processor-aware readiness and bounded live IDA execution

- Analysis settings link directly to Setup Center, distinguish core selection from full-pack availability, and show the packaged desktop version/commit and selected runtime. Missing Python packages never diagnose IDA. Readiness checks do not install or repair anything. Existing signed-worker, Android, license and idle-Hub restart approvals are preserved.
- Setup Center saves the explicitly selected IDA folder when running a licensed test and supports separate fixed owned x86-64 and ARM64 fixtures. Receipts bind processor, fixture and selected executable SHA-256; replacing the executable at the same path invalidates readiness. No all-processor, target-compatibility or licensed-host CI claim is added.
- Fixed one-shot and managed IDA scripts check the loaded processor's Hex-Rays plugin before costly auto-analysis; exact entry validation and full analysis remain intact. Selected one-shot scripts record decompilation-started explicitly.
- One-shot IDA streams bounded host-observed PID/phase/elapsed/deadline summaries to its chat row, with a 30-second heartbeat. The default overall and unchanged-phase budgets are one hour, with ida_phase_timeout_ms still explicitly adjustable and capped by the overall deadline. A phase deadline is a configured limit, not proof of a hung engine. Timeouts never publish success or automatically retry work.
- Cancellation drains for at most two seconds. Missing exit/EOF confirmation remains termination-unconfirmed and retains project ownership; no PID-only kill, automatic lease theft or cleanup is added. Optional live read-only job refresh is serialized and stops on view unmount. Archived host state remains clearly distinct from a fresh liveness check.
- Deterministic ARM64 fixture checks, processor-bound receipt tests, deadline/cancellation tests, and non-command live progress UI regressions are blocking. See docs/IDA_READINESS_AND_PROGRESS.md for limits and recovery.

Explicit Setup Center IDA selection is carried into the owning backend environment. Windows registry refresh cannot overwrite it, and a missing executable in that chosen installation fails instead of silently using another IDA from PATH or auto-discovered folders. Other tool/PATH refresh behavior is unchanged. Applying a saved selection to an existing Hub still requires the separate idle-only action.

Managed IDA requests also stream owned PID/readiness/request mailbox observations with a bounded waiting heartbeat. These are explicitly not script-phase or liveness proof; capacity, nonce binding, idle/lifetime limits and no-replay/no-automatic-restart behavior are unchanged. Failed native execution receipts render as unsuccessful tool rows rather than visually successful decompilation.

Licensed acceptance also requires the executor's actual target SHA-256 to match the owned fixture and checks processor/fixture identity when reading each processor's receipt. Copying an x86-64 receipt into the ARM64 slot cannot establish ARM64 readiness.

## Managed Hub replacement credential binding

Managed discovery resolution refreshes the returned daemon URL and authentication token before reconnecting, including replacements reusing a pinned port. Explicit endpoint callers remain non-recoverable; no accepted task prompt is replayed. Regression coverage checks first-spawn authentication and same-URL token rotation without assuming a concurrent observer refreshes discovery. Both installed crash-recovery journeys remain mandatory.

Installed recovery failures retain a separately bounded, redacted tail of the fixture-owned hub-daemon.log and expose its bounded startup context in the failure annotation. This diagnostic does not replace any installed acceptance assertion, replay commands, mark failed installers verified, or read user Hub logs.

Managed-local transport recovery now retains bounded/redacted daemon-ensure failures rather than replacing every startup timeout with a generic WebSocket error. The owned daemon log records spawn request, returned child PID and eventual error/exit without arguments, environment or credentials. Diagnostics do not assert readiness, replay accepted prompts or change startup/test deadlines; explicit endpoints and header-auth transports remain excluded.

### Integrated IDA database lifecycle and tracked Setup Center jobs

- One-shot IDA separates target/executable/configuration database compatibility from selected-function output identity. Each fresh or reused execution owns a unique attempt directory under the existing workspace lease, copies only digest-verified compatible packed databases, and atomically publishes a new accepted snapshot only after successful confirmed execution. Failed/legacy databases and logs are never automatically deleted. Selector changes no longer collide with an existing fresh `-o` destination; uncertain termination still retains ownership.
- Built-in IDA analyze now attaches a fixed phase-reporting auto-wait, explicit database-save and exit script without requiring Hex-Rays. Decompile scripts explicitly save too. Unsupported user-script invocations retain overall supervision but are not required to emit Cline script phases. No timeout is blindly increased, no command is automatically retried and no license protection is bypassed.
- Confirmed trusted setup operations return optional immediate persisted job IDs, reject competing cross-process mutations and coalesce identical concurrent requests in one host. The UI shows coarse stages beside its buttons and rejoins through serialized read-only polling without replay. Request timeouts are not installation-failure evidence. Interrupted hosts retain admission until termination is confirmed; no PID-only lease theft is introduced. Terminal summaries are bounded and errors use the existing secret redactor.
- IDA installation can be saved independently; its processor integration test is explicitly optional, not a gate for direct analysis. Detection/selection is not readiness proof; actual execution errors and processor-bound tests remain available. Processor choice persists across navigation. Full eleven-engine fixtures, integrity coverage, signed-worker/device approvals, idle-only Hub activation, installed restart/recovery/core rollback, and unsigned Windows artifact gates remain mandatory. See docs/IDA_AND_SETUP_JOB_RELIABILITY.md for migration and crash-recovery boundaries.

Installed crash-recovery follow-up: a live Hub startup owner is never reclaimed solely because its lock is 30 seconds old. Same-host lock holders serialize, identical owner/endpoint startup requests coalesce, confirmed-dead reclamation re-reads under a separate exclusive guard, unknown/permission PID probes retain ownership, and nonce-bound release cannot remove replacement ownership. Compiled helpers retain all selected-pack integrity verification before Hub readiness and emit bounded verification-start/finish timing diagnostics. Their finite cold-start budget is 90 seconds with a 120-second cross-process lock wait, rather than spawning replacements while verification is still running; IDA phase budgets, task replay restrictions and installer acceptance deadlines remain unchanged. New ownership/coalescing regressions and both real installed recovery journeys remain blocking. Empty/malformed or interrupted reclamation ownership is not automatically stolen.

CLI acceptance determinism: unauthenticated headless tests use a synthetic, credential-free 401 cassette with explicit network-isolated playback, retaining all error/JSON/exit assertions. Production authentication is unchanged, and fixture playback does not claim a real provider or licensed-engine acceptance test.

## Scrollable artifact and recorded-code previews; bounded batch scans

- Markdown/artifact previews use bounded flex layout and a focusable independent scroll region. Tapping a green edit diff opens a small read-only recorded-code window with before/after and truthful fragment labels; selection remains possible, text is bounded and no filesystem read/execution occurs on code-preview open.
- Fixed Smali scans accept multiple literal queries in one candidate pass, explicit directory/byte limits, actual streamed counters, cancellation-aware finite deadlines and honest partial coverage. Same-host/owner duplicate scans are rejected, not replayed; no cross-host caching/resume or private-script speedup is claimed.
- Process sessions accept optional finite batch lifetimes retained in identity-bound recovery metadata. Expiry requests termination and never fabricates exit/liveness or restarts work. Persistent terminal/server behavior without a timeout and short-command deadlines remain unchanged. Existing engine/installer/security gates stay mandatory. See docs/PREVIEW_AND_SCAN_RELIABILITY.md.

## Integrated reliability and investigation upgrade

The guided first-party investigation panel adds scoped artifact handles, exact function analysis through existing approval plans, explicitly approved Windows browser metadata recording, partial feature-candidate reconciliation and selected JSON evidence export. Setup Center adds capability filtering and backend connectivity status; chat adds optional manual unsent-draft recovery. Windows builds use bounded noninteractive verified wheel caches and avoid duplicate feature/fix push installer builds. Existing execution isolation, licenses, session recovery, installer upgrade/rollback and evidence limits remain intact. See `docs/overall-upgrade-20261013.md` for actual coverage, limitations and release gates; this is not a full backup or REA superiority claim.

## Guided investigation and Binary Triage Pack

- Analysis adds Start here with four preserved journeys: coding, understanding applications, APK/native investigation and evidence review/export. Existing advanced tabs, providers, profiles, worktrees and tools remain intact.
- Fixed GUI-controlled static operations integrate radare2/r2pipe, YARA, capa and optional-use FLOSS static strings. No arbitrary r2 commands, scripts, debugger actions, target execution or new model-tool bypass is exposed.
- Windows packaging pins official archives/licenses and compatible Python bindings, verifies full file inventories and executes four owned fixtures. Installed acceptance repeats actual engine readiness through the installed GUI. Shared readiness distinguishes available resources from explicitly tested capabilities.
- Hash-verified confined snapshots, minimal child environments, bounded outputs/deadlines, owner cancellation and immutable session receipts preserve evidence categories and unknowns. Missing termination confirmation retains capacity; no replay or automatic crash repair is claimed.
- Older CI-only Python descriptions above are historical: current installed core/full/angr packs are bundled as configured by the Windows workflow. Binary triage uses core/full bindings; selecting a different interpreter requires explicit readiness testing. Hosted fixture success is not licensed-engine or physical-device validation.
- See `docs/BINARY_TRIAGE_AND_GUIDED_INVESTIGATION.md` for coverage, remaining administrator actions and acceptance. Preserve unsigned artifact-only Windows builds and merge only after successful current-revision checks.

The installer artifact also includes `DEPENDENCIES.cdx.json`, a CycloneDX 1.5 source-lock inventory generated by `scripts/write-dependency-inventory.ts`. It explicitly excludes claims of complete installed/transitive Python/PyInstaller composition, dependency graph, or license completeness.

Windows gates now provision Gitleaks 8.28.0 from its official upstream archive using pinned SHA-256, bounded download retries and an executable version check, rather than depending on the Chocolatey Gitleaks feed. The full-history secret scan still fails closed.

Native triage acceptance has an independent fast Windows job in custom desktop validation. Packaging and owned-worker failures emit bounded, credential-free check annotations (engine/status, whitelisted phase/error type) without exposing raw child output. It does not replace the installer or installed-app acceptance gates.

FLOSS release v3.1.1 reports embedded runtime version `v3.1.1-0-g3cd3ee6` in the verified official archive. The lock now records exact archive/release and runtime versions separately, with exact runtime-version regression checks; it does not broadly allow unknown build suffixes or skip provenance checks.

Installed acceptance explicitly enters the new Start here guide and navigates to App analysis before checking saved receipts and Off-mode behavior. Those existing assertions remain intact; new guide navigation is also covered by a no-execution UI regression.

Installed triage acceptance now observes either the readiness test's terminal success or bounded host-owned engine/phase/error tokens, without raw exception output or automatic replay. Its observation budget covers the existing four sequential 90-second worker limits; worker deadlines and all four Ready assertions remain unchanged. An independent Windows check repeats all four actual fixtures with checksum-pinned CPython 3.13.12 embedded isolation matching the shipped runtime, not only the build venv.

The radare2 adapter passes r2pipe 2.0.0 a one-element target list. Its plain-string overload splits at spaces and reinterprets remaining filename segments as extra file arguments; the literal list preserves installed Program Files and workspace filenames without quoting or shell parsing. The real embedded-Python four-engine gate uses a copied digest-verified pack under a path containing spaces.

## Pinned Android Analysis & Rebuild Pack

- The private Windows installer provisions checksum-pinned Java, Apktool, maintained Google Smali/Baksmali, JADX, Bundletool and official Build Tools with upstream notices. Direct fixed Java arguments avoid batch expansion; verified inventories reject missing/changed/untracked/linked resources. No installed investigation downloads dependencies or executes an app.
- Android tools is an additive guided workbench; each step prepares an exact approved request. AAB validation and split-container inventory remain distinct from ordinary APK decoding. Existing coding, providers, Python/native analysis and device incident workflows are preserved.
- Decode reuse binds input, engine/runtime/API and decoded-tree hashes. Rebuilds use bounded private snapshots, validate bounded output structure and atomically publish new no-overwrite artifacts. Original app signatures are not preserved. Separate alignment/signing/verification never installs or launches; signing uses only a host-configured authorized test key with child-only secret references and omitted private diagnostics.
- Explicit readiness executes owned resource/multidex/Smali/JADX/signature fixtures, not mere version inventory. Windows native acceptance is mandatory before installer production and installed WebView acceptance exercises the installed pack. No valid-AAB, full Dalvik/ART, custom OEM framework, production key-management or real-device compatibility claim. See `docs/ANDROID_ANALYSIS_REBUILD_PACK.md`.

- Android Java tools use a fixed-entry ASCII/Base64 argument bridge compiled during packaging, with a relative classpath and verified-pack working directory. This preserves Unicode paths across the Windows Java ANSI launcher boundary without changing host locale or passing through a shell. Owned Unicode fixtures remain mandatory.

- Preserve only non-secret Windows processor architecture/count fields in Android child environments, since Apktool uses them to distinguish 64-bit native tools. Bundled native helpers use private ASCII-filename snapshots, never the target workspace as a working directory.

- Android inventory hashing uses bounded explicit reads with deterministic handle closure (including read errors), avoiding Bun/Windows stream descriptor accumulation during repeated per-command integrity checks. Full integrity verification remains mandatory.

- Fixed bundled native Android commands stage bounded artifact copies behind ASCII relative filenames in a private working directory, preserving Unicode input/output paths despite Windows narrow-CRT tools. Only supported fixed argument shapes are accepted; outputs never overwrite and scratch remains when child termination is unconfirmed. Owned native fixture calls use the same runner.

- CI Android provisioning retries transient HTTP/network download failures at most four times with bounded backoff. Exact cached/new SHA-256 remains mandatory; checksum mismatches fail immediately. Offline download regressions block both Windows packaging paths; installed operations still never download dependencies.


## Pre-task Analysis and session-owned reasoning (2026-10-16)

- Local fresh-chat composers expose Off / Static / Runtime / Hybrid before the first task. Draft mode changes never invoke a tool, run a command, install software or change permission profiles. Runtime/Hybrid retain explicit confirmation. The chosen mode is applied through the existing trusted idle-session command after session creation and before the first prompt; failure blocks dispatch. SSH/cloud do not acquire local Analysis controls.
- The optional inline Analysis workspace retains draft form selections when welcome transitions into a conversation; opening it performs existing read-only discovery, not target execution. Existing header access and per-action review/approval gates remain unchanged.
- Reasoning selections are non-secret desktop-local preferences, scoped by environment/session. Draft selections and new-chat defaults are scoped separately by environment/provider/model. Existing chats never inherit another chat's effort or new-draft defaults. Existing runtime attach settings are a fallback when no saved preference exists. These preferences do not sync between devices; unavailable local storage cannot guarantee restart retention.
- Remove mount-time Low writes. Auto uses model-default effort (thinking enabled, no explicit effort); None disables thinking. Serialized Auto clears the previous runtime effort/budget instead of merging it back. Unsupported model capabilities retain the saved selection and explain that support is unavailable; no guaranteed provider-wide support for every effort level is claimed.
- History may render while attach is pending, but composer sending and reasoning edits remain locked until the destination configuration is restored. Request ownership rejects late attach results and immediate stale send callbacks. Tests cover independent Medium/High/Extra chats, remount, rapid switching, draft defaults, outgoing request settings, Auto wire reset, mode-before-send and fail-closed mode configuration. Installed WebView acceptance checks fresh-draft visibility and selection with no live model turn. Windows installer and existing installed acceptance remain blocking before merge.

- Mounted inactive drafts use a distinct “Draft Analysis mode” accessible label and React-generated unique control IDs; the active header retains “Session Analysis mode”. Installed acceptance targets the intended draft/session explicitly rather than weakening strict locators.

## Advanced AI command pack (review-first)

The Analysis workspace now has an **AI commands** panel available before a first task as well as in an existing local session. Opening it reads a static catalog only: it does not discover engines, run fixtures, install software, grant approval, or execute a target. Each prepared request goes through the existing exact-request approval ledger. Unsupported capabilities are listed separately, not represented as working commands.

### Fixed command adapters

- Android: `baksmali_dir` (flat directory, max 32 DEX files / 256 entries / 512 MiB, shared deadline, managed outputs only), `disassemble_dex` (DEX only), `decode_apk` (ordinary APK only), `recompile_smali`, `build_apk`, and `validate_smali_project`. Assembly/validation produces a **new DEX**; Apktool rebuild produces a **new unsigned APK**. Original signatures and device correctness are not preserved or certified.
- Native/artifact: `identify_artifact`, `inspect_binary`, `decompile_function` (explicit Ghidra/IDA plus exact symbol/address), `inspect_elf`, `disassemble_range`, `read_native_function`.
- Android evidence: `index_multidex`, `map_jni_bindings` (static relationships/JNI-name candidates, not observed dynamic registration), `read_android_method_code`.
- Electron: `inspect_asar` uses the owning session's first-party static parser and existing Analysis-mode requirements. It does not execute source or prove complete IPC/data flow.
- Saved evidence: `query_investigation`, `query_investigation_graph`, `export_evidence_bundle` (the existing bounded forensic JSON/HTML report, not a blanket archive of all session data).
- Static notebooks: `validate_batch`, `run_batch`, `resume_investigation` reuse the existing maximum-20-cell, allowlisted static notebook runner. `target` is the notebook manifest path. Its existing input/engine/dependency fingerprints control checkpoint reuse. These aliases do **not** accept arbitrary shell, Smali-patch, signing, device, or debugger batches.

`analysis_command_catalog` reports the exact adapter names and limitations. Adapter availability is not tool installation, compatibility, or successful fixture readiness. All backend-specific options and bounds remain in force. No duplicate execution engines, automatic downloads, cross-device preference sync, or broader privileges are introduced.

### Precise Smali candidates

1. Read one `.smali` file (maximum 512 KiB) and compute its SHA-256.
2. Call `preview_smali_patch` with `target`, a distinct new `.smali` `output_file` in an existing parent directory, and `smali_patch`: `expected_sha256`, exact `class_descriptor`, exact `method_signature`, `expected_method`, and `replacement_method`.
3. Review the returned before/after text and `previewSha256`. Preview publishes no file.
4. Separately approve `patch_smali_method` (alias `patch_smali`) with those same parameters and `smali_patch.preview_sha256` set to the reviewed hash. Source, method, replacement and destination are bound into that hash.
5. The operation rejects stale hashes, ambiguous/duplicate methods, changed signatures, class/field insertion, symlink paths, existing outputs and cancellation before publication. An exclusive temporary file is atomically hard-linked to the new output; no overwrite fallback is used. The original remains unchanged.
6. Integrate the **single candidate file** into a separately managed candidate project; assemble/rebuild, compare, align, and separately sign/verify as applicable. This is not a whole-project copy, parser-backed register repair, assembly test, ART verifier, installation, or runtime test. The receipt explicitly says `validation: not-run`.

All new construction aliases and patch operations are classified as writes **before** normalization. Read-only profiles cannot invoke them, and workbench execution additionally requires an idle Full Access owning session through a trusted desktop connection. Full Access is never enabled automatically.

### Planning, not automatic execution

`plan_investigation` / `plan_batch` take an `investigation_plan` with `workflow` (`artifact`, `android`, `native`, `electron`) and descriptive `goal`, plus an explicit target. They return dependency-labelled stage proposals; no stage runs or receives approval. The Android recipe accepts ordinary APKs only; split/bundle validation remains separate. Native exact decompile is proposed only with an explicit supported engine and selector. Plans are not executable notebook manifests.

Still not implemented in this pack: recursive/unbounded Baksmali batching, universal cross-language/data-flow tracing, .NET/JVM transformations, arbitrary native binary rewriting, automatic runtime capture, general write-batch replay, universal hypothesis verification, or a new tool installer/readiness system. Existing device/debugger workflows stay separately authorized. Analyzed content and descriptive goals are untrusted data, not executable AI instructions.

Regression coverage includes SDK alias/schema/permission checks, adversarial patch tests, notebook checkpoint tests, desktop write classification, command-panel tests, and installed Windows catalog plus preview/approved-candidate verification. Merge remains gated on current-head CI, Windows setup.exe, and installed WebView acceptance.

## Advanced candidate follow-through and truthful roadmap status

The latest follow-through extends exact candidates to up to 32 disjoint byte edits or parser-checked primitive JS/TS literal edits per file. It adds bounded `trace_source_sink` queries over declared saved evidence and read-only `audit_candidate_batch` recovery review. No query infers missing edges or validates sanitizers; no audit writes, replays, authenticates producers or certifies runtime behavior. Original hashes, no-overwrite publication, separate exact-preview approval and existing restricted-profile controls remain mandatory.

See `docs/ADVANCED_ANALYSIS_ROADMAP.md` for the full completed/partial/not-implemented ledger and broader acceptance criteria. This supersedes earlier historical statements that all managed/JVM transformations are unavailable: selected fixed-width constant candidates exist. It does **not** mean that universal tracing, whole-program taint, general native rewriting, complete .NET decompilation, arbitrary refactoring, unrestricted replay, system-wide capture or unattended signing/installing have been delivered. No entire-roadmap completion claim is permitted without implementation and validation evidence.


## Hash-bound admitted-source acquisition

New static-reader receipts retain a versioned acquisition manifest, explicit selected workspace target, exact admitted file hashes and observed ASAR container byte hashes. Selected ASAR members retain container identity and physical byte ranges; malformed selected-member ranges admit no earlier members from that archive. Files are checked against the opened descriptor and named-path identity after reading. ASAR suffix matching is case-insensitive. Existing limits are preserved, with an additional aggregate 64 MiB ASAR read cap.

`analysis_evidence` views `source-acquisition` and `source-containers` paginate retained sources and original observed container identities. They remain session-owned and readable while Off, with zero provider calls and no target execution. Receipt schemas validate the acquisition commitment and artifact projection; the supervising parent also binds the selected path to the request. Legacy receipts without this manifest return unavailable, not invented provenance.

This is a first-party acquisition-ledger improvement, not another original REA contract port. The seven partial-route inventory remains unchanged. Directory reads are not atomic whole-tree snapshots; archive publisher authenticity, linked/unpacked acquisition, excluded/unvisited files, automatic executable/bundle source selection and JavaScript bundle recovery remain unimplemented or unknown. The application graph still identifies a virtual admitted manifest, not original container bytes. Do not claim full acquisition, complete REA parity or current-head installed validation before CI passes.

Acceptance adds `installed-source-acquisition-hash-bound-saved-off-no-execution-passed` without removing existing stages. The real installed journey compares every selected owned fixture's retained hash/size to filesystem bytes while Off and saves `source-acquisition-evidence.json`. This candidate requires all 68 installed stages and the unchanged core/engine gates.

## Ghidra owned architecture acceptance matrix

Setup Center now offers independent x86-64, ARM32 and ARM64 selected-function tests plus explicit sequential Test all. The ARM32 inert ELF fixture is deterministic and generator-checked. Tests use real Ghidra static decompilation, require the imported language family to match the selected architecture, and never execute the fixture. A failed profile does not discard successful sibling receipts. Architecture selection survives settings remount.

Version 2 per-architecture receipts bind fixture bytes, launcher/configuration and actual Java executable identity, selected processor-definition bytes and the host-native decompiler. Changed or legacy identities are stale, not silently accepted. Identity walks are bounded and reject links; this is not a complete Ghidra/JDK/OS distribution seal. The read-only projection is shared by Setup Center and desktop AI discovery, refreshed independently of the SDK discovery cache. Reading readiness launches no acceptance tests, grants no permissions, and does not gate direct analysis of other processors.

Real local Ghidra 12.1.4 / Temurin 21 owned tests passed for all three profiles. CI must repeat Linux/Windows real-engine tests and the installed Windows UI journey before merge. The installed journey verifies selection persistence, all three receipts and saves ghidra-profile-readiness.json. The release policy adds one stage (71 total), preserves all previous stages and repins changed validation recipes.

This change does not implement the separate Emulation Framework Pack. Managed Qiling, unidbg, rnidbg and Speakeasy Install / Repair / Test / Remove remains outstanding; no HTTPS-worker provisioning or WSL containment has been replaced by this patch.

The release verifier also admits complete successful ready-for-review E2E repetitions only when every check has exact GitHub job/run binding to the expected same-head successful workflow. Both distinct detection workflows remain required. Failed/pending repeats, unknown workflows, missing provenance and absent required gates still block merge. No duplicate evidence is discarded.

Android stdlib fixture shards now retain flushed per-case start/finish timing diagnostics. The TypeScript parent verifies every selected case has an ordered start and finish receipt. These diagnostic timings do not pass a failed case, rerun failures, change sharding, relax the 18-second child / 20-second test deadline, or modify production worker behavior. A prior Windows timeout had no case-level stderr; its root cause remains unproven, not asserted to be fixed by diagnostics.

## Explicit reboot-bound setup recovery

Admission is returned immediately; native setup holds its lease while boot evidence is read and persisted before starting workers. Chat/status reads do not wait on the PowerShell query. New setup admission and job records retain a hashed host identity and the OS-provided boot identity when available. Windows uses an asynchronous bounded fixed read-only native boot-environment query through system PowerShell, not wall-clock/uptime estimates or PID disappearance; Linux reads the kernel boot UUID. Unsupported/unavailable evidence does not block normal setup, but cannot authorize recovery. The identity is local OS evidence, not hardware attestation or protection against cloned/tampered host state.

Only a trusted, explicitly confirmed local recovery command may close an exact retained job after evidence establishes the same host and a different OS boot. The job and admission identities must agree. Durable failed/interrupted-operation closure is written before removing the lease; an exclusive recovery lock prevents competing setup. No install/test is replayed and no capability becomes ready. Same-boot, foreign-host, inconsistent, linked, legacy and unknown records remain blocked. A source-owned native-operation allowlist excludes remote-worker, device and future managed-VM setup: host reboot cannot prove their termination.  A recovery operation whose own termination is unknown retains its recovery lock; automatic deletion of that lock is deliberately not implemented.

Setup Center offers explicit inspection and a second confirmation before recovery, with no OS probe on normal status polling or settings open. Interrupted work is no longer mislabeled as currently running. The regression suite requires stable real OS-query results on Windows and Linux hosts with machine identity, and covers unavailable evidence plus mocked reboot/refusal paths; a mocked boot change is not a claim that a real host reboot was tested. The installed Windows journey additionally stages a controlled retained job with the real current OS identity and requires the installed UI to refuse same-boot recovery without changing admission or replaying work; this is not a real reboot test. The release gate adds this 72nd stage and retains all previous stages.   The four-framework managed installer, same-boot supervised process-tree recovery, session-specific model exposure and performance acceptance remain separate unfinished work.
 Installed recovery-fixture cleanup preserves the primary assertion failure and aggregates cleanup errors rather than throwing from a finally block; foreign or changed admission is never removed.

## Session-specific model request tool evidence

The agent runtime retains a bounded name/count-only snapshot immediately before calling the core model adapter, after all prepare-turn and before-model hooks. It includes local function definitions and separately named provider-executed tools, capture time, run and iteration; descriptions, schemas, messages, options, credentials and provider tool configuration are excluded. Names are capped at 256 entries of 256 characters per category with full totals and explicit truncation. This is evidence of an adapter handoff attempt, not server receipt, provider acceptance, current model awareness or execution authority.

Interactive resident sessions retain their last request after a turn. Tool addition or connection/configuration updates mark retained evidence stale. New/restored host processes have unavailable evidence until a real request is prepared; nothing is reconstructed from registered routes or transcript tool calls. A changed runtime configuration never overwrites the captured provider/model identity. Session snapshots include this evidence only when explicitly requested; routine status events and durable transcripts do not grow tool-name lists.

Capabilities offers explicit Refresh attached sessions → select owning session → Inspect last request. Reads are trusted-desktop-only, local, attached-session-bound and revalidated after the Hub response; remote/older/missing evidence stays unavailable. Opening the page performs no inventory RPC, model call, engine probe, test, install or approval. Existing reverse_engineer discover and analysis_command_catalog expose the same core request evidence through the tool context without adding a standalone tool or expanding permission. The pure command catalog does not probe engines. Engine readiness, selected Analysis mode, disabled tool policies and per-request approval remain separate; historical names are never authorization.

Regression and installed acceptance compare names with the deterministic loopback provider's real HTTP function definitions and verify inspection adds no provider requests. The release policy requires the 73rd installed stage in addition to all previous checks. This does not deliver managed emulator installation, live provider attestation, provider-native schema normalization auditing, general remote inventory or performance certification.
