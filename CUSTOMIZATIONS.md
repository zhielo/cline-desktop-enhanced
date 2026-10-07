# Cline Enhanced custom fork

This file is the durable customization ledger for this repository. The source on `main` is the source of truth: every installer must be built from a committed revision, and custom behavior must never exist only as an uncommitted patch or generated build output.

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
- `bun run validate:advanced --engines` additionally requires a trusted absolute CLINE_RE_PYTHON and runs the real static engine, Miasm and cryptography fixture corpora. Default CI reports these optional engines as not requested, not validated. A passed consolidated source test is not proof of installer or whole-platform completion.

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
