# Analysis runtime hardening

## Windows setup and repair

The installer is lightweight: CI's temporary engine environment is **not** bundled into the desktop.
Use a trusted committed checkout and inspect `scripts/setup-analysis-environment.ps1`.
Without `-Apply`, it prints a plan and changes nothing. With `-Apply`, it creates/reuses
a dedicated Python 3.13 venv, installs the committed pinned requirements, checks imports
under `-I`, and only then sets the user's absolute `CLINE_RE_PYTHON`.
Native Miasm installation may require the supported x64 Visual C++ development environment.
Failures are blocking and do not change the interpreter setting. No automatic package
installation occurs during an analysis request.

Fully stop the desktop and backend; launch from the configured environment or sign out/in
so the launch parent inherits the new variable. SDK changes also require rebuild/restart.
Open Settings → Analysis environment → Check analysis readiness. It checks the backend's
actual interpreter, package inventory, and owned LIEF/Capstone/Androguard static fixtures.
Missing engines remain blocked; package versions alone are not execution proof.
Keystone is not a prerequisite for the Capstone disassembly path or IDA.

## Worker diagnosis

Worker results include host-owned job ID, requested action, selected interpreter, PID,
exit code/signal, duration, bounded redacted stderr and failure category. Failed/blocked
results retain a private redacted JSON receipt under the Cline data directory; retention
is bounded to 32 receipts. Windows privacy depends on the ACLs of the configured Cline data directory; no encryption or secure erasure is claimed. Arguments, artifact bytes and private key contents are excluded.
The fixed toolchain worker additionally reports `sys.executable`, Python version and isolation.
Nonzero exit remains failure even if the child emitted valid completed evidence.
Timeout/output-budget/cancellation request tree termination. If termination does not settle,
the result explicitly reports uncertainty and defers script cleanup rather than hanging forever.
This is diagnostics and bounded supervision, not an OS sandbox or secure-erasure guarantee.

## IDA diagnosis

Normal supervised IDA jobs publish exact launched PID and unique host receipts alongside
`ida.log`. Each job has a unique script-progress path, including reused databases.
`process-exited` is not proof of successful decompilation; the tool's artifact verification
and `succeeded` result remain authoritative.
Settings → Analysis environment → Refresh IDA jobs is read-only and never
kills, restarts or steals a lease. Fixed full/selected decompiler scripts append phases:
input-loaded, auto-analysis-waiting, analysis-complete, decompiler-initialized,
output-written, script-failed, script-exiting.

No phase yet means no phase observed, not a hung process. Process CPU totals and a missing
output file are not progress evidence. Custom scripts are not assumed to emit these phases.
GUI handoffs and managed engine pools retain their separate existing lifecycle contracts;
they are not falsely reported as normal supervised jobs. Host-written job indexes are shared
through the Cline data directory so Hub-created jobs remain visible in the desktop.
The view reads bounded recent records; statuses are last recorded states, not live process
identity checks. On-disk receipts/logs are not used for PID-only control.
Unconfirmed output drain/termination retains the project lease. An operator must verify
the exact process and any relevant descendants exited before recovering a retained lease;
no automatic stale-lease stealing is added.

Prefer exact selected-function analysis. Increase a budget only when logs justify it.
Python engine failure does not prove an IDA/IDAPython failure. Check the exact IDA command,
log, script error file, executable/version and processor-specific Hex-Rays license.

## Licensed IDA acceptance

On an authorized installed IDA machine, configure an absolute `IDA_HOME` and explicitly
set `CLINE_TEST_IDA_LICENSED=1`; then run `bun run scripts/validate-installed-ida.ts`.
The script verifies an owned ELF fixture hash, performs one selected-function decompilation,
and retains its acceptance result, IDA log and phase receipts. It never executes the ELF.
Missing licenses/engines fail, never skip. This is one x86-64 fixture, not a claim of universal
architecture, IDA version, decompiler license or protected-binary compatibility.
Hosted Windows CI does not have an IDA license; this local licensed gate must be run
separately and its receipt reviewed when changing IDA adapters.

## Build and merge contract

- Supported Bun is read from canonical root `packageManager` / `engines.bun` through `scripts/read-bun-version.mjs`; mismatched or unpinned metadata fails.
- Every PR targeting `main` gets unsigned Windows packaging and installed smoke/UI checks.
  Feature/fix branch pushes and manual runs remain available.
- Regression validation has no path-filter blind spots and uses the single consolidated
  runner, avoiding multiline PowerShell native-command failure masking.
- The Windows build runs Python fixture corpora in the pinned `windows-portable` engine
  profile: LIEF, Capstone, Z3, Androguard, Miasm and cryptography execution remain required.
  Triton and QBinDiff are not shipped in that pin set; explicit negative-capability tests
  require them to report missing-engine blocking, not successful execution. The default
  `full` Python corpus still requires their real execution in the full pinned environment.
  The hash-verified owned ELF LIEF fixture runs on both Windows and Linux; no ELF target
  is executed. Missing shipped engines never become skips or successful capability claims.
- Verified artifacts require both installed sidecar smoke and installed WebView acceptance.
  The UI harness uses a fresh isolated profile, actual installed Tauri transport, an owned
  workspace/idle session seeded with owned fixture history, local-setting persistence,
  readiness fixtures, navigation and restart. Empty new sessions intentionally persist lazily;
  the seed exercises the existing durable recovery contract without dispatching a model turn.
  It does not claim a live model/tool turn, physical-device test or licensed IDA validation.
  The test-only WebView2 CDP port exists only for the app process launched by the harness;
  normal application configuration is not changed.
  Native Node launches the installed executable with explicit per-process WebView2 flags;
  the port is allocated after isolated Hub bootstrap. If CDP startup fails, review the
  bounded redacted launch receipt and owned-descendant flag observations, not just the
  timeout. The harness never falls back to a development web page or treats absent CDP
  as successful acceptance.
  The fixture sets `CLINE_INSTALLED_ACCEPTANCE=1` so the native shell explicitly
  supplies the validated loopback port and absolute private profile through Tauri's
  WebView options before window creation, rather than relying only on WebView2's
  environment-variable override. Exact opt-in is required; ordinary launches stay
  unchanged. Extra browser flags, non-loopback addresses, invalid ports and relative
  profiles are rejected. This does not bypass application IPC or backend authentication.
- Private packages remain unsigned and artifact-only; no signing secrets or release write
  permissions are available to this workflow. Version/tag consistency checks remain.
- Provenance identifies `GITHUB_SHA`. For a PR event this is the tested synthetic merge
  revision (head plus base), not merely the head SHA. Reject stale checks after new commits
  or base changes. The post-merge `main` artifact is the canonical installer.

Repository administrators must configure required checks/up-to-date branch or merge-queue
policy in GitHub settings. This PR does not silently alter administrator branch protection.
Require `Windows regression gates` and `Validate and build Windows x64 setup.exe` from the
expected workflow source. Inspect validation summaries and installer `PROVENANCE.json`.
Do not merge while checks are pending, failed, cancelled or stale.