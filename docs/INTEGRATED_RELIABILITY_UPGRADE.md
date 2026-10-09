# Integrated reliability upgrade

This delivery extends the full capability Setup Center without replacing existing chat, providers, permissions, analysis, Android, Engineering, recovery or resource controls.

## Command execution and artifact contracts

Use `run_commands` with explicit `command` and `args` for native executables. Shell strings remain available for intentional pipes, variables and redirection. The description names the actual shell family and warns about the legacy Windows PowerShell fail-fast/native-stderr interaction. The fail-fast policy is retained, not globally disabled.

Commands can declare `required_files` and `expected_output_files`. Inputs are checked before launch. Outputs must be regular non-linked files and must not have the same filesystem fingerprint as a pre-existing output. This is a freshness check, not cryptographic provenance or proof that arbitrary shell code produced valid analysis. No output is promoted after process failure. File paths are explicit; the host never guesses them from shell source. Independent commands still execute concurrently; dependent artifact-producing steps must be separate calls.

Default executor results carry a process receipt: executable, cwd, PID, actual exit code, bounded/redacted stdout and stderr tails, duration, status and observed termination confirmation. Full legacy output remains compatible. No argv or environment is persisted in the receipt. Custom executor overrides do not get fabricated process metadata. A running/detached process is not a completed process; output contracts cannot pass until completion. Timeouts, cancellation and launch failures remain distinct. Failed commands are not automatically replayed.

## Setup and resource readiness

The Setup Center distinguishes actual ready receipts, stale runtime/worker identities, installed-but-untested engines, integrity failure and missing setup. A previous test timestamp is retained without labeling it current. Commercial licenses, selected device authorization and signed isolated-worker configuration remain external prerequisites.

Runtime integrity still covers every tracked file, but file hashing uses bounded 64 KiB stream buffers instead of loading whole native libraries into memory. No integrity check is bypassed. Resource controls expose queued-work age and estimated admission reservations; they do not claim machine-wide OS enforcement. Explicit trusted GUI cleanup uses the existing process-identity-aware expiry policy for detached command logs. It never deletes project files, session history or runtime packs. Old runtime-pack reclamation remains disabled because another process can still own an older pack.

## Performance evidence

`scripts/benchmark-command-execution.mjs --out <file>` measures a fixed owned runtime workload through the real shared command executor. Seven samples per execution mode follow one discarded warmup, alternating direct/shell order. Environment identity binds hardware host, runtime and OS using a digest. `--baseline <file>` enables comparable p95 regression checks; invalid, incompatible or empty measurements are rejected. Without a baseline the status is explicitly `baseline-required`, never passed or improved.

The benchmark does not measure whole-app RAM, scrolling, live model latency or analysis throughput. Installed UI acceptance retains native startup samples, settings/session persistence, exact Hub restart recovery, full-engine execution and core rollback. These samples are candidate evidence, not a controlled speedup claim. Long-session render containment and existing cancellation/lifecycle limits are preserved. A controlled previous-version installed-app and database migration benchmark remains a separate acceptance requirement before a public migration/rollback guarantee.

## Model advice

Engineering routing accepts economy/balanced/deep modes and an explicit `manualModelId`. Capability, context and cost constraints remain hard gates; an ineligible manual choice produces no selection instead of a silent fallback. Candidate outcome estimates are validated and measured-versus-estimated labels remain visible. Advice never changes normal chat's selected provider, downgrades permissions or replays side effects. Existing provider retries are not replaced with a blanket command retry.

## Shipping

The consolidated validator blocks on command/artifact, shell compatibility, resource, Setup Center, routing and retained recovery regressions and records the owned command benchmark. Windows installer generation, installed binaries and installed WebView acceptance remain mandatory. A bounded redacted failure annotation exposes the last completed installed acceptance stages without publishing raw logs. Verified setup.exe upload remains gated on successful installed acceptance.

A missing license, absent physical-device authorization, unsigned private distribution, unavailable baseline or unprovisioned external VM is never represented as solved by this PR.
