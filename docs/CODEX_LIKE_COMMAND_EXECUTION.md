# Codex-like command execution customization

This document is the durable implementation contract for the private Cline Enhanced fork. Future AI assistants must preserve these behaviors together with `CUSTOMIZATIONS.md` and `scripts/verify-custom-fork.ts`.

## Implemented behavior

### Structured direct execution

- `run_commands` advertises structured `{ command, args }` entries.
- An explicit `args` array, including `args: []`, invokes the executable directly without shell parsing.
- String commands and object commands without `args` remain compatible and run through the configured shell when shell syntax is required.
- Tool guidance tells models to prefer direct argv execution for ordinary commands and reserve shell execution for pipes, redirects, variables, and chaining.

### Immediate first output

- The first non-empty stdout or stderr chunk is emitted immediately.
- Later output retains the bounded 48 ms coalescing window to avoid flooding the Hub, sidecar, WebSocket, and webview.
- Existing truncation, timeout, cancellation, detachment, and process-tree behavior must remain intact.

### Bounded telemetry and progress payloads

The implementation records these metrics without command text, arguments, stdout, stderr, environment values, or other command content:

- `cline.run_commands.duration_ms`
- `cline.run_commands.time_to_first_output_ms`
- `cline.run_commands.output_chunk_count`
- `cline.run_commands.output_chars`

Low-cardinality attributes identify direct versus shell execution, timeout-source configuration, and completion success where applicable. The bounded command preview is attached only to the first progress event for a command instead of being repeated with every output chunk.

## Primary source and regression files

- `sdk/packages/core/src/extensions/tools/schemas.ts`
- `sdk/packages/core/src/extensions/tools/definitions.ts`
- `sdk/packages/core/src/extensions/tools/executors/bash.ts`
- `sdk/packages/core/src/extensions/tools/definitions.test.ts`
- `sdk/packages/core/src/extensions/tools/executors/bash.test.ts`
- `CUSTOMIZATIONS.md`
- `scripts/verify-custom-fork.ts`

## Native Vitest configuration

The root project config and the example VS Code project config use `.mts` so Vite's native config loader treats their ESM syntax correctly. Do not restore `vitest.config.ts` at either path. The installer workflow explicitly uses the root `vitest.config.mts`.

## Required validation

After changing this behavior:

1. Install and run with Bun 1.3.13.
2. Run `bun run build:sdk`.
3. Run the focused `definitions.test.ts` and `executors/bash.test.ts` suites.
4. Run Biome on changed source, tests, and verifier files.
5. Run `bun run scripts/verify-custom-fork.ts`.
6. Run `git diff --check` and the repository secret scan.
7. Build the existing unsigned Windows x64 installer artifact when a Windows package is needed.

## Remaining phased roadmap

1. Compare direct and shell duration, time to first output, and output-volume metrics on Windows.
2. Optimize the Hub-to-sidecar-to-WebSocket path if transport remains the dominant delay.
3. Add a feature-flagged Prewarmed PowerShell worker only when measurements show shell startup is the dominant delay.
4. Initially serialize worker commands per workspace, automatically restart on failure, and fall back to the existing executor.
5. Keep direct argv commands outside the PowerShell worker.
6. Consider native Rust/Tokio process supervision only after the worker behavior is stable and measured.

## Release and build policy

- Preserve `.github/workflows/build-custom-windows-installer.yml` as an unsigned, artifact-only workflow.
- Do not publish a GitHub Release unless the user explicitly changes this policy.
- Do not merge a performance pull request without explicit user authorization.
- Every installer must be built from committed source and must include the customization ledger and exact commit identity.
