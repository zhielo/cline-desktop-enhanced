# Desktop audit repair contracts

This repair batch addresses six reproduced defects. Passing the checks below does not establish that every engine, external service, target artifact or device is error-free.

## Automatic task validation

- Plan-declared commands are not run on a tool-start event. The host schedules validation only after a successful plan-tool completion, for a local session with automatic command approval enabled.
- Plan mode, read-only profiles, command denies, and missing workspace boundaries fail closed. Automatic shell validation requires command, write and network capabilities because an arbitrary shell string can exercise all three. Restricted profiles should use individually reviewed normal tool calls; auto-approval never broadens their capabilities.
- The working directory must resolve inside the configured canonical workspace. A plan-provided path or symlink cannot grant access to another working directory. This is a capability gate, not an OS sandbox: an approved arbitrary shell command still has the host process's OS access.
- Stop, Abort, environment disposal and session configuration changes cancel active checks. Cancellation waits for owned process termination and cannot turn a late exit code zero into a passed receipt. Replacement plans cancel old checks and wait for termination before starting their own accepted checks.
- Tests: `sidecar/task-validation-policy.test.ts`, `sidecar/task-validation.test.ts`, `sidecar/context.test.ts`, `sidecar/task-state-machine.test.ts`.

## IDA time budget

Explicit IDA desktop requests default to a 75-minute overall envelope, allowing the existing one-hour auto-analysis phase plus startup/export overhead. Explicit shorter caller budgets remain valid; unrelated engines keep their existing limits. This does not guarantee that IDA finishes a particular binary in one hour. Approval binds the exact request and budget; changing it requires a new approval.

- Tests: `shared/analysis-budgets.test.ts`, `sidecar/analysis-task-orchestrator.test.ts` (including the full deadline under a fake clock).

## Report recovery

A newer host-validation receipt supersedes an older headline failure only for the same plan, step and validation scope. Raw history remains visible. Unassigned failures and different-scope receipts remain unresolved. Passing declared checks is not proof of semantic correctness, full coverage, installer verification or merge status.

- Tests: `webview/lib/task-report-view.test.ts`, existing task-report integration/detail suites.

## Media compatibility

The local Zod 3 chat schema calls the canonical shared media schema through a validation adapter rather than nesting a Zod 4 schema. Supported media survives history round-trips; malformed media is rejected without the mixed-major `_parseSync` crash.

- Tests: `webview/lib/chat-media-schema.test.ts` and existing chat/history suites.

## Frontend verification

Desktop `typecheck` now includes `typecheck:web`. Next.js type failures are no longer ignored. The consolidated release validator requires the full WebView check, including fixtures, and explicit new audit-contract tests. WebView types consume built SDK declarations; build the SDK before standalone checks. Existing stale fixtures and invalid prop/import/parser typings are repaired without excluding tests or adding broad type suppressions.

## Release acceptance

Local unit tests and a WebView build are not a Windows installed-app acceptance result. The proposed head must pass the existing Windows regression and `.exe` installer/installed-WebView gates before merge. Keep the exact head SHA in the merge request and retain CI evidence. Do not replace these gates with larger timeouts, `continue-on-error`, skipped tests or cached acceptance results.
