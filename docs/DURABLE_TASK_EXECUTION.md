# Durable task execution

Cline Enhanced persists structured plan state independently from chat rendering.
Each desktop session owns an atomic `task-state.json` artifact beside its other
session data. The artifact is authoritative after restart or re-attachment;
`plan.updated` messages are its typed UI projection.

## State and transition rules

The normal lifecycle is:

`planned → running → verifying → repairing → completed`

Exceptional states are `waiting_for_user`, `blocked`, `failed`, `cancelled`,
and `skipped`.

- Step IDs must be unique and stable.
- At most one step may be `in_progress`.
- Work cannot advance past a failed or blocked step until repair or
  verification completes.
- Completed and cancelled plans cannot be reopened by an ordinary plan update.
- Every skipped step must include a non-empty `skipReason`.
- Transition history is bounded to 500 entries.

## Automatic validation

A completed step may declare `validationCommands`. In a local Full Access
session (`mode: "yolo"`) or a session with tool auto-approval explicitly
enabled, the sidecar:

1. reopens the step as `verifying`;
2. runs commands sequentially in the step worktree, session working directory,
   or workspace root;
3. limits each command to two minutes;
4. records start/end timestamps, status, and exit code;
5. marks the step failed on the first unsuccessful command and records later
   commands as skipped.

Validation stdout and stderr are not retained in task state. This prevents
command output and accidental secrets from becoming a second durable log.
Failures use bounded, generated error descriptions rather than raw process
output.

Automatic execution is disabled for non-auto-approved and remote sessions.
Those sessions keep their declared commands for execution through the normal
approved command tool path.

## Checkpoint rollback

Steps may record `checkpointRunCount`. After the existing workspace checkpoint
restore succeeds, task steps associated with the selected checkpoint or a later
run return to `pending`; execution timestamps, repair attempts, and validation
results for those steps are cleared. Earlier completed steps remain intact.
The task state records the checkpoint run, time, and transition reason.

Workspace restore remains the source of truth: task rollback occurs only after
the SDK restore operation succeeds.

## Migration

If a session has no canonical artifact, session hydration scans persisted
messages from newest to oldest for a valid projected `plan.updated` event. The
first compatible report is normalized, persisted with the
`migration.projected-report` transition reason, and used from then on. Invalid
or prose-only reports are ignored.

## Build and release policy

These changes do not alter the custom Windows workflow. It still creates an
unsigned x64 NSIS `setup.exe` artifact for private testing and does not publish a GitHub Release.