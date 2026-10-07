# Session navigation status restoration

## Confirmed defect

Local/SSH hydration guessed that a running session was completed when its last nonempty user/assistant message was assistant text. Intermediate narration is not a completion receipt. Returning to a history-backed pane could display Completed and Task completed while the backend was still working. Existing mounted-pane navigation preservation stays unchanged.

Hydration also applied delayed attachment status after a newer runtime event or queued turn. A guard now binds the status revision and turn epoch captured before the history read; newer events supersede both history and attachment snapshots. Existing session/environment request guards remain.

## Behavior

- Running records remain running regardless of transcript shape. Explicit completed, failed, cancelled and idle statuses remain supported.
- Genuine terminal runtime events settle the UI. Stale snapshots cannot reopen or complete a newer turn.
- Stale-stream polling reconciles attached sessions; stale running records are not guessed successful.
- Navigation reads/attaches and does not replay, stop or submit a task. This fixes presentation/state restoration, not the APK being analyzed.

## Validation boundary

Four regression assertions failed on the merged baseline. Coverage includes local/SSH pane remounts, intermediate narration, live failure/completion racing a running attach, explicit terminal statuses, and a queued follow-up racing a completed attach. Existing cloud and transport tests remain enabled. Automated hook tests do not replace manual Settings/back navigation in the new Windows installer.
