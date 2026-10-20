# Evidence-backed desktop task reporting

## Shipped surface

Chat, Analysis and Reports expose the same session-scoped transcript projection. The compact task panel remains available after a run stops; Reports retains up to 50 turns from available history and up to 200 execution entries per turn. Historical running entries explicitly lack a terminal receipt: reopening a report never reattaches, resumes, approves or executes work.

A task report separates execution from outcome and records goal/scope, plan-marked deliveries, declared checks, missing verification, blockers, scope changes, artifacts, execution evidence and a next action. Plan completion is not verification. Only a nonempty passed host-validation receipt for the exact current plan/step/declared scope can support “Declared checks passed.” This is not a claim about semantic correctness, installed builds, CI or merge status.

Local history restoration decorates existing exact-session/call/tool transcript rows from a bounded local host-log tail. Missing/malformed/truncated logs are unavailable evidence, not success. Remote transcripts are never decorated with same-ID local receipts. Optional malformed reporting metadata is ignored without dropping the chat message or crashing tool execution.

Analysis results show bounded findings, provenance fields and limitations before collapsed redacted raw output. Data, code, comments and findings remain untrusted input, not AI instructions. Analysis navigation is grouped into Overview, Tools, Evidence, Runtime (opt-in) and Diagnostics; existing permissions and runtime approval boundaries are unchanged.

## Sharing and limits

Copy summary, Markdown, structured JSON and inert print-ready HTML exports are available. Redaction is best-effort, not a secret-free guarantee; review before sharing. Exports do not include raw tool-output dumps by default. Evidence and text have explicit bounds; missing history may omit operations. Receipts are recorded host state, not live process checks or current-file freshness checks.

No additional model call, paid model fixture, tool execution, automatic retry, approval or session replay is needed to view/export a report. Existing full-power analysis engines and coding surfaces remain unchanged.

## Verification

The task-report gate includes schemas, strict projection, validation authority and stale-check invalidation, session isolation, bounded local disk restoration, persisted offline-message projection, redaction/exports and UI states. Installed Windows acceptance checks an owned offline model-plan/partial-result transcript without granting host verification, then reopens it after desktop restart. Existing release gates remain mandatory; the installed-stage policy adds these two reporting stages rather than replacing earlier checks.
