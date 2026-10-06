# Long-session edit and recovery

## Symptoms and scope

`Desktop command timed out waiting for chat_session_command` identifies the
desktop RPC waiter, not proof that the Hub rejected the operation. Large
transcripts, checkpoint restoration, and runtime/MCP initialization may take
longer than lightweight metadata commands.

The Hub allows ten minutes for `session.create` and `session.restore`. Desktop
`start`, `attach`, `fork`, and `restore_checkpoint` commands allow the same
budget plus thirty seconds for response delivery. A caller's explicit timeout
still wins. Status/queue/control commands retain their ordinary deadlines.
This is a bounded reliability measure, not a claim that operations normally
take ten minutes or that a hung server should be ignored.

## No automatic replay of sends

A lost acknowledgement does not prove a prompt was rejected. The send RPC
represents the complete model/tool turn, and retains an unbounded command
waiter while the runtime's cancellation/provider limits remain active.
Transport close still rejects the waiter. The desktop client never replays
arbitrary sends merely because a timeout occurred.

Edit forks already carry a stable operation ID. A recoverable disconnect or
lifecycle timeout first queries `fork_status`, reuses a completed result when
available, and permits at most one retry of the same idempotent operation.
The sidecar coalesces an in-flight operation and checks persisted fork metadata.
Authentication errors are never treated as edit transport retries.

When re-attachment fails, visible messages from the same session are retained
with an error row. Switching to a different session does not carry those
messages across the session boundary.

## Authentication is separate

`Unauthorized` from a model provider is distinct from a desktop RPC timeout.
The runtime already attempts a single OAuth refresh and continues from its
persisted message/tool trail. Regression coverage exercises a long ClinePass
history and confirms that completed tool evidence survives continuation.

Revoked credentials, a missing refresh token, invalid account entitlement, or a
provider rejecting refreshed credentials still require provider/account
diagnostics and possibly a fresh sign-in. Do not bypass authentication, retry
indefinitely, clear the chat database, or replay completed tools to conceal it.
Screenshots alone do not identify which credential condition occurred.

Before reporting a remaining failure, record the installed build's commit/run,
the session ID, the action (edit, resume, attach, or send), and timestamps.
Inspect the matching desktop and `hub-daemon.log` entries. Redact tokens,
authorization headers, personal content, and sensitive file paths before sharing.

## Required regression checks

- Shared Hub lifecycle deadline and explicit override tests.
- Desktop deadlines beyond two minutes, bounded expiry, explicit overrides,
  and transport-disconnect behavior.
- Edit reconciliation after an ambiguous timeout, without retrying provider
  authorization failures or unrelated commands.
- Same-session transcript retention and different-session isolation.
- ClinePass OAuth continuation with long history and completed tool results.

The consolidated Windows installer gate runs these checks before packaging.
Native Windows installer/startup validation remains required; Linux source tests
alone are not installer proof.