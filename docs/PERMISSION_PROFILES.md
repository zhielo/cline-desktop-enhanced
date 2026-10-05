# Permission profiles

Cline Enhanced supports optional host-enforced capability profiles in local
session configuration:

- `read-only`: structured repository reads, file inspection, search, skills,
  questions, and coordination. Arbitrary shell and interpreter execution is denied.
- `workspace`: local workspace reads, edits, commands, and process sessions;
  network, device, debugger, reverse-engineering, and unclassified plugin/MCP
  tools are denied.
- `workspace-network`: the workspace profile plus built-in web-fetch and web
  search tools.
- `full-access`: preserves the existing Full Access behavior.
- custom profiles: explicit capability booleans plus tool allow/deny lists.

The guard runs as a `beforeTool` runtime extension, before approval and tool
execution. It is inherited by delegated agents, so a child cannot gain a wider
tool surface merely by being spawned.

Permission profiles are technical enforcement and remain separate from approval
UX. A profile can deny a tool even when it would otherwise be auto-approved.

The desktop General settings page persists one of the four built-in profiles
for new local sessions. When no preference exists, the sidecar applies
`full-access`, matching the desktop composer's existing Full Access/Yolo
contract. Restricted profiles are explicit choices; changing the setting
affects new sessions and cannot be silently weakened by omitting the field from
a webview request. SDK hosts that omit `permissionProfile` retain their existing
host-selected behavior.

## Security boundary

These are capability profiles, not an operating-system sandbox. They constrain
which registered tools may run. `read-only` and `project-notion-bridge` deny
`run_commands` entirely instead of relying on a bypassable command blacklist.
Structured repository reads accept only status, diff, log, and branches; Git
diffs disable external diff and textconv execution. Commands in profiles that
allow execution still have the OS permissions of the Cline process. Native filesystem and network isolation must
be added by the host when containment against arbitrary shell behavior is
required.

The unsigned private Windows installer workflow and no-release policy are
unchanged.