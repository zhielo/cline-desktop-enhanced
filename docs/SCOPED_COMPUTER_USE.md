# Scoped computer use

Cline Enhanced exposes an optional Windows-only `computer_use` tool for applications that do not provide a safer structured API, MCP server, browser protocol, or specialized tool.

## Enablement

Computer use is disabled by default. In **Settings → General → Scoped computer use**, add exact absolute Windows `.exe` paths, then enable the feature. The host refuses every `start` request until this explicit opt-in is stored; restricted permission profiles continue to block the tool.

Starting control requires the model to provide the exact allowlisted executable and `acknowledge_risk: true`. The application must already be running. A visible banner remains on screen while any computer-control session is active, and **Stop and take over** immediately invalidates the sessions and deletes their retained screenshots.

## Supported operations

- `start` and `stop` an owner-agent-scoped control session;
- `list` only sessions owned by, or explicitly delegated to, the requesting agent;
- `delegate` a short lease to one exact child-agent ID, with both an expiry and
  a maximum action count, and `revoke_delegation` immediately;
- `observe` the foreground allowlisted window, including a bounded accessibility tree and optional screenshot evidence;
- `click` an accessibility selector, with coordinates as a fallback;
- `type` through UI Automation `ValuePattern` only;
- send a small allowlist of navigation keys;
- perform bounded wheel scrolling;
- wait briefly for an accessibility selector.

The model should observe before every action and prefer `automation_id`, accessible name, and control type over screen coordinates.

## Safety boundary

- Foreground executable identity is revalidated before every observation or action. Control pauses if focus leaves the allowlisted executable.
- Password controls, UAC/security processes, arbitrary key combinations, clipboard-based typing, and unbounded retries are rejected.
- A session is limited to 200 actions and 15 minutes.
- At most 10 screenshots are retained per session under the private Cline data directory; older captures and stopped-session captures are deleted.
- Session ownership is enforced using both the host-provided session ID and
  agent ID. Child agents cannot start control, delegate it onward, or stop the
  owner's session. They can act only while an explicit owner-created lease
  remains unexpired and has actions remaining.
- Aggregate local diagnostics record only counts and durations: sessions,
  completed sessions, actions, accessibility/coordinate actions, focus-loss
  pauses, takeovers, failures, and total active duration. They never store
  executable paths, window titles, selectors, typed text, screenshots, user
  identity, or send telemetry externally.
- Computer use is not an operating-system sandbox and cannot bypass Windows permissions, authentication, application authorization, or secure-desktop boundaries.

## Routing policy

Use tools in this order:

1. built-in structured tool;
2. MCP or application API;
3. Windows UI Automation;
4. screenshot-guided targeting;
5. raw coordinates only as a last resort.

Android, browser, Git, IDA, Ghidra, JADX, debugger, and filesystem work should continue to use their existing structured integrations.

## Validation

Focused tests cover opt-in and allowlist enforcement, owner/agent isolation,
bounded delegation and revocation, takeover, privacy-safe metrics, settings
validation, tool registration, and permission-profile denial. The existing
Windows installer test command now also launches a deterministic WinForms
fixture. On an interactive Windows desktop it verifies real UI Automation
observation, safe text entry, button invocation, and password-control denial.
Hosted runners that expose no interactive UI Automation tree still verify
foreground process scoping and report the action portion as a capability skip
instead of hanging. The workflow remains unchanged and artifact-only.

Further native Windows validation should exercise DPI scaling, multiple
monitors, modal dialogs, stale accessibility elements, focus theft, app
crashes, and screenshot expiry.
