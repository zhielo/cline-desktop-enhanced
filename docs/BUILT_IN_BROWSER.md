# Lightweight built-in browser

Cline Enhanced exposes a structured `browser` tool in the Windows desktop app.
It opens an isolated Tauri WebView window and controls that window through the
existing WebView2 runtime's Chrome DevTools Protocol (CDP). No second Chromium
distribution is bundled, so the installer remains lightweight.

## Capability order

Agents should prefer:

1. APIs and MCP integrations;
2. `fetch_web_content`;
3. the structured built-in `browser`;
4. screenshot interpretation;
5. `computer_use`.

## Supported operations

- start, list, navigate, back, forward, reload, and stop;
- inspect visible interactive elements;
- click, type, select, and check using role, accessible name, text, test ID, or
  a CSS fallback;
- wait for an element to appear or disappear;
- capture a bounded screenshot response.

The browser accepts only HTTP(S) destinations. Sessions are owner-scoped,
limited to eight concurrent windows, and expire after 30 minutes of inactivity.
Child agents cannot create browser sessions.

Password fields are rejected. Controls whose label appears consequential
(purchase, payment, submission, sending, publishing, deletion, confirmation,
acceptance, or booking) require `confirm_consequential: true`. The normal Cline
tool-approval policy still applies.

Permission profiles treat the browser as a network capability. Read-only and
workspace profiles block it. Workspace + network allows navigation and
inspection but blocks state-changing browser actions. Full Access permits
interaction.

## Security boundary

This is structured application automation, not an operating-system sandbox.
Page content is untrusted. The tool does not expose raw CDP methods to the
model, does not target password inputs, and does not import the user's regular
browser profile. Authentication remains user-driven in the visible browser.

The first implementation is Windows-only because it uses WebView2 CDP through
Tauri. Other desktop platforms return an explicit unsupported error instead of
silently falling back to generic computer control.