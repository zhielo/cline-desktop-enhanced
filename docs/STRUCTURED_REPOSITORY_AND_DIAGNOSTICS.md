# Structured repository, browser diagnostics, and recovery center

This package extends Cline Enhanced without adding native Windows sandboxing and without changing the private unsigned installer policy.

## Structured repository tool

The desktop registers a host-owned `repository` tool for the active local workspace.

Read operations:

- `status`
- `diff` (working tree or staged, optionally one relative path)
- `log` (bounded to 100 entries)
- `branches`

Local writes:

- `create_branch`
- `switch_branch`
- `commit` (optionally stage an explicit relative-path list)

Every local write requires `confirm_write: true`. The tool does not expose reset, clean, branch deletion, force checkout, amend, rebase, or force push.

Remote and GitHub operations:

- `fetch`
- fast-forward-only `pull`
- non-force `push`
- the native `composio_integrations` GitHub connector, which uses the signed-in Cline account's browser OAuth flow
- connected GitHub tool schemas are persisted as non-secret metadata and registered into new agent sessions
- the connector exposes GitHub repository, issue, pull request, review, comment, and related automation tools without GitHub CLI

Local `fetch`, fast-forward-only `pull`, and non-force `push` still require `confirm_remote: true`; ref, remote, and path validation remain unchanged. Connector credentials stay behind the Cline API connector proxy and are never accepted as tool input or returned in output.

Permission profiles enforce three boundaries:

- Read only: repository inspection only.
- Workspace: inspection plus local branches/commits.
- Workspace + network and Full Access: inspection, local writes, and confirmed remote/GitHub operations.
- Plan mode does not expose the repository tool, preventing a separate mutation route around the read-only command guard.

## Browser page diagnostics

The built-in browser adds `page_info`, returning only metadata needed for troubleshooting:

- URL origin and title;
- document readiness and language;
- frame, form, link, and resource counts;
- navigation duration;
- local/session storage key counts.

It does not return cookies, storage values, passwords, typed content, authorization headers, or arbitrary JavaScript results. Multiple isolated browser sessions remain available through `start`, `list`, and `stop` within the existing eight-session and idle-expiry limits.

## Diagnostics center

Settings → Diagnostics displays a sanitized local health summary:

- Hub connection state and sanitized error;
- app version and platform;
- selected permission profile;
- running local session count;
- browser and computer-control session counts;
- PowerShell optimization evidence state.

The copied report intentionally excludes prompts, typed browser content, credentials, URLs, workspace/repository paths, and browser targets. The page can stop all stale built-in browser sessions and refresh state without restarting the app.

## Build and release policy

The unsigned Windows x64 NSIS workflow remains artifact-only. Its required preflight now includes repository, permission-profile, runtime-catalog, browser, full desktop regression, type-check, SDK build, task-report, and customization-preservation tests before packaging. It does not create a GitHub Release.
