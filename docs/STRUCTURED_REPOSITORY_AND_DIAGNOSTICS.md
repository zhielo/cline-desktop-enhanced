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
- `github_status` through the existing GitHub CLI credential store

Every remote operation requires `confirm_remote: true`. Ref and remote names are validated and paths must remain relative to the active workspace. Commands use fixed argv execution with terminal prompting disabled. Tokens are never accepted as tool input or returned in output.

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
