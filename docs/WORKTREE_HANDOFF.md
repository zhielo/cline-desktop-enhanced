# Managed worktree isolation and handoff

Substantial local tasks can start in a managed worktree under
`<CLINE_DIR>/worktrees/<id>/<repo>`. Creation records a durable identity, source
repository, exact source revision, base branch, generated branch, and timestamp
in a private `worktree.json` beside the checkout. The original checkout is not
modified when the worktree is created.

## Handoff status

The desktop inspects both checkouts before any handoff and reports uncommitted
changes, unresolved conflicts, the current branch, commits ahead of the source
revision, and whether the local checkout is dirty. Handoff is blocked when the
chosen action could overwrite dirty or conflicting state.

Managed-worktree sessions expose five explicit actions:

- **Apply to Local** — cherry-picks committed task changes, in order, only when
  both checkouts are clean. A conflict aborts the cherry-pick and restores the
  local checkout.
- **Create Branch** — renames the task branch without switching or modifying
  the original checkout.
- **Open PR** — requires committed, conflict-free work, pushes the current
  branch without an interactive credential prompt, then creates a PR through
  authenticated GitHub CLI.
- **Keep** — marks the worktree retained so deleting the chat does not remove
  it.
- **Discard** — requires a separate explicit confirmation, force-removes only
  the managed worktree, prunes stale worktree metadata, and independently
  deletes only the generated `cline/<id>` branch.

Cleanup is idempotent. Durable metadata lets cleanup remove a stale generated
branch even if the checkout was already partially deleted. User-created or
renamed branches are preserved.

## Boundaries

Handoff does not bypass Git conflicts, local filesystem permissions, GitHub
authentication, or branch protection. Uncommitted work is never applied or
discarded without the corresponding explicit user action.

The unsigned Windows x64 installer remains artifact-only for private testing;
this feature does not publish a GitHub Release.
