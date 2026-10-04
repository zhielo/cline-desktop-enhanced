# Engineering Control Center

The Engineering Control Center is a separate desktop workspace for durable engineering missions, project posture, secure-execution policy, Git review risk, and model-routing evidence. It is intentionally additive: standard Cline chat, provider selection, permission profiles, Notion Functions, and the Analysis workbench keep their existing behavior.

## Normal chat isolation

Opening Engineering does not create or reconfigure a chat session. It does not change the selected model, grant a permission, enable tool auto-approval, call Notion, create a worktree, run a command, or merge a branch. The first release deliberately makes planning separate from execution so a future orchestrator cannot silently inherit normal-chat authority.

## Durable control plane

Device-local state is stored in `engineering-control-plane.db` under the normal Cline data directory. SQLite uses WAL, foreign-key enforcement, and a busy timeout. The database records:

- bounded project profiles;
- project execution policies;
- dependency-validated mission DAGs;
- append-only policy and mission events;
- privacy-safe model outcomes.

A sidecar restart marks a running mission interrupted rather than claiming it completed. Mission planning rejects duplicate or empty task IDs, missing dependencies, self-dependencies, and cycles. Repository-writing tasks are marked as requiring isolated worktrees.

## Trust boundary

The control plane evaluates a request before an execution backend is selected. The default policy is:

- restricted execution tier;
- network denied;
- 20-minute runtime limit;
- 32-process limit;
- worktree required for repository writes;
- independent review required;
- sandbox escalation for untrusted scripts and package installation;
- isolated VM escalation for unknown binaries and debugger activity.

Protected host paths, denied networking, missing worktree isolation, and excessive runtime fail closed. Existing request-bound Analysis approvals remain a second boundary for Analysis tasks.

This module does not execute a mission. It produces durable plans and policy decisions for later executors. A positive policy decision is not a security sandbox and is never authority to bypass existing tool approval or permission-profile enforcement.

## Windows containment

Restricted host execution, Windows Sandbox, and an isolated VM are distinct tiers:

1. **Read only** performs inspection without writes or process execution.
2. **Restricted** is for known project commands under host permission and resource controls.
3. **Windows Sandbox** is for disposable, attested workers with denied networking by default.
4. **Isolated VM** is required for unknown binaries, malware-like samples, and debugger-driven dynamic analysis.

The desktop does not claim to provision Windows Sandbox, Hyper-V, or remote infrastructure automatically. Until an attested external worker is configured, untrusted dynamic execution remains blocked instead of falling back to the host.

## Project discovery

Discovery is bounded to 10,000 files and skips dependency, output, cache, and hidden directories. It records counts and configuration metadata—not source content. It detects:

- primary languages;
- package managers;
- package build/test scripts;
- Git repository and branch;
- common CI providers;
- known sensitive root files.

Detection is advisory and user-correctable. A detected command is never automatically executed.

## Git review risk

The initial risk engine is transparent and deterministic. It scores:

- broad or very large changes;
- sensitive files;
- dependency modifications;
- public API changes;
- migrations or schema changes;
- failing checks;
- absence of new tests.

The result includes the exact reasons and a conservative merge decision. It is a merge-gate input, not a substitute for tests or human review.

## Model routing

The router ranks only candidates supplied by the application. It considers required capabilities, context window, observed success, tool reliability, latency, and cost. Missing a required capability is heavily penalized. The ranking and reason are returned to the UI; users can continue to lock a specific provider and model.

No prompt, source file, credential, command output, or Notion content is stored as a model outcome. Outcomes are limited to model ID, task kind, success, duration, cost, and timestamp.

## Follow-on executors

Future releases may consume the control-plane contracts to add:

- a signed Windows Sandbox worker;
- worktree lease ownership;
- parallel mission scheduling;
- semantic-diff review councils;
- merge-candidate preparation;
- provider evaluation dashboards;
- optional Notion project reporting;
- IDA/Ghidra isolated workers.

Each executor must preserve the existing permission profile, tool approval, worktree, evidence, and attestation boundaries rather than treating a stored mission as implicit approval.
