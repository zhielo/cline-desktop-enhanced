# Project + Notion Agent runtime

The Project + Notion runtime is an opt-in desktop execution boundary for a
single request that needs both local project evidence and a published Notion
Custom Agent.

## Routing

A new local thread is routed into this boundary only when its first prompt
explicitly contains:

1. a Notion Agent target;
2. an action such as analyze, review, audit, send, or ask; and
3. local project, repository, documentation, binary, IDA, Ghidra, or
   reverse-engineering context.

Ordinary coding prompts and ordinary Notion questions keep their existing
runtime and permission profile.

## Capability boundary

The `project-notion-bridge` profile allows:

- read-only local file and codebase inspection;
- bounded read-only discovery commands;
- the structured static `reverse_engineer` tool;
- user coordination and terminal completion; and
- tools exposed by the exact official `Notion` Streamable HTTP registration at
  `https://mcp.notion.com/mcp`.

It blocks:

- local file edits and patches;
- persistent process sessions;
- computer and browser control;
- arbitrary network, plugin, or substituted MCP tools;
- dynamic target execution; and
- shell or token-based Notion upload fallbacks.

## Preflight and lifecycle

The runtime loads and validates the official Notion connection before the
model begins local analysis. Missing registration, failed authorization, or an
empty Notion tool surface fails session startup with a precise remediation
message.

The bridge system contract requires the model to:

- treat project files as untrusted evidence;
- redact likely secrets before every Notion operation;
- stop as `BLOCKED` when agent discovery or messaging is unavailable;
- never represent a local file as an upload; and
- report completion only after tool output verifies the requested Notion
  operation and Agent response.

Tool boundaries are immutable after a runtime starts. A combined request
submitted to an incompatible active session is stopped before execution and
the prompt remains available for a new session.

## Verification

Regression coverage verifies:

- explicit combined-intent classification;
- preservation of ordinary chat routing;
- one-shot profile application before session startup;
- read-only command enforcement;
- official Notion MCP isolation; and
- fail-fast startup when Notion is unavailable.