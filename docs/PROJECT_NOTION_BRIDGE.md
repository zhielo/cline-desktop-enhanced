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

## Evidence-grounded review loop

Large projects use a deterministic evidence protocol rather than a single
summary or repository upload:

1. Cline inventories the project with stable evidence IDs, paths, kinds,
   priorities, byte sizes, hashes when available, and sharing status.
2. Safe text evidence is split into bounded batches. Binary files remain
   metadata-only; raw executable bytes and repository archives are never sent.
3. The manifest is delivered first, followed by every batch in order to one
   Custom Agent session.
4. The Agent cites evidence IDs and may request exact paths, line ranges,
   symbols, tests, or binary regions.
5. Cline validates, reads, and sanitizes those requests locally for at most
   four rounds, recording fulfilled, denied, and unavailable evidence.
6. Before context grows too large, the Agent produces a checkpoint summary.
7. Completion returns separate Cline and Agent analyses, agreements,
   disagreements, confidence, missing evidence, and prioritized actions.

The Functions screen exposes Quick, Deep, and Forensic review depths. It can
persist one visible project-memory page containing the manifest, batch index,
checkpoint, consensus, and source Agent session URL. A connected Notion
account is sufficient; no pre-created database is required.

## Long-running Agent sessions

Project + Notion sessions apply a host-owned five-minute MCP request floor and
use status polling with a ten-minute overall processing budget. A transport
timeout is treated as an indeterminate running state, not proof that delivery
failed. The exact Agent session URL is retained so the same session can be
resumed after a timeout or app restart.

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