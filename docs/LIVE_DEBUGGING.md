# Supervised live debugging

Cline Enhanced exposes live debugging separately from static reverse engineering. The `live_debugger` tool uses an installed GDB or LLDB executable for bounded, one-shot local debugger invocations.

## Safety contract

- Every operation except `discover` requires `acknowledge_risk: true`.
- The caller must own or be explicitly authorized to inspect the process or executable.
- Targets launched under the debugger must be absolute local file paths.
- Attach operations require an explicit positive PID.
- Remote debugging is rejected; use device-specific tooling for authorized devices.
- There is no hidden persistent debugger connection. Each request launches one supervised debugger process, gathers bounded output, detaches when applicable, and exits.
- Timeouts and cancellation terminate the debugger process tree.

## Operations

- `discover`: report available GDB/LLDB commands and versions.
- `launch`: start an authorized executable under a debugger, stop at a named breakpoint or program entry, and collect a backtrace and registers.
- `attach_snapshot`: attach, collect a backtrace and registers, detach, and exit.
- `backtrace`, `registers`, `read_memory`, and `disassemble`: bounded one-shot inspection of an attached process.
- `continue` and `step`: perform bounded execution from the initial stopped state, collect evidence, detach, and exit.

This interface deliberately does not accept arbitrary debugger command strings, silently elevate privileges, bypass operating-system protections, or maintain a background session.
