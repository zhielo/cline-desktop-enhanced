# IDA readiness and execution progress

## Setup without manual dependency scripts

Install the newly built Windows executable, then open Settings → Analysis environment → Open Setup Center. The desktop build commit identifies the installed revision; merging a PR does not update the local app. Core and full are independent runtime selections. Install the full pack only after accepting its notices; apply saved settings only to an idle compatible backend. Running work is never forcibly restarted.

Select the authorized IDA installation and the needed processor (x86-64 or ARM64). Test licensed IDA saves that folder and decompiles one fixed owned ELF without executing it. An ARM64 receipt does not validate x86-64, every license, arbitrary targets or physical devices. The matching licensed Hex-Rays plugin must come from the user's installation. Receipt freshness binds the executable bytes, not only its folder name. Explicit IDA folder selection takes precedence over Windows registry refresh, PATH and other discovered installations; a missing selected executable fails instead of silently falling back. Missing Triton, angr or QBDI in a core Python inventory does not establish an IDA problem.

## Execution

Fixed scripts initialize the processor-matching decompiler before waiting for auto-analysis. They do not skip analysis, guess a containing function or decompile all functions when selection fails. One-shot IDA reports explicit phases and PID in the tool row; expanding it retains bounded progress history. Heartbeats are host observations, not proof that the process is healthy or making semantic progress.

The overall timeout remains 15 minutes by default (timeout_ms). The one-shot unchanged-phase deadline is five minutes by default, capped by the overall deadline. ida_phase_timeout_ms explicitly adjusts that phase limit (1 second to 1 hour; still capped by overall). Large binaries may need a larger reviewed phase budget. A phase deadline is an enforced budget, not a diagnosis of a hung engine. Custom scripts may emit no phases and still need an explicit budget. Managed workers report owned PID/readiness/request mailbox states with a 30-second waiting heartbeat, explicitly not script-phase or liveness proof. They retain their separate mailbox/idle/lifetime deadlines and explicit opt-in, with no automatic restart or replay.

An aborted process gets a two-second drain window. When termination/EOF cannot be confirmed, the result stays unsuccessful and termination-unconfirmed; project leases remain held. Refreshing diagnostics does not kill a process, steal a lease or relaunch a job. The user's normal Stop/Esc control requests cancellation through the owning execution path. Do not terminate arbitrary IDA processes by name or reuse a PID as an ownership guarantee.

## Diagnostics

Optional live IDA job refresh polls the read-only endpoint every two seconds, serially, while enabled on the visible analysis page. It stops on unmount. PID, last script phase, elapsed time, overall deadline and phase deadline are last recorded host/script evidence, not a fresh process-identity probe. Completed durations freeze at the observation end. Never infer progress from CPU totals or output-file presence.

## Validation boundaries

Blocking tests cover deterministic ELF bytes, phase deadlines, bounded cancellation uncertainty, stale same-path executable replacement, architecture-specific requests, UI navigation and progress visibility. Hosted CI cannot validate a user's commercial license, physical device or packed application's correctness. Windows installer smoke and the full installed engine/restart/Hub/core-rollback journey remain required before merging.
