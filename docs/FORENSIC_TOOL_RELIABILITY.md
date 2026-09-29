# Forensic tool reliability

This package hardens the specialized reverse-engineering, live-debugger, and
Android-device tools without adding a native Windows sandbox.

## Reverse engineering

- String filters are literal by default. Regex use is explicit and rejects
  oversized patterns, backreferences, and common nested-quantifier forms that
  can cause excessive backtracking.
- Outputs under the reverse-engineering cache, the operating-system temporary
  directory, or `CLINE_RE_OUTPUT_ROOT` are classified as managed.
- Any other output destination requires
  `acknowledge_external_output: true`.
- Future output paths are resolved through their nearest existing real parent,
  preventing a symlink or Windows reparse-point parent from silently escaping a
  managed root.
- Generated artifacts up to 256 MiB include SHA-256 evidence. Larger artifacts
  report that hashing was skipped rather than performing unbounded work.
- Analysis manifests record whether output was managed or explicitly approved.
- Target binaries are analyzed as data and are never executed automatically.

## Live debugger

- One-shot backtrace, register, memory, and disassembly operations are reported
  as `inspect-only`.
- `continue` and `step` resume target execution and therefore require both
  `acknowledge_risk: true` and `confirm_execution_control: true`.
- Remote debugging, arbitrary debugger command strings, and hidden persistent
  sessions remain unavailable.

## Android device

- Captured textual output passes through the shared secret redactor.
- Screenshot results include SHA-256 evidence.
- Install and uninstall require `confirm_package_change: true`.
- Deleting logcat history requires `confirm_log_clear: true`.
- Unrestricted shell still requires `acknowledge_risk: true`; its arguments are
  not returned.

## Build policy

The existing private unsigned Windows x64 NSIS `setup.exe` workflow remains the
only packaging path. This package does not publish a GitHub Release and does not
add native Windows sandboxing.