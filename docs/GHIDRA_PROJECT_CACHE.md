# Ghidra project cache paths

Ghidra rejects a project location when any path component starts with a dot.
The shared `~/.cline/reverse-engineering` default was therefore unsuitable for
Ghidra projects even when Java and Ghidra themselves were healthy.

Ghidra now defaults to `~/cline-analysis-cache/reverse-engineering/<input SHA-256>/ghidra`.
Other engines retain their existing cache locations. Existing files are not
moved or deleted; the first use of the new Ghidra cache imports the target again.
Exact-input project reuse, leases, engine fingerprints, and fresh verification
receipts remain required.

An explicit `output_directory` takes precedence. Otherwise, `CLINE_RE_CACHE_DIR`
still overrides the cache root. These user-selected paths are not silently
rewritten. Every Ghidra project location is checked before directory creation
and engine launch, including the physical location behind existing parent
symlinks/junctions. Dot-prefixed components produce an actionable error.
For example, use `C:\ClineCache` rather than `C:\Users\name\.cline`.
Restart the backend after changing its environment variables.

This check also applies to temporary (`reuse_analysis: false`) project
directories. Disabling reuse is not a reliable fix if the temporary directory
itself is under a dot-prefixed parent. A home directory with a dot-prefixed
component similarly requires a compatible explicit cache or output location.

Unit tests cover Windows/UNC/POSIX paths, missing parents, junction/symlink
aliases, default cache selection and verified reuse. The real Ghidra owned
fixture gate additionally imports and reopens the persistent cache and checks
the invalid-path preflight. These checks do not claim compatibility with every
target or execute target code.