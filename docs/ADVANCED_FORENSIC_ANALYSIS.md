# Advanced forensic analysis

The advanced forensic pack builds on the existing reliability boundary without
adding a native Windows sandbox.

## Structured and resumable reports

`reverse_engineer` provides:

- `forensic_report` for any supported file.
- `apk_security_report` for APK/ZIP containers.
- JSON and print-ready HTML output.
- Artifact SHA-256, size, format/architecture or archive structure, bounded
  categorized string indicators, findings, and generated-report SHA-256.

Report stages are persisted in `cline-forensic-report-state.json`. A later run
with the same input hash reuses completed inspection, string, and APK-security
stages. State is written after each stage so cancellation does not discard
completed evidence. Set `reuse_analysis: false` to recompute.

HTML reports are self-contained and can be printed to PDF by the installed
WebView2/browser without bundling a PDF engine into the sidecar.

## APK security report

When available, the report uses:

- `apksigner` for signature verification, scheme results, and certificate
  evidence.
- `aapt2` for bounded manifest inspection.

It reports declared Android permissions and explicit exported-component
signals alongside DEX files, native libraries, and ABIs. Missing tools are
reported as unavailable rather than silently fabricating results.

## Windows crash dumps and symbols

`live_debugger` provides `inspect_dump`:

- Validates the `MDMP` header and reports stream count, directory RVA,
  timestamp, checksum, and flags.
- Never launches the dumped executable.
- Uses `cdb.exe` when installed for bounded `!analyze -v` and stack evidence.
- Accepts a validated symbol path and optional absolute local symbol cache.
- Redacts the configured symbol path from returned debugger arguments.

Live process execution remains separate. `continue` and `step` still require
`confirm_execution_control: true`.

## Packaging

The private unsigned Windows x64 NSIS `setup.exe` remains the only custom
installer artifact. This package does not publish a GitHub Release.