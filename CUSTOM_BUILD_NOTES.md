# Customized Cline Desktop build

This source tree extends the supplied Windows reverse-engineering fork.

## Included behavior

- **Full Access** is the only approval mode shown in the desktop composer and
  is enabled by default. A legacy internal Cline mode value drives the
  auto-approval policy but is never displayed to users.
- Full Access keeps code search, batched commands, patch/editor, web fetch,
  configured skills, and reverse-engineering tools enabled.
- `reverse_engineer` supports:
  - installation discovery for Ghidra, IDA Pro, and JADX;
  - bounded ZIP/APK/AAB/JAR inspection;
  - safe extraction with traversal, symlink, duplicate, encryption,
    compression-ratio, entry-count, per-file, total-size, CRC, and output-root
    checks;
  - APK DEX/native-library inventory without executing APK content;
  - supervised headless analysis with timeout, cancellation, process-tree
    termination on Windows, and bounded output;
  - detached GUI handoff;
  - Ghidra script-path setup and per-artifact project names;
  - IDA batch database/log destinations, quoted script arguments, and bounded
    Hex-Rays batch output when the installed license supports it.

Full Access removes Cline's repeated tool approval prompts. It intentionally
does **not** bypass Windows UAC, filesystem ACLs, remote authentication, IDA
licensing, or the parser/resource limits above.

The custom Windows package is branded **Cline Enhanced** and uses its own
application identifier. The upstream Cline update endpoint is removed so an
official upstream update cannot silently replace this customized build.

## Build

Use Bun 1.3.13 and Node 22 or later:

```powershell
bun install
bun run build:sdk
cd apps/examples/desktop-app
bun run typecheck
bun run test:chat-ui
bun run build
```

For a native Windows package, install the Tauri prerequisites documented by the
upstream desktop example, then use its package command.

## Reverse-engineering setup

Set `GHIDRA_HOME`/`GHIDRA_INSTALL_DIR`, `IDA_HOME`/`IDADIR`, or `JADX_HOME`, or
put the launchers on `PATH`. Open **Settings → MCP Servers** for the optional
PyGhidra and IDA idalib MCP setup. The built-in `discover` operation reports
the exact detected paths and optional activation guidance.

Run `inspect` before unknown files and before `extract`. Extraction requires a
new output directory and deletes that directory if extraction fails, so partial
artifacts are never presented as complete.

## Validation status

The archive inspection/extraction paths were smoke-tested with:

- a clean stored ZIP;
- a ZIP containing `../` traversal;
- extraction refusal for the unsafe archive;
- a non-ZIP binary inspection.

Run the repository's Bun test and build commands on the target Windows build
machine before distribution. This workspace did not contain the repository's
installed Bun dependencies, so a full monorepo build was not performed here.

The manual GitHub Actions workflow at
`.github/workflows/build-custom-windows-installer.yml` performs that native
Windows build and uploads a single NSIS `setup.exe` artifact plus its SHA-256
checksum. The workflow intentionally creates an unsigned private test build;
Windows may show a SmartScreen warning until the installer is Authenticode
signed with the publisher's certificate.