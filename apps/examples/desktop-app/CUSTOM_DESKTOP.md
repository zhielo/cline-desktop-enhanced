# Cline Desktop Power Tools

This fork adds an explicit **Full Access** profile, hardened binary handling, supervised reverse-engineering tools, and one-click Notion MCP setup.

## Execution profiles

- **Plan**: read-oriented planning with guarded commands.
- **Act**: normal interactive development.
- **Full Access**: maps to Cline's existing `yolo` preset, enabling and auto-approving tool calls. Read/search, batched commands, patch/editor, web fetch, configured skills, and reverse-engineering tools remain available so this profile does not trade speed for missing coding capabilities. It does not bypass operating-system permissions, remote-service authentication, parser limits, or licensing.

## Reverse engineering

The built-in `reverse_engineer` tool supports discovery, safe ZIP inspection, headless analysis/decompilation, scripts, and GUI handoff.

Configure installed tools with `GHIDRA_HOME`/`GHIDRA_INSTALL_DIR`, `IDA_HOME`/`IDADIR`, or `JADX_HOME`, or put launchers on `PATH`. IDA requires a valid installation and license; this fork does not bypass licensing.

Example:

```json
{
  "engine": "auto",
  "operation": "analyze",
  "target": "/absolute/path/to/sample.bin",
  "timeout_ms": 300000
}
```

APK, AAB, DEX, and JAR inputs prefer JADX when installed. Ghidra uses `analyzeHeadless`; IDA uses autonomous mode; child output is bounded and timed out. ZIP inspection reads only the central directory and does not extract files.

## Binary and media safety

`read_files` detects PNG, JPEG, GIF, and WebP from signatures rather than extensions, rejects spoofed image names and unknown binary payloads, retains size/line/output limits, and processes at most three files concurrently.

## Notion

Settings → MCP Servers → **Connect Notion** installs the official Streamable HTTP endpoint `https://mcp.notion.com/mcp` and starts the existing browser OAuth flow. Interactive OAuth is required by Notion. This provides workspace tools to Cline; it does not claim private Notion model APIs or a Cline MCP server for Notion Custom Agents.

## Build and validation

Use the repository-required Bun toolchain:

```bash
bun run build:sdk
cd apps/examples/desktop-app
bun run typecheck
bun run test:sidecar
bun run test:chat-ui
bun run build:web
bun run build
```

## Windows setup for Ghidra 12 and IDA 9.x

The reverse-engineering executor now searches the normal Windows application locations in `Program Files`, `Program Files (x86)`, and `%LOCALAPPDATA%\\Programs`. For portable Ghidra distributions it also checks Ghidra-named directories under `%USERPROFILE%` and `%USERPROFILE%\\Downloads`. Explicit `GHIDRA_INSTALL_DIR`, `GHIDRA_HOME`, `IDADIR`, and `IDA_HOME` values still take precedence.

Ask Cline to **discover reverse-engineering tools** or call:

```json
{
  "engine": "auto",
  "operation": "discover"
}
```

The result reports the detected headless and GUI launchers, Ghidra's bundled PyGhidra wheel directory, and IDA's idalib activation script. For IDA 9.0–9.3, activate idalib once using the exact command returned by discovery. This uses the installed licensed IDA instance and does not alter or bypass licensing.

Use `inspect` before processing an unknown artifact. ZIP, APK, AAB, and JAR
containers are parsed without extraction and report traversal, symlink,
duplicate-name, compression-ratio, entry-count, and output-size findings. Use
`extract` only after inspection; extraction is confined to a private output
root, rejects unsafe archives, supports stored and deflated ZIP entries, and
removes partial output after failure. APK inspection also reports DEX and native
library counts without executing package content.

`open_gui` is a handoff: it launches the detected GUI and returns immediately
instead of holding an agent tool call open. Headless runs remain supervised,
bounded, cancellable, and use per-artifact Ghidra project names so concurrent
analyses do not write the same project.

### Persistent IDA tools

For a Codex-like query workflow, install the Hex-Rays-recommended community `mrexodia/ida-pro-mcp` package after reviewing it, ensure `idalib-mcp` is on `PATH`, and select **Settings → MCP Servers → Configure IDA**. Cline registers:

```text
idalib-mcp --stdio --max-workers 1
```

The one-worker default avoids consuming multiple IDA license seats. The resulting MCP tools let the model open a database once and repeatedly query functions, strings, imports, pseudocode, and cross-references. The button configures an existing installation; it deliberately does not download third-party code.

Ghidra 12 continues to work through the built-in supervised `analyzeHeadless` adapter. Discovery also prints the offline command for installing PyGhidra from the bundled Ghidra distribution when available.
