# Cline Desktop Power Tools

This fork adds an explicit **Full Access** profile, hardened binary handling, supervised reverse-engineering tools, and one-click Notion MCP setup.

## Execution profiles

- **Plan**: read-oriented planning with guarded commands.
- **Act**: normal interactive development.
- **Full Access**: maps to Cline's existing `yolo` preset, enabling and auto-approving tool calls. Read/search, batched commands, patch/editor, web fetch, configured skills, and reverse-engineering tools remain available so this profile does not trade speed for missing coding capabilities. It does not bypass operating-system permissions, remote-service authentication, parser limits, or licensing.

## Reverse engineering

The built-in `reverse_engineer` tool supports discovery, structured binary triage, safe ZIP inspection/extraction, cached headless analysis/decompilation, scripts, and exact GUI handoff.

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

APK, AAB, DEX, and JAR inputs prefer JADX when installed. Ghidra uses `analyzeHeadless`; IDA uses autonomous mode; child output is bounded and timed out. Successful analysis is stored under an artifact SHA-256 and reused by default. Set `reuse_analysis` to `false` for an isolated temporary run. ZIP inspection reads only the central directory and does not extract files.

JADX options include `jadx_mode`, `jadx_threads`, `jadx_single_class`, `jadx_output_format`, `jadx_deobfuscate`, `jadx_call_graph`, `jadx_export_gradle`, `jadx_no_resources`, `jadx_no_sources`, and `jadx_mappings_path`. Ghidra accepts `max_cpu`. IDA batch decompilation generates a bounded IDAPython script that calls `ida_hexrays.decompile()` for every eligible function, writes a non-empty pseudocode artifact, records per-function failures, and exits IDA explicitly. It does not pass output paths through the incompatible `-Ohexrays:<path>:ALL` form.

For protected or obfuscated Android applications, `disassemble_smali` uses `apktool` for APK-family containers or `baksmali` for raw DEX files. The resulting `.smali` files can be edited with normal file tools. `assemble_smali` builds an edited Smali directory into a DEX using `smali`; `rebuild_apk` builds an edited decoded directory into an unsigned APK using `apktool`. Build outputs are written atomically, symbolic links are rejected in build inputs, and the tool never executes the analyzed application. APK signing remains a separate, explicitly configured workflow.

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

The reverse-engineering executor performs a bounded two-level search under `%USERPROFILE%\\Documents`, `Program Files`, `Program Files (x86)`, and `%LOCALAPPDATA%\\Programs`. This finds nested portable Ghidra ZIP layouts without scanning arbitrary drive roots. Explicit `GHIDRA_INSTALL_DIR`, `GHIDRA_HOME`, `IDADIR`, and `IDA_HOME` values still take precedence.

Ask Cline to **discover reverse-engineering tools** or call:

```json
{
  "engine": "auto",
  "operation": "discover"
}
```

The result refreshes the sidecar's Windows `PATH` plus persisted `GHIDRA_HOME`, `GHIDRA_INSTALL_DIR`, `IDA_HOME`, `IDADIR`, and `JADX_HOME` values from the user and machine environment, then reports detected versions, headless and GUI launchers, Ghidra's bundled PyGhidra wheel directory, the analysis cache directory, and IDA's idalib activation script. Tools installed while Cline is open can therefore be detected without killing the sidecar. For IDA 9.0–9.3, activate idalib once using the exact command returned by discovery. This uses the installed licensed IDA instance and does not alter or bypass licensing.

Use `inspect` before processing an unknown artifact. ZIP, APK, AAB, and JAR
containers are parsed without extraction and report traversal, symlink,
duplicate-name, compression-ratio, entry-count, and output-size findings. Use
`extract` only after inspection; extraction is confined to a private output
root, rejects unsafe archives, supports stored and deflated ZIP entries, and
removes partial output after failure. APK inspection also reports DEX files,
native-library paths, and ABIs without executing package content. Non-archive
inspection recognizes PE, ELF, Mach-O, DEX, and WebAssembly headers,
architecture, bitness, entry point where available, and bounded sample entropy.

`open_gui` is a handoff: it launches the detected GUI and returns immediately
instead of holding an agent tool call open. When cached analysis exists, it
opens the generated Ghidra project or IDA database rather than reimporting the
original binary. Headless runs remain supervised, bounded, cancellable, and
serialized per analysis workspace. Ghidra reprocesses its saved project, IDA
reuses its `.i64` database, and generated artifacts plus a reproducibility
manifest are returned to the agent.

### Persistent IDA tools

For a Codex-like query workflow, install the Hex-Rays-recommended community `mrexodia/ida-pro-mcp` package after reviewing it, ensure `idalib-mcp` is on `PATH`, and select **Settings → MCP Servers → Configure IDA**. Cline registers:

```text
idalib-mcp --stdio --max-workers 1
```

The one-worker default avoids consuming multiple IDA license seats. The resulting MCP tools let the model open a database once and repeatedly query functions, strings, imports, pseudocode, and cross-references. The button configures an existing installation; it deliberately does not download third-party code.

Ghidra 12 continues to work through the built-in supervised `analyzeHeadless` adapter. Discovery also prints the offline command for installing PyGhidra from the bundled Ghidra distribution when available.

## Attached Android device debugging

The built-in `android_device` tool uses Android Debug Bridge from `ADB_PATH`,
`ANDROID_SDK_ROOT`, `ANDROID_HOME`, or `PATH` with an already-authorized USB or
wireless-debugging device. It supports device discovery, package/process
inspection, APK install/uninstall and launch/force-stop, PID-filtered `logcat`,
the Android crash buffer, installed base-APK pulls, screenshots, and
bugreports. Operations support device serial selection, timeout/cancellation,
bounded text output, and Windows process-tree termination. APK pulls and
screenshots update destinations atomically.

The tool exposes unrestricted `adb shell` only for an already-authorized device and only when `acknowledge_risk: true` is supplied. It does not root a device, bypass Android authorization, or bypass app signing. Full Access removes Cline approval prompts; Android must still authorize the device.
