This is the **Cline** monorepo. Toolchain is **Bun 1.3.13** (package manager + task runner) with **Node >=22** as the runtime. Do not use npm/yarn/pnpm.

## Customized Cline Enhanced handoff — read before changing this fork

This branch is an active customized **Windows Cline Desktop** project. Before making changes, inspect the latest branch, pull requests, workflow runs, and current diff instead of recreating completed work.

### Product goal and required deliverable

- Build **Cline Enhanced** for **Windows x64**.
- The final deliverable must be a working NSIS `setup.exe`, expected to be named `Cline-Enhanced_0.0.34_x64-setup.exe` or an equivalent Windows x64 setup executable.
- Do not substitute an AppImage, DMG, Linux build, macOS build, or source ZIP for the requested installer.
- Preserve the custom application identifier and disabled upstream auto-update behavior documented in `CUSTOM_BUILD_NOTES.md`.

### Active development

- Primary development branch: `feature/windows-re-tooling-task-ui`
- Draft PR #10: <https://github.com/zhielo/cline-desktop-enhanced/pull/10>
- Focused IDA startup-fix branch: `feature/advanced-re-tooling-ui`
- Draft PR #9: <https://github.com/zhielo/cline-desktop-enhanced/pull/9>
- PR #10 is intentionally stacked on the IDA-fix branch. Do not merge either PR until Windows validation and relevant CI results are understood.

### Completed custom work that must be preserved

1. Fixed the incorrect IDA `idat -h`/`--help` probing behavior. Never restore help-flag probing of IDA entry points.
2. Added supervised IDA, Ghidra, and JADX analysis with bounded output, cancellation, timeouts, and Windows process-tree cleanup.
3. Added `health_check` and `binary_triage` operations.
4. Added discovery for tools including capa, FLOSS, YARA, binwalk, Detect It Easy CLI, radare2, readelf, nm, ExifTool, UPX, GDB, LLDB, dumpbin, and Sigcheck.
5. Added Codex-style task status presentation with Running/Done/Failed state pills and disclosure controls.
6. Added modern Dexlib2/Smali support:
   - `dex_summary` provides a fast Dexlib2-backed DEX class inventory through Baksmali.
   - Prefer official Smali/Dexlib2 **3.0.10** artifacts while retaining compatibility with **3.0.9**.
   - Discover `BAKSMALI_JAR`, `SMALI_JAR`, and `DEXLIB2_JAR` overrides, common Cline tool directories, Maven cache paths, Java, and command launchers.
   - Raw DEX disassembly falls back to `java -jar <baksmali-fat-release.jar>` when a Baksmali launcher is unavailable.
   - Smali assembly falls back to `java -jar <smali-fat-release.jar>` when a Smali launcher is unavailable.
   - JAR paths and all external arguments must remain structured argv entries; do not introduce shell interpolation for Windows paths.

Recommended end-user JAR locations on Windows:

```text
%USERPROFILE%\.cline\tools\baksmali-3.0.10-fat-release.jar
%USERPROFILE%\.cline\tools\smali-3.0.10-fat-release.jar
```

The standalone `smali-dexlib2` library JAR is not required for normal disassembly/assembly because the official fat-release JARs carry their runtime dependencies. Do not assume the standalone Dexlib2 library JAR has an executable main class.

### Important implementation files

- `sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts`
- `sdk/packages/core/src/extensions/tools/executors/reverse-engineering.test.ts`
- `sdk/packages/core/src/extensions/tools/definitions.ts`
- `sdk/packages/core/src/extensions/tools/schemas.ts`
- `apps/examples/desktop-app/CUSTOM_DESKTOP.md`
- `apps/examples/desktop-app/webview/components/views/chat/messages/tool-message-block.tsx`
- `sdk/packages/ui/components/agent-chat/index.tsx`
- `sdk/packages/ui/components/agent-chat/agent-chat.css`
- `CUSTOM_BUILD_NOTES.md`

### Focused validation

Run these after relevant changes. Build SDK packages before their tests because package exports resolve through `dist/`.

```bash
bun run build:sdk
cd sdk/packages/core
bun vitest run src/extensions/tools/executors/reverse-engineering.test.ts --config vitest.config.ts
cd ../../ui
bun run typecheck
bun vitest run tests/agent-chat.test.tsx --config vitest.config.ts
cd ../../../apps/examples/desktop-app
bun run typecheck
cd ../../..
git diff --check
```

The last verified focused reverse-engineering suite contained **15 passing tests**, including Dexlib2/Baksmali class inventory. Re-run tests rather than relying on this historical count after modifying code.

### Remaining release work

1. Inspect PR #10, its latest diff, reviews, and CI before changing code.
2. Build the latest development head on a Windows x64 GitHub Actions runner.
3. Confirm the NSIS `setup.exe` exists and is the full desktop installer, not only a sidecar binary.
4. Test silent installation and confirm `cline-app.exe` and `code-sidecar.exe` start.
5. Generate and retain a SHA-256 checksum for the installer.
6. Make the Windows installer artifact available to the user.
7. Remove one-time build trigger files after the required artifact is captured, if they still exist:
   - `.github/workflows/build-windows-once.yml`
   - `.github/WINDOWS_BUILD_TRIGGER`
8. Ensure no temporary Base64 patch-transfer files or self-applying transfer workflows remain in the PR.
9. Distinguish baseline/infrastructure CI failures from regressions caused by the focused changes; do not claim all CI passed unless verified.

### Reverse-engineering safety and licensing constraints

- Never bypass, patch, suppress, or circumvent IDA licensing or activation.
- Never patch IDA binaries.
- Do not execute `idat.exe -h`, `idat64.exe -h`, `ida.exe --help`, or `ida64.exe --help`.
- Use IDA only through legitimately installed/licensed capabilities; first-run GUI setup may be required.
- Use Ghidra through its official interfaces.
- Keep reverse-engineering operations supervised, scoped to authorized artifacts, bounded, cancellable, timeout-controlled, and non-shell-interpolated where structured argv is available.

## Cloud Agent Instructions

### Cline CLI
- Run from source: `bun run cli` (interactive: `bun run cli -i`; one-shot: append a prompt). This resolves to `apps/cli` and **auto-spawns the `@cline/cline-hub` daemon** — you do not start the hub separately.
- Inspect local health with `bun run cli doctor`; `bun run cli version` prints the version.
- An actual agent turn requires an **LLM provider credential**. With no credentials the default `cline` provider fails fast with an `Unauthorized` error and the interactive TUI shows a provider sign-in screen. Configure via `cline auth` or provider env vars (e.g. `ANTHROPIC_API_KEY`, `CLINE_API_KEY`, `OPENROUTER_API_KEY`); see `apps/cli/README.md`.

### Build / Lint / test
- SDK packages (`@cline/shared|llms|agents|core|sdk`) resolve each other through compiled `dist/` (their `exports` point only at `dist/`, with no `development` source condition). You **must** run `bun run build:sdk` after changing SDK dependencies/source before running the CLI or SDK tests, otherwise imports fail with missing `@cline/*` / missing `dist/` errors. Running processes do **not** hot-reload SDK source changes — rebuild and restart.\
- Known cloud-env test artifact: `@cline/core` test `src/services/workspace/workspace-manifest.test.ts > readGitWorkspaceState > prefers origin and returns the current branch` fails because cloud VMs configure git `insteadOf` rules that rewrite GitHub remotes to `https://x-access-token:...@github.com/...`. This is an environment artifact, not a code bug.
- Some `@cline/cli` e2e assertions (`bun -F @cline/cli test:e2e`) may fail on exact tool-listing string formats; treat as pre-existing test drift, not an environment problem.

### GUI display
- A virtual X display is live at **`DISPLAY=:1`** (the same desktop used for screenshots). GUI apps (VS Code, the Tauri desktop window) launched with `DISPLAY=:1` render there and can be screenshotted — no need to start your own `xvfb`. Prefer starting long-running GUI/dev processes in a `tmux` session (see the tmux guidance) so they survive.

### VS Code extension (`apps/vscode`, package `claude-dev`)
Toolchain is pre-installed and persisted in the VM: generated gRPC/proto code, the bundled `ripgrep` binaries (`apps/vscode/bin/`), the built webview (`webview-ui/build`), the esbuild bundle (`dist/extension.js`), VS Code itself (`/usr/bin/code`), and the GUI system libraries its tests need.
- **Codegen prerequisite:** `bun run protos` (from `apps/vscode`) regenerates `src/generated/*` and the webview grpc client. The `dev`, `build:webview`, and `check-types` scripts already run it, so proto changes are picked up by those commands; run it manually only if you edit `.proto` files without a full build.
- **Build:** `bun run build:webview` (webview UI, ~15s) then `bun esbuild.mjs` (extension bundle). `bun run package` does the full production build.
- **Run it (dev host):** `DISPLAY=:1 code --no-sandbox --user-data-dir=/tmp/vscode-userdata --extensionDevelopmentPath=/workspace/apps/vscode <some-folder>`, then click the Cline icon in the Activity Bar to open the webview. (`--no-sandbox` is required in this container.)
- **Test:** `bun run test:unit` (bun-based, ~984 tests, no VS Code host needed). `bun run test:integration` (`@vscode/test-electron`, downloads a VS Code build, runs under the GUI libs) and `bun run test:e2e` (Playwright) exercise a real extension host — heavier, and the GUI libs for them are already installed.
- One-time deps (already installed, listed here in case they must be recreated): ripgrep via `bun run download-ripgrep`; VS Code test GUI libs per `CONTRIBUTING.md` (`libnss3`, `libatk*`, `libgbm1`, `xvfb`, etc.).

### Desktop app (`apps/examples/desktop-app`, package `@cline/code`)
A Tauri v2 (Rust) shell + Next.js webview + a Bun "sidecar" backend. Rust and the Tauri Linux system libs are pre-installed and persisted.
- **Headless (no Rust/window):** run the backend and UI separately — `bun run dev:sidecar` (Bun backend on `127.0.0.1:3126`, serves `ws://.../transport`) and `bun run dev:web` (Next.js UI on `http://localhost:3125`).
- **Native window:** `bun run dev` (`tauri dev`) — its `beforeDevCommand` builds the sidecar binary and starts `dev:web` (`:3125`), then Rust `main.rs` spawns the sidecar; so free ports `3125`/`3126` first. Launch with `DISPLAY=:1` to see the window. A `libEGL: DRI3 error` warning is benign (software rendering) — the WebKitGTK window still renders.
- **Rust version caveat:** the crate graph needs Cargo's `edition2024` feature, so **Rust ≥1.85** is required (the VM's base 1.83 fails with "feature `edition2024` is required"). The toolchain here was updated via `rustup default stable` (currently 1.97). First `cargo` build downloads/compiles the full Tauri crate graph (a few minutes); subsequent builds are cached.
- **System libs (already installed):** `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`, `libxdo-dev`, `libssl-dev`, `build-essential`.
- **Test/typecheck:** `bun run typecheck`, `bun run test:chat-ui` (Vitest). Both trigger `build:ui` first.
