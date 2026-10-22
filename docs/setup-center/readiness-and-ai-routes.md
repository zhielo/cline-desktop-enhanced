# Setup Center: runtime checks and AI routes

## What readiness means

Installation, discovery, owned-fixture readiness and compatibility with a specific target are different states. A catalog entry is not an installation or health receipt. A failed, blocked, interrupted or stale test must not be reported as Ready. Full-pack readiness still requires eleven distinct successful execution receipts bound to the current runtime identity.

No REA installation or service is required.

## IDA and Ghidra

The IDA adapter invokes the selected executable directly. It does not infer Hex-Rays availability from plugin filenames, inspect license files or require a license-ownership checkbox before trying an owned fixture. IDAPython and the processor-specific decompiler are checked by the actual fixed adapter. IDA's own licensing, missing modules and runtime errors remain authoritative; this change does not activate or bypass a vendor license.

The trusted local desktop connection, explicit confirmation, supported architecture, bounded job admission, executable identity and owned output validation remain required. Optional Setup Center acceptance is not a prerequisite for normal authorized decompilation. IDA analysis without decompilation does not require Hex-Rays.

The Ghidra adapter uses its headless launcher and compatible Java. Optional PyGhidra or idalib activation instructions are not prerequisites for these adapters. Actual selected-function fixture tests remain separate from discovery.

## What the AI can discover

`reverse_engineer` operations `discover` and `analysis_command_catalog` return `setupCapabilities`. Setup Center uses the same catalog. Library backends are not separate top-level AI tools.

| Backend | Existing AI route |
| --- | --- |
| LIEF | `advanced_analysis` / `native_inventory` |
| Capstone | `advanced_analysis` / `native_disassemble` |
| Z3 | `advanced_analysis` / `compare_expressions` |
| Triton | `advanced_analysis` / `triton_expression` |
| QBinDiff | `advanced_analysis` / `match_native_functions` with two BinExport inputs |
| Androguard | `advanced_analysis` / `dex_index` |
| Miasm | `advanced_analysis` / `lift_native_ir` |
| Unicorn | `advanced_analysis` / `unicorn_emulate` with existing bounds |
| angr | `advanced_analysis` / `angr_lift`, separate interpreter |
| QBDI | Local owned fixture only; arbitrary tracing is not an enabled model action |
| cryptography | `advanced_analysis` / `decrypt_blob`, host-enabled known-key configuration |
| IDA / Ghidra / JADX | `decompile` with the selected engine and its required input selectors |
| Android construction tools | Existing construction/signing recipes in `analysis_command_catalog`; separate write approval |
| ADB / Android device | `android_device`, authorized selected device |
| First-party JS / Electron | `javascript_analysis`; retained receipts through `analysis_evidence` |
| Isolated worker | `plan_runtime_observation` proposes work only; no execution authorization implied |

The AI schema now accepts `full_readiness` and `angr_readiness` under `advanced_analysis`. They run fixed owned fixtures, reject target/compare_target/advanced_options and preserve actual blocked/partial/failed results. `toolchain` remains inventory only. Tool enablement, Analysis mode, host configuration, permissions and output policies still apply.

The specialist Binary Triage Pack (radare2/r2pipe, YARA, capa, FLOSS) is listed under `workbenchOnly`. Its existing trusted-desktop, scoped-evidence execution boundary is deliberately preserved. Awareness in the catalog does **not** create a model RPC route or permission to bypass that boundary using shell commands. Native radare2 discovery elsewhere is not equivalent to the pinned triage adapter.

## Setup failures that remain actionable

- Missing packages, incompatible Java, missing processor decompilers and actual vendor runtime refusals.
- Unverified or changed runtime/executable identity; stale receipts require a new explicit test.
- Missing selected/authorized Android device, signing configuration or isolated-worker proof.
- Unsupported input format, invalid exact selector, output bounds or process deadline.
- Notice acceptance for redistributing/installing platform tools. This is not a license-file detector and is not removed.

No test suite can guarantee every engine works on every machine or target. Windows installed-app validation and locally configured commercial tools/devices are separate acceptance steps. Mocked adapter tests prove routing and error handling, not an installed commercial license or actual decompilation on the user's computer.
