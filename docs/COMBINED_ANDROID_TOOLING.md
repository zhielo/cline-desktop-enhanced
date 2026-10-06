# Combined Android/native tooling integration

## What this patch implements

Use Analysis workbench → Advanced analysis. Every task is prepared, reviewed and approved using the existing exact-request envelope. These are static investigations: target programs never execute in these functions.

| Function | Actual capability | Requirements |
| --- | --- | --- |
| `analysis_readiness` | Executes owned DEX/ELF parsing and instruction fixtures, recording versions and completed/blocked/failed status | Trusted Python; LIEF, Capstone, Androguard for their respective checks |
| `artifact_discovery` | Bounded APK/ZIP/compression traversal and standard embedded DEX candidates | Trusted Python |
| `android_relationships` | Loader/reflection pool references, derived JNI names and defined ELF dynamic-export name matches | Python; LIEF for parsed ELF/export evidence |
| `android_method_code` | Exact class/name/descriptor bytecode and operands in covered standard DEX | Androguard |
| `native_function` | Exact symbol or entry address, executable file mapping and bounded linear disassembly | LIEF + Capstone |
| `investigation_query` | Paginated immutable saved evidence, including selected functions | A returned investigation index |
| `investigation_graph` | Provenance graph from a validated saved index | A returned investigation index |
| Ghidra/IDA `decompile` selector | Fixed exact-function adapter scripts and selector-aware cache identity | Compatible installed engine; IDA requires a licensed Hex-Rays decompiler |
| JADX class selection | Existing single-class adapter with class-aware cache identity | Installed compatible JADX |

Fixture execution is not a claim that arbitrary hostile/packed inputs will parse successfully. Ghidra/IDA template and mock-routing tests are not real licensed-engine execution tests. Missing engines stay blocked rather than becoming simulated results. Windows CI runs a pinned portable-engine fixture corpus without optional-engine skips; these CI engines are not bundled into the installed app.

## Exact options

No target is required for `analysis_readiness`.

```json
{"method":{"class_descriptor":"Lcom/example/Loader;","name":"load","descriptor":"([B)V"}}
```

```json
{"function":{"symbol":"Java_com_example_Loader_load","max_bytes":4096}}
```

```json
{"function":{"address":"0x1000","max_bytes":4096}}
```

Use exactly one symbol or hexadecimal entry address. Stripped files without matching defined function symbols cannot be reliably selected by this action. It does not guess a nearby function. Inventories/searches are bounded, ambiguity and truncation remain visible. ARM Thumb entries are normalized for file mapping while their decode mode stays recorded. Capstone direct-call immediates are candidates, not observed callees or a recovered CFG.

For Ghidra/IDA choose `decompile`, select the installed engine, then enter:

```json
{"function_selector":{"address":"0x1000"}}
```

For JADX:

```json
{"jadx_single_class":"com.example.Loader","jadx_mode":"fallback"}
```

Set saved-index query/graph targets to `investigationIndex.file`, not the original APK. References to a constant-pool method do not prove invocation. JNI export-name candidates do not establish runtime `RegisterNatives`, binding identity, overload selection or execution. Graphs retain those distinctions. Byte fingerprints do not prove semantic equivalence.

## Runtime requirements

Authorized runtime recovery of encrypted/dynamically loaded DEX requires a disposable Android emulator/device or isolated VM and a provisioned authenticated worker, explicit upload/execution approval and bounded capture/retention. The existing worker-client protocol does not provision that environment. Do not execute hostile APKs or ELF libraries on the desktop host. No unknown-key recovery, universal devirtualization, license bypass or automatic hostile-code execution is included.

Existing known-key authenticated decryption, expression equivalence, Miasm IR and imported trace tools retain their specific requirements and limits. Imported traces are not automatically authenticated runtime observations. Static parsing itself is not an OS sandbox; use isolation for hostile parser inputs too.

## Build and long-chat reliability

This integration also retains bounded lifecycle recovery and authenticated desktop transport. Provider Unauthorized errors still require valid account credentials; the desktop token cannot repair ClinePass login.

The previous Windows installed-sidecar smoke reported 404 where 401 was required. Cached NSIS output selection is a plausible cause, not a confirmed diagnosis from complete logs. The build now deletes only cached NSIS bundle outputs before rebuilding, compares freshly built/installed sidecar hashes, and checks health protocol plus embedded source commit. The tokenless transport denial still must be 401. No test is relaxed to accept the old failure.

A local source build is not Windows installer evidence. Do not merge from packaging success alone: require source gates, real portable-engine tests, terminal smoke, installed-app smoke and review of independent repository checks. No auto-merge or release publication is added. Private installers remain unsigned unless separately configured signing credentials are provided.

## One-command local Windows source build

From a clean committed checkout on Windows x64:

```powershell
.\scripts\build-windows.ps1
```

Prerequisites: pinned Bun 1.3.14, Git, Rust/Cargo, Visual Studio C++ build tools, Tauri Windows prerequisites, UPX, and a trusted absolute `CLINE_RE_PYTHON` environment variable pointing to Python with `sdk/packages/core/scripts/requirements-advanced-windows.txt` installed. Use the supported MSVC developer environment for native Python builds; do not select Git's Unix `link.exe`. This wrapper does not provision dependencies/licenses or relax system execution policy. Dependency/build tools may need network access.

The wrapper runs consolidated source gates and real portable-engine fixtures, cleans old NSIS output, builds a single setup executable and records its commit/SHA256 under `dist/local-installer`. It does not install or launch the result and explicitly records that installed-app smoke was not run. Use the workflow's installed-app gate before merge; the script is not a replacement for it. Its PowerShell source is reviewed/tested by static contracts here, not executed in this Linux environment.
