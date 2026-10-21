# Integrated source-port validation record

## Current local application-graph expansion

Linux development results against pinned REA revision `d0067ba34a39ea47dd7e11bb2e6169bc0938cc3f`:

| Check | Result |
| --- | --- |
| SDK build, all packages | Passed |
| Production desktop sidecar bundle | Passed |
| Production Next.js desktop WebView build | Passed |
| Complete workspace TypeScript checks, including tests and smoke declarations | Passed |
| Complete repository CI lint gate | Passed; existing non-failing warnings remain |
| Custom-fork preservation | 314 source contracts passed |
| Source/test provenance | 291 files verified |
| Pinned public contract inventory | 212 contracts and 443 static dependency files; committed audit matches source |
| Entire analysis suite with separately pinned reference | 492 passed; 1 existing Windows-only test skipped on Linux, across 53 files |
| Complete desktop chat UI suite | 305 passed across 21 files |
| Complete desktop sidecar regression suite | 1,838 passed; 2 existing Windows-only tests skipped on Linux, across 113 files |
| Owned child-worker, paired graph persistence and saved trace Off | Passed; filesystem sentinel confirms fixture code was not run |
| Final targeted UI, sidecar analysis and release verifier regressions | Passed after source-binding and accessible result-markup changes |
| Frozen install, lockfile scope, workflow YAML, whitespace and changed release hash pins | Passed |

The new application differential corpus compares original and integrated application/semantic graph digests for the **same admitted inventory**, covering CJS/Electron, ESM/JSON, bundle/source maps, HTML/unresolved imports, shadowing and malformed source. Saved feature/version/export algorithm outputs also match their pinned originals. Additional unchanged upstream graph, package-main, source-map, version-matching, relationship-uncertainty, relocation, export-schema and source-to-bundle tests run in the analysis suite. These are scoped fixture results, not acquisition parity or proof about all programs.

The expanded graph binding additionally checks that the virtual manifest corresponds to the exact admitted receipt artifact inventory under one common directory/ASAR/single-file prefix. Mixed-prefix suffix matches, changed bytes/counts and duplicate identities are rejected. Parent validation and atomic storage both enforce this check.

Local compiler caches produced stale diagnostics after changing the desktop target from ES6 to ES2020. A fresh-cache strict check and subsequent complete workspace check pass. ES2020 matches the existing Bun and modern WebView2 runtime baseline; strict checking and test inclusion are not disabled. The static analysis engine remains sidecar-only.

## Published release evidence must match the new head

The Windows workflow now includes an explicit **installed application graph/Electron/saved trace/no-execution** stage. The finite release policy requires it and pins the changed acceptance script and source-validation workflow. Its presence in source is **not** a passing installed result. Review the new head's Linux/Windows source checks, installer, installed binary smoke and actual installed WebView results before any release decision.

The previous file-local-only head `eb0a844f2987ed295591a9767bdeab07d247679f` passed its registered checks and older installed journey in workflow run `39542980893`. That older installer **does not contain this application-graph expansion** and cannot be reused as evidence for it.

## Still unfinished

- Complete original-container acquisition, source selection and bundle source recovery.
- Full native dossiers, high-p-code/value tracing and additional source-level Ghidra/IDA provider workflows, including appropriate real-engine acceptance.
- Remaining managed/specialist migrations, runtime identity reconciliation, scenario/rebuild/reconstruction obligations and contradiction handling.
- Shipped app-native skills adapted to the complete integrated capability set. Updating tool guidance or adding a repository development skill alone would not satisfy this requirement.
- Full REA parity/superiority over owned fixtures and representative real engines. A contract name, copied type or green installer is not parity proof.

Queries still validate/load bounded whole graphs rather than stream them. No fixed-RSS guarantee, new OS sandbox, automatic approval, or zero-problem guarantee is provided. Keep the consolidated PR draft and unmerged while the complete requested migration remains unfinished.
