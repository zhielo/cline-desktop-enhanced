# CI-owned reproduction of the installed interpreter; not a presence-only check.
param([Parameter(Mandatory=$true)][string]$EnginePython)
$ErrorActionPreference = 'Stop'
$version = '3.13.12'
$archive = Join-Path $env:RUNNER_TEMP 'triage-python-embedded.zip'
Invoke-WebRequest "https://www.python.org/ftp/python/$version/python-$version-embed-amd64.zip" -OutFile $archive
if ((Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne '76f238f606250c87c6beac75dccd35ee99070a13490555936abb6cb64ecce3d0') { throw 'Official embedded Python digest mismatch' }
$root = Join-Path $env:RUNNER_TEMP 'triage-embedded-python'
New-Item -ItemType Directory -Path $root -Force | Out-Null
Expand-Archive -LiteralPath $archive -DestinationPath $root -Force
$site = & $EnginePython -I -c "import sysconfig; print(sysconfig.get_path('purelib'))"
if ($LASTEXITCODE -ne 0 -or -not $site) { throw 'Isolated binding source unavailable' }
New-Item -ItemType Directory -Path (Join-Path $root 'Lib/site-packages') -Force | Out-Null
Copy-Item -Path (Join-Path $site '*') -Destination (Join-Path $root 'Lib/site-packages') -Recurse -Force
@('python313.zip', '.', 'Lib/site-packages', 'import site') | Set-Content (Join-Path $root 'python313._pth') -Encoding ascii
$env:CLINE_RE_PYTHON = Join-Path $root 'python.exe'
$env:CLINE_BINARY_TRIAGE_ROOT = Join-Path $PSScriptRoot '../apps/examples/desktop-app/src-tauri/resources/binary-triage'
& bun scripts/test-binary-triage-pack.ts
if ($LASTEXITCODE -ne 0) { throw 'Embedded triage execution failed; no installer readiness claimed' }
