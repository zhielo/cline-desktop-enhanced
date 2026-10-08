# Build-time only. The installed app never invokes pip or downloads packages.
param([Parameter(Mandatory=$true)][string]$EnginePython)
$ErrorActionPreference = 'Stop'
$version = '3.13.12'
$expected = '76f238f606250c87c6beac75dccd35ee99070a13490555936abb6cb64ecce3d0'
if (-not [IO.Path]::IsPathFullyQualified($EnginePython)) { throw 'Absolute build interpreter required' }
$root = Join-Path $PSScriptRoot '../apps/examples/desktop-app/src-tauri/resources/analysis-runtime'
$archive = Join-Path $env:RUNNER_TEMP "python-$version-embed-amd64.zip"
Invoke-WebRequest "https://www.python.org/ftp/python/$version/python-$version-embed-amd64.zip" -OutFile $archive
if ((Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'Official Python archive checksum mismatch' }
if (Test-Path $root) { Remove-Item -LiteralPath $root -Recurse -Force }
New-Item -ItemType Directory -Path $root -Force | Out-Null
Expand-Archive -LiteralPath $archive -DestinationPath $root
$site = & $EnginePython -I -c "import sysconfig; print(sysconfig.get_path('purelib'))"
if ($LASTEXITCODE -ne 0 -or -not $site) { throw 'Build engine environment unavailable' }
New-Item -ItemType Directory -Path (Join-Path $root 'Lib/site-packages') -Force | Out-Null
Copy-Item -Path (Join-Path $site '*') -Destination (Join-Path $root 'Lib/site-packages') -Recurse -Force
Get-ChildItem $root -Directory -Filter '__pycache__' -Recurse | Remove-Item -Recurse -Force
# Explicit isolated import roots; never depend on the user's site-packages/PATH.
@('python313.zip', '.', 'Lib/site-packages', 'import site') | Set-Content (Join-Path $root 'python313._pth') -Encoding ascii
$python = Join-Path $root 'python.exe'
& $python -I -B -c "import sys,lief,capstone,androguard,z3,miasm,cryptography; assert sys.flags.isolated; assert not __import__('site').ENABLE_USER_SITE; print(sys.version)"
if ($LASTEXITCODE -ne 0) { throw 'Bundled isolated imports failed' }
& bun scripts/write-analysis-runtime-manifest.ts $root
if ($LASTEXITCODE -ne 0) { throw 'Runtime integrity manifest failed' }
& $python -I -B sdk/packages/core/scripts/advanced-analysis-worker.test.py --engine-profile windows-portable
if ($LASTEXITCODE -ne 0) { throw 'Bundled execution corpus failed' }
& $python -I -B sdk/packages/core/scripts/android-investigation-worker.test.py
if ($LASTEXITCODE -ne 0) { throw 'Bundled Android owned fixtures failed' }
