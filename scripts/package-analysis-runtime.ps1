# Build-time only. The installed app never invokes pip or downloads packages.
param([Parameter(Mandatory=$true)][string]$EnginePython, [ValidateSet('core','full','angr')][string]$Pack = 'core')
$ErrorActionPreference = 'Stop'
$version = '3.13.12'
$expected = '76f238f606250c87c6beac75dccd35ee99070a13490555936abb6cb64ecce3d0'
if (-not [IO.Path]::IsPathFullyQualified($EnginePython)) { throw 'Absolute build interpreter required' }
$resource = if ($Pack -eq 'core') { 'analysis-runtime' } else { "analysis-runtime-$Pack" }
$root = Join-Path $PSScriptRoot "../apps/examples/desktop-app/src-tauri/resources/$resource"
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
if ($Pack -eq 'core') {
& $python -I -B -c "import sys,lief,capstone,androguard,z3,miasm,cryptography; assert sys.flags.isolated; assert not __import__('site').ENABLE_USER_SITE; print(sys.version)"
if ($LASTEXITCODE -ne 0) { throw 'Bundled isolated imports failed' }
& $python -I -B sdk/packages/core/scripts/advanced-analysis-worker.test.py --engine-profile windows-portable
if ($LASTEXITCODE -ne 0) { throw 'Bundled execution corpus failed' }
& $python -I -B sdk/packages/core/scripts/android-investigation-worker.test.py
if ($LASTEXITCODE -ne 0) { throw 'Bundled Android owned fixtures failed' }
} elseif ($Pack -eq 'full') {
  & $python -I -B sdk/packages/core/scripts/advanced-analysis-worker.test.py --engine-profile full
  if ($LASTEXITCODE -ne 0) { throw 'Full expression and matching execution failed' }
  & $python -I -B sdk/packages/core/scripts/full-analysis-readiness.test.py --pack full
  if ($LASTEXITCODE -ne 0) { throw 'Full owned execution fixtures failed' }
} else {
  & $python -I -B sdk/packages/core/scripts/full-analysis-readiness.test.py --pack angr
  if ($LASTEXITCODE -ne 0) { throw 'Isolated angr execution fixture failed' }
}
# Corpus subprocesses may create bytecode even if the outer Python uses -B.
# Freeze the shipped inventory only after all execution acceptance completes.
Get-ChildItem $root -Directory -Filter '__pycache__' -Recurse | Remove-Item -Recurse -Force
& bun scripts/write-analysis-runtime-manifest.ts $root $Pack
if ($LASTEXITCODE -ne 0) { throw 'Runtime integrity manifest failed' }
