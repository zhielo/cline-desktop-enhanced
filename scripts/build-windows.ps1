# One-command source build. Does not merge, release, install the result, or execute a target APK/ELF.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitOperatingSystem) { throw 'Windows x64 is required' }
$root = Split-Path $PSScriptRoot -Parent
function Checked([string]$program, [string[]]$arguments) {
  & $program @arguments
  if ($LASTEXITCODE -ne 0) { throw "$program failed with exit code $LASTEXITCODE" }
}
Push-Location $root
$previousCommit = $env:GITHUB_SHA
$previousCache = $env:BUN_INSTALL_CACHE_DIR
try {
  foreach ($tool in @('git','bun','rustc','cargo','upx','npm','tar')) { Get-Command $tool -ErrorAction Stop | Out-Null }
  $bunVersion = (& bun --version).Trim()
  if ($LASTEXITCODE -ne 0 -or $bunVersion -ne '1.3.14') { throw 'Use the pinned Bun 1.3.14' }
  $dirty = & git status --porcelain
  if ($LASTEXITCODE -ne 0 -or $dirty) { throw 'Build from a clean committed checkout; save changes first' }
  $commit = (& git rev-parse HEAD).Trim()
  if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[a-f0-9]{40}$') { throw 'Cannot identify source commit' }
  if (-not $env:CLINE_RE_PYTHON -or -not [IO.Path]::IsPathRooted($env:CLINE_RE_PYTHON) -or -not (Test-Path $env:CLINE_RE_PYTHON)) { throw 'Set CLINE_RE_PYTHON to an absolute trusted Python with the pinned Windows analysis engines installed' }
  $env:GITHUB_SHA = $commit
  # Same workaround as the workflow: Bun on Windows cannot reliably extract Linux runtimes.
  $cache = Join-Path ([IO.Path]::GetTempPath()) 'cline-bun-install-cache'
  New-Item $cache -ItemType Directory -Force | Out-Null
  foreach ($target in @('linux-x64-baseline','linux-aarch64')) {
    $stage = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())
    New-Item $stage -ItemType Directory | Out-Null
    Push-Location $stage
    try {
      Checked 'npm' @('pack',"@oven/bun-$target@$bunVersion",'--ignore-scripts','--silent')
      $archives = @(Get-ChildItem '*.tgz')
      if ($archives.Count -ne 1) { throw 'Expected one pinned Bun runtime package' }
      Checked 'tar' @('-xzf',$archives[0].FullName,'package/bin/bun')
      $runtime = Join-Path $stage 'package/bin/bun'
      $stream = [IO.File]::OpenRead($runtime)
      try { $header = New-Object byte[] 4; if ($stream.Read($header,0,4) -ne 4 -or [BitConverter]::ToString($header) -ne '7F-45-4C-46') { throw 'Expected ELF runtime package' } }
      finally { $stream.Dispose() }
      Copy-Item $runtime (Join-Path $cache "bun-$target-v$bunVersion") -Force
    } finally { Pop-Location; Remove-Item $stage -Recurse -Force }
  }
  $env:BUN_INSTALL_CACHE_DIR = $cache
  Checked 'bun' @('install','--frozen-lockfile')
  Checked 'bun' @('run','validate:advanced')
  Checked 'bun' @('test','sdk/packages/core/scripts/advanced-windows-engine-smoke.test.ts')
  Push-Location 'apps/examples/desktop-app'
  try {
    $bundles = 'src-tauri/target/release/bundle/nsis'
    if (Test-Path $bundles) { Remove-Item $bundles -Recurse -Force }
    Checked 'bun' @('x','tauri','build','--bundles','nsis')
    $installers = @(Get-ChildItem $bundles -Filter '*-setup.exe')
    if ($installers.Count -ne 1) { throw "Expected exactly one fresh installer; found $($installers.Count)" }
    $destination = Join-Path $root 'dist/local-installer'
    New-Item $destination -ItemType Directory -Force | Out-Null
    $installer = $installers[0]
    Copy-Item $installer.FullName $destination -Force
    Copy-Item (Join-Path $root 'CUSTOMIZATIONS.md') $destination -Force
    $hash = (Get-FileHash $installer.FullName -Algorithm SHA256).Hash
    @("Source commit: $commit", "Bun: $bunVersion", "Installer SHA256: $hash", 'Installed-app smoke: NOT RUN by this source-build wrapper; require the Windows workflow gate before merge', 'Signing: not requested by this wrapper') | Set-Content (Join-Path $destination 'BUILD-INFO.txt')
    Write-Host "Source build completed: $destination"
    Write-Host 'No merge, release, installation, or installed-app validation was performed.'
  } finally { Pop-Location }
} finally {
  $env:GITHUB_SHA = $previousCommit
  $env:BUN_INSTALL_CACHE_DIR = $previousCache
  Pop-Location
}
