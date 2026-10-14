param([Parameter(Mandatory=$true)][string]$Python,[Parameter(Mandatory=$true)][string]$Requirements,[Parameter(Mandatory=$true)][string]$Wheelhouse,[string]$FindLinks="")
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
New-Item -ItemType Directory -Force -Path $Wheelhouse | Out-Null
$manifest=Join-Path $Wheelhouse 'manifest.json'
if (Test-Path -LiteralPath $manifest) {
  node scripts/wheelhouse-manifest.mjs verify $Wheelhouse $Requirements
  if ($LASTEXITCODE -ne 0) { throw 'Cached wheel integrity verification failed; no cached code installed' }
} else {
  if ((Get-ChildItem -LiteralPath $Wheelhouse -File).Count -gt 0) { throw 'Incomplete wheel cache; delete this cache entry before rebuilding' }
  $arguments=@('1200000',$Python,'-m','pip','wheel','--no-input','--disable-pip-version-check','--progress-bar','off','--verbose','--timeout','30','--retries','2','-r',$Requirements,'--wheel-dir',$Wheelhouse)
  if ($FindLinks) { $arguments += @('--find-links',$FindLinks) }
  & node scripts/run-bounded-process.mjs @arguments
  if ($LASTEXITCODE -ne 0) { throw 'Pinned wheel build failed or exceeded 20-minute deadline; no engine checks skipped' }
  node scripts/wheelhouse-manifest.mjs write $Wheelhouse $Requirements
  if ($LASTEXITCODE -ne 0) { throw 'Wheel inventory could not be sealed' }
}
node scripts/wheelhouse-manifest.mjs verify $Wheelhouse $Requirements
if ($LASTEXITCODE -ne 0) { throw 'Wheel inventory verification failed' }
node scripts/run-bounded-process.mjs 300000 $Python -m pip install --no-input --disable-pip-version-check --no-index --find-links $Wheelhouse -r $Requirements
if ($LASTEXITCODE -ne 0) { throw 'Offline engine installation failed or exceeded five-minute deadline' }
