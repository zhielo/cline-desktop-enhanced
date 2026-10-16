[CmdletBinding()]
param([ValidateSet('8.28.0')][string]$Version = '8.28.0')
$ErrorActionPreference = 'Stop'
# Official upstream bytes, independently verified against release checksum + asset digest.
$expected = 'da6458e8864af553807de1c46a7a8eac0880bd6b99ba56288e87e86a45af884f'
$root = Join-Path $env:RUNNER_TEMP "gitleaks-$Version"
$zip = Join-Path $env:RUNNER_TEMP "gitleaks-$Version.zip"
$url = "https://github.com/gitleaks/gitleaks/releases/download/v$Version/gitleaks_${Version}_windows_x64.zip"
for ($attempt = 1; $attempt -le 3; $attempt++) {
    try {
        Invoke-WebRequest $url -OutFile $zip
        if ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'Gitleaks archive checksum mismatch' }
        break
    } catch {
        if ($attempt -eq 3) { throw }
        Start-Sleep -Seconds (5 * $attempt)
    }
}
if (Test-Path $root) { Remove-Item $root -Recurse -Force }
Expand-Archive -LiteralPath $zip -DestinationPath $root
$exe = Join-Path $root 'gitleaks.exe'
if (-not (Test-Path $exe -PathType Leaf)) { throw 'Pinned Gitleaks executable missing' }
$actual = & $exe version
if ($LASTEXITCODE -ne 0 -or "$actual".Trim() -ne $Version) { throw 'Gitleaks version self-check failed' }
$env:PATH = "$root;$env:PATH"
$root >> $env:GITHUB_PATH
