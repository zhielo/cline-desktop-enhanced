[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('upx', 'gitleaks')]
    [string]$Package,
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version
)
$ErrorActionPreference = 'Stop'
# Inspect native exit codes explicitly so transient feed failures can retry.
# This preference is script-scoped, not a change to subsequent CI steps.
$PSNativeCommandUseErrorActionPreference = $false
for ($attempt = 1; $attempt -le 3; $attempt++) {
    & choco install $Package "--version=$Version" --no-progress -y
    $code = $LASTEXITCODE
    if ($code -eq 0) { return }
    if ($attempt -eq 3) {
        throw "Pinned $Package $Version installation failed after 3 attempts (exit $code)"
    }
    Write-Warning "Pinned $Package $Version installation failed (exit $code); retrying."
    Start-Sleep -Seconds (5 * $attempt)
}