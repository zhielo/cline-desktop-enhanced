$ErrorActionPreference = 'Stop'
$scriptUnderTest = Join-Path $PSScriptRoot 'install-pinned-windows-tool.ps1'
# Owned command doubles only: no network, package installation or waiting.
function global:choco {
    $global:installArguments += ,@($args)
    if ($global:installCalls -ge $global:installCodes.Count) {
        throw 'Unexpected extra installation attempt'
    }
    $global:LASTEXITCODE = $global:installCodes[$global:installCalls]
    $global:installCalls++
}
function global:Start-Sleep {
    param([int]$Seconds)
    $global:installDelays += $Seconds
}
function Test-Scenario {
    param([int[]]$Codes, [int]$ExpectedCalls, [bool]$ExpectedFailure, [int[]]$ExpectedDelays)
    $global:installCodes = $Codes
    $global:installCalls = 0
    $global:installArguments = @()
    $global:installDelays = @()
    $failed = $false
    try { & $scriptUnderTest -Package upx -Version 4.2.4 }
    catch {
        $failed = $true
        if ($_.Exception.Message -notmatch 'failed after 3 attempts') { throw }
    }
    if ($failed -ne $ExpectedFailure -or $global:installCalls -ne $ExpectedCalls) {
        throw 'Incorrect bounded installation outcome'
    }
    if (($global:installDelays -join ',') -ne ($ExpectedDelays -join ',')) {
        throw 'Incorrect bounded installation backoff'
    }
    foreach ($arguments in $global:installArguments) {
        if (($arguments -join ' ') -ne 'install upx --version=4.2.4 --no-progress -y') {
            throw 'Pinned version or install arguments changed'
        }
    }
}
try {
    Test-Scenario -Codes @(0) -ExpectedCalls 1 -ExpectedFailure $false -ExpectedDelays @()
    Test-Scenario -Codes @(1, 0) -ExpectedCalls 2 -ExpectedFailure $false -ExpectedDelays @(5)
    Test-Scenario -Codes @(1, 1, 0) -ExpectedCalls 3 -ExpectedFailure $false -ExpectedDelays @(5, 10)
    Test-Scenario -Codes @(1, 1, 1) -ExpectedCalls 3 -ExpectedFailure $true -ExpectedDelays @(5, 10)
    Write-Host 'Pinned Windows tool retry fixtures passed (4 scenarios; no installs).'
} finally {
    Remove-Item Function:\global:choco -ErrorAction SilentlyContinue
    Remove-Item Function:\global:Start-Sleep -ErrorAction SilentlyContinue
}