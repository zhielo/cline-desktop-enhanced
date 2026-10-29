# Native Windows CI only. Creates one random, bounded SYSTEM scheduled task for
# the explicitly built owned fixture; no service/VM/user-PC setup is installed.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Owned SYSTEM acceptance requires native Windows CI'
}
$exe = Join-Path $PSScriptRoot 'target/debug/owned-system-roots-fixture.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw 'Explicitly built owned SYSTEM fixture required'
}
$exe = (Get-Item -LiteralPath $exe).FullName
$hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$name = 'ClineOwnedRootFixture-' + [Guid]::NewGuid().ToString('N')
$registered = $false
try {
    $action = New-ScheduledTaskAction -Execute $exe
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 90) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    # No -Force: never overwrite an existing task. No shell, user parameters,
    # environment credentials, alternate executable, or arbitrary command line.
    Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings | Out-Null
    $registered = $true
    if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne $hash) {
        throw 'Owned fixture executable changed before launch'
    }
    Start-ScheduledTask -TaskName $name
    $deadline = [DateTime]::UtcNow.AddSeconds(110)
    $finished = $false
    do {
        $task = Get-ScheduledTask -TaskName $name
        $info = Get-ScheduledTaskInfo -TaskName $name
        # A newly registered task has never run; a stale/default zero result
        # alone must not count as a completed SYSTEM process.
        # Scheduler snapshots are not atomic. Ready/running/not-run/queued
        # status codes are nonterminal even if the state snapshot is older.
        $pending = $info.LastTaskResult -in @(267008, 267009, 267011, 267045)
        if (-not $pending -and $task.State -ne 'Running' -and $task.State -ne 'Queued' -and $info.LastRunTime.Year -gt 2000) {
            if ($info.LastTaskResult -ne 0) {
                throw ('Owned SYSTEM fixture failed at native stage code ' + $info.LastTaskResult)
            }
            $finished = $true
            break
        }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $finished) { throw 'Owned SYSTEM fixture deadline; retained state is unresolved' }
    if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne $hash) {
        throw 'Owned fixture executable changed during acceptance'
    }
    Write-Output 'Native SYSTEM local inert IPC and roots passed: scoped identification-token exchange and checked reversion; fixed protected ACLs/owner, reopen, no overwrite, pinned lifetime and nonrecursive owned cleanup. No VM, service, installed pack or readiness established.'
} finally {
    if ($registered) {
        $task = Get-ScheduledTask -TaskName $name -ErrorAction Stop
        if ($task.State -eq 'Running' -or $task.State -eq 'Queued') {
            Stop-ScheduledTask -TaskName $name
            $until = [DateTime]::UtcNow.AddSeconds(10)
            do {
                $task = Get-ScheduledTask -TaskName $name
                if ($task.State -ne 'Running' -and $task.State -ne 'Queued') { break }
                Start-Sleep -Milliseconds 200
            } while ([DateTime]::UtcNow -lt $until)
        }
        if ($task.State -eq 'Running' -or $task.State -eq 'Queued') {
            throw 'Owned task termination unresolved; no successful cleanup claim'
        }
        Unregister-ScheduledTask -TaskName $name -Confirm:$false
    }
}
