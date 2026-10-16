# Fixed CI provisioning only. Installed investigations never download dependencies/rules.
$ErrorActionPreference = 'Stop'
try {
$repo = Split-Path $PSScriptRoot -Parent
$lock = Get-Content (Join-Path $PSScriptRoot 'binary-triage-tools.lock.json') -Raw | ConvertFrom-Json
$root = Join-Path $repo 'apps/examples/desktop-app/src-tauri/resources/binary-triage'
if (Test-Path $root) { Remove-Item $root -Recurse -Force }
New-Item -ItemType Directory -Path $root -Force | Out-Null
foreach ($tool in $lock.tools) {
    $dir = Join-Path $root $tool.id
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $zip = Join-Path $env:RUNNER_TEMP $tool.archive
    Invoke-WebRequest $tool.url -OutFile $zip
    if ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $tool.sha256) { throw "Tool archive digest mismatch: $($tool.id)" }
    Expand-Archive -LiteralPath $zip -DestinationPath $dir
    $notice = Join-Path $dir 'UPSTREAM-LICENSE.txt'
    Invoke-WebRequest $tool.licenseUrl -OutFile $notice
    if ((Get-FileHash $notice -Algorithm SHA256).Hash.ToLowerInvariant() -ne $tool.licenseSha256) { throw 'License digest mismatch' }
    if (-not (Test-Path (Join-Path $dir $tool.executable))) { throw 'Missing pinned engine executable' }
}
Copy-Item (Join-Path $PSScriptRoot 'fixtures/binary-triage.yar') (Join-Path $root 'triage.yar')
Copy-Item (Join-Path $PSScriptRoot 'binary-triage-tools.lock.json') (Join-Path $root 'tools.lock.json')
# Do not accidentally resolve Git's link.exe instead of Microsoft's linker.
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$vsRoot = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath).Trim()
if (-not $vsRoot) { throw 'Owned PE compilation requires Visual C++ tools' }
$devCmd = Join-Path $vsRoot 'Common7/Tools/VsDevCmd.bat'
$vars = & $env:COMSPEC /d /s /c "`"$devCmd`" -no_logo -arch=amd64 -host_arch=amd64 && set"
if ($LASTEXITCODE -ne 0) { throw 'Owned PE compiler environment failed' }
foreach ($line in $vars) { $i=$line.IndexOf('='); if ($i -gt 0) { [Environment]::SetEnvironmentVariable($line.Substring(0,$i),$line.Substring($i+1),'Process') } }
$linker = (Get-Command link.exe -CommandType Application).Source
if (-not $linker.StartsWith($vsRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Owned PE compiler did not resolve Microsoft linker' }
& rustc --edition=2021 -C opt-level=1 -C debuginfo=0 (Join-Path $PSScriptRoot 'fixtures/binary-triage-owned.rs') -o (Join-Path $root 'owned-fixture.exe')
if ($LASTEXITCODE -ne 0) { throw 'Owned PE fixture compilation failed' }
$files = [ordered]@{}
Get-ChildItem $root -File -Recurse | Sort-Object FullName | ForEach-Object {
    $name = [IO.Path]::GetRelativePath($root, $_.FullName).Replace('\','/')
    $files[$name] = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}
@{ schemaVersion=1; files=$files } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $root 'manifest.json') -Encoding utf8
# Real SDK-to-Python-to-native acceptance, not package-presence checks.
$env:CLINE_BINARY_TRIAGE_ROOT = $root
& bun scripts/test-binary-triage-pack.ts
if ($LASTEXITCODE -ne 0) { throw 'Binary triage pack owned acceptance failed' }

} catch {
    $message = $_.Exception.Message.Replace('%','%25').Replace("`r",'%0D').Replace("`n",'%0A')
    Write-Output "::error title=Binary Triage Pack packaging::$message"
    throw
}
